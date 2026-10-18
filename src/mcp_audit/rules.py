"""Detection rules for the MCP permission auditor.

Each rule inspects the normalized manifest and emits zero or more
`Finding` records. Rules are deterministic, side-effect free, and reason
only about the *declared* manifest — they cannot observe what the server
actually does at runtime (that limitation is documented, not hidden).
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

SEVERITY_ORDER = {"LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
SEVERITY_WEIGHT = {"LOW": 5, "MEDIUM": 15, "HIGH": 35, "CRITICAL": 60}


@dataclass
class Finding:
    rule_id: str
    severity: str  # CRITICAL | HIGH | MEDIUM | LOW
    target: str  # tool name, resource URI, or "server"
    message: str
    fix: str  # least-privilege remediation guidance
    evidence: dict[str, Any] = field(default_factory=dict)


# ---------------------------------------------------------------------------
# Pattern tables
# ---------------------------------------------------------------------------

# Environment variable names that almost always carry secrets.
SECRET_ENV_RE = re.compile(
    r"(secret|token|password|passwd|pwd|api[_-]?key|private[_-]?key|"
    r"credential|auth|bearer|session|client[_-]?secret)",
    re.IGNORECASE,
)

# Filesystem scopes that are effectively "the whole machine".
BROAD_FS_SCOPES = {
    "/", "/*", "/**", "file:///", "file:///**", "file:///*",
    "~", "$HOME", "%USERPROFILE%", "C:\\", "C:\\*", "C:\\**",
    ".", "./", "./**",
}

# Read scopes that touch credential-bearing locations.
SENSITIVE_PATH_RES = [
    re.compile(r"(^|/)\.ssh(/|$)"),
    re.compile(r"(^|/)\.aws(/|$)"),
    re.compile(r"(^|/)\.gnupg(/|$)"),
    re.compile(r"^/etc(/|$)"),
    re.compile(r"\.pem$|\.key$|id_rsa|id_ed25519", re.IGNORECASE),
]

WRITE_CAPS = {"fs:write", "file:write", "write", "fs:*", "*"}
READ_CAPS = {"fs:read", "file:read", "read", "fs:*", "*"}
DELETE_CAPS = {"fs:delete", "file:delete", "delete", "fs:*", "*"}
EXEC_CAPS = {"process:exec", "exec", "shell", "shell:exec", "process:*", "*"}
NET_CAPS = {"net:egress", "network", "http:request", "net:*", "*"}


def _cap_set(tool: dict[str, Any]) -> set[str]:
    caps = {c.strip().lower() for c in tool.get("capabilities", [])}
    if tool.get("network"):
        caps.add("net:egress")
    return caps


def _is_wildcard(value: str) -> bool:
    v = value.strip()
    return v == "*" or v.endswith(":*") or v == "**"


# ---------------------------------------------------------------------------
# Rules
# ---------------------------------------------------------------------------

def rule_wildcard_permissions(manifest: dict[str, Any]) -> list[Finding]:
    """Wildcard (`*`) permissions grant everything and audit nothing."""
    findings: list[Finding] = []
    for perm in manifest.get("permissions", []):
        if _is_wildcard(perm):
            findings.append(Finding(
                rule_id="wildcard-permission",
                severity="CRITICAL",
                target="server",
                message=f"Server declares wildcard permission '{perm}'.",
                fix="Replace the wildcard with the minimal explicit permission list "
                    "(e.g. ['fs:read'] with scoped paths). A wildcard makes every "
                    "other control in this report unenforceable.",
                evidence={"permission": perm},
            ))
    for tool in manifest["tools"]:
        for perm in tool["permissions"]:
            if _is_wildcard(perm):
                findings.append(Finding(
                    rule_id="wildcard-permission",
                    severity="CRITICAL",
                    target=f"tool:{tool['name']}",
                    message=f"Tool '{tool['name']}' declares wildcard permission '{perm}'.",
                    fix=f"Give '{tool['name']}' only the capabilities it needs "
                        "(capabilities list), never '*'.",
                    evidence={"permission": perm},
                ))
    return findings


def rule_dangerous_combos(manifest: dict[str, Any]) -> list[Finding]:
    """Write/exec + network egress in one tool = exfiltration or remote implant."""
    findings: list[Finding] = []
    for tool in manifest["tools"]:
        caps = _cap_set(tool)
        name = tool["name"]
        if (caps & WRITE_CAPS) and (caps & NET_CAPS):
            findings.append(Finding(
                rule_id="write-plus-network",
                severity="CRITICAL",
                target=f"tool:{name}",
                message=(f"Tool '{name}' combines filesystem WRITE with network "
                         "egress — it can read local files and send them out, or "
                         "download and persist remote payloads."),
                fix=f"Split '{name}' into a write-only tool and a network-only "
                    "tool, or remove one of the two capabilities. If both are "
                    "genuinely needed, restrict scopes to exact paths and pin "
                    "allowed_hosts.",
                evidence={"capabilities": sorted(caps)},
            ))
        if (caps & EXEC_CAPS) and (caps & NET_CAPS):
            findings.append(Finding(
                rule_id="exec-plus-network",
                severity="CRITICAL",
                target=f"tool:{name}",
                message=(f"Tool '{name}' combines process execution with network "
                         "egress — a classic remote-code-execution primitive."),
                fix=f"Remove network egress from '{name}' or remove the exec "
                    "capability. Exec tools must be network-isolated and require "
                    "explicit user confirmation per invocation.",
                evidence={"capabilities": sorted(caps)},
            ))
    return findings


def rule_unscoped_resources(manifest: dict[str, Any]) -> list[Finding]:
    """Resources with no scope restriction are world-readable/writable."""
    findings: list[Finding] = []
    for res in manifest["resources"]:
        if not res["scopes"]:
            findings.append(Finding(
                rule_id="unscoped-resource",
                severity="HIGH",
                target=f"resource:{res['uri']}",
                message=(f"Resource '{res['uri']}' ({res['access']}) declares no "
                         "scope restriction."),
                fix=f"Add explicit scopes to '{res['uri']}' limiting it to the "
                    "exact URI prefixes clients may use. Unscoped resources are "
                    "reachable from any client context.",
                evidence={"uri": res["uri"], "access": res["access"]},
            ))
    return findings


def rule_broad_fs_scopes(manifest: dict[str, Any]) -> list[Finding]:
    """Scopes covering the filesystem root (or home) are overbroad."""
    findings: list[Finding] = []
    for tool in manifest["tools"]:
        for scope in tool["scopes"]:
            if scope.strip() in BROAD_FS_SCOPES:
                findings.append(Finding(
                    rule_id="broad-fs-scope",
                    severity="HIGH",
                    target=f"tool:{tool['name']}",
                    message=(f"Tool '{tool['name']}' is scoped to '{scope}' — "
                             "effectively the whole filesystem."),
                    fix=f"Narrow '{tool['name']}' to the exact directories it "
                        "needs (e.g. '/srv/data/invoices/*'), never the root or "
                        "home directory.",
                    evidence={"scope": scope},
                ))
    for res in manifest["resources"]:
        uri_lower = res["uri"].lower()
        if uri_lower in BROAD_FS_SCOPES or re.search(r"file:///\*{1,2}$", uri_lower):
            findings.append(Finding(
                rule_id="broad-fs-scope",
                severity="HIGH",
                target=f"resource:{res['uri']}",
                message=f"Resource URI '{res['uri']}' exposes a filesystem root.",
                fix="Serve resources from a dedicated subtree, not the root.",
                evidence={"uri": res["uri"]},
            ))
    return findings


def rule_credential_env(manifest: dict[str, Any]) -> list[Finding]:
    """Environment passthrough of secret-looking names leaks credentials to the model."""
    findings: list[Finding] = []
    seen: set[str] = set()
    candidates = list(manifest.get("env_passthrough", []))
    for tool in manifest["tools"]:
        candidates.extend(tool["env"])
    for name in candidates:
        if name in seen:
            continue
        seen.add(name)
        if SECRET_ENV_RE.search(name):
            findings.append(Finding(
                rule_id="credential-env",
                severity="HIGH",
                target="server",
                message=(f"Environment variable '{name}' looks credential-bearing "
                         "and is passed through to the MCP server context."),
                fix=f"Do not pass '{name}' through. Inject secrets at the transport "
                    "layer (e.g. the server reads its own config file), or use a "
                    "secret manager reference instead of the raw value.",
                evidence={"env": name},
            ))
    return findings


def rule_sensitive_path_read(manifest: dict[str, Any]) -> list[Finding]:
    """Read access scoped to credential-bearing paths (~/.ssh, /etc, *.pem...)."""
    findings: list[Finding] = []
    for tool in manifest["tools"]:
        caps = _cap_set(tool)
        if not (caps & READ_CAPS):
            continue
        for scope in tool["scopes"]:
            for pattern in SENSITIVE_PATH_RES:
                if pattern.search(scope):
                    findings.append(Finding(
                        rule_id="sensitive-path-read",
                        severity="MEDIUM",
                        target=f"tool:{tool['name']}",
                        message=(f"Tool '{tool['name']}' can read sensitive path "
                                 f"pattern '{scope}'."),
                        fix=f"Exclude credential paths from '{tool['name']}' scopes "
                            "(~/.ssh, ~/.aws, /etc, key files). Tools that need "
                            "config should read one allowlisted file, not a glob "
                            "that matches keys.",
                        evidence={"scope": scope},
                    ))
                    break
    return findings


def rule_destructive_no_confirm(manifest: dict[str, Any]) -> list[Finding]:
    """Delete/exec tools without per-invocation confirmation."""
    findings: list[Finding] = []
    for tool in manifest["tools"]:
        if tool["requires_confirmation"]:
            continue
        caps = _cap_set(tool)
        name = tool["name"]
        if caps & DELETE_CAPS:
            findings.append(Finding(
                rule_id="destructive-no-confirm",
                severity="HIGH",
                target=f"tool:{name}",
                message=f"Tool '{name}' can delete files without user confirmation.",
                fix=f"Set requires_confirmation=true on '{name}', or split it "
                    "into a dry-run preview tool plus a confirmed-apply tool.",
                evidence={"capabilities": sorted(caps)},
            ))
        elif caps & EXEC_CAPS:
            findings.append(Finding(
                rule_id="destructive-no-confirm",
                severity="HIGH",
                target=f"tool:{name}",
                message=(f"Tool '{name}' can execute processes without user "
                         "confirmation."),
                fix=f"Set requires_confirmation=true on '{name}' and restrict it "
                    "to an allowlisted command set — never a free-form shell.",
                evidence={"capabilities": sorted(caps)},
            ))
    return findings


def rule_network_no_allowlist(manifest: dict[str, Any]) -> list[Finding]:
    """Network egress with no declared host allowlist."""
    findings: list[Finding] = []
    for tool in manifest["tools"]:
        caps = _cap_set(tool)
        if (caps & NET_CAPS) and not tool["allowed_hosts"]:
            findings.append(Finding(
                rule_id="network-no-allowlist",
                severity="MEDIUM",
                target=f"tool:{tool['name']}",
                message=(f"Tool '{tool['name']}' has network egress with no "
                         "allowed_hosts allowlist."),
                fix=f"Declare allowed_hosts on '{tool['name']}' — the exact "
                    "domains it may contact. Unrestricted egress turns any "
                    "prompt-injection into a data-exfiltration channel.",
                evidence={"capabilities": sorted(caps)},
            ))
    return findings


def rule_hygiene(manifest: dict[str, Any]) -> list[Finding]:
    """Low-severity hygiene: undocumented tools, oversized tool surface."""
    findings: list[Finding] = []
    for tool in manifest["tools"]:
        if not tool["description"].strip():
            findings.append(Finding(
                rule_id="undocumented-tool",
                severity="LOW",
                target=f"tool:{tool['name']}",
                message=f"Tool '{tool['name']}' has no description.",
                fix="Document what the tool does, its inputs, and its side "
                    "effects. Undocumented tools are misused tools.",
                evidence={},
            ))
    if len(manifest["tools"]) > 25:
        findings.append(Finding(
            rule_id="excessive-tool-surface",
            severity="LOW",
            target="server",
            message=(f"Server exposes {len(manifest['tools'])} tools — a large "
                     "attack surface for prompt-injection."),
            fix="Consolidate tools behind fewer, well-scoped operations; split "
                "the server if it serves unrelated domains.",
            evidence={"tool_count": len(manifest["tools"])},
        ))
    return findings


RULES = [
    rule_wildcard_permissions,
    rule_dangerous_combos,
    rule_unscoped_resources,
    rule_broad_fs_scopes,
    rule_credential_env,
    rule_sensitive_path_read,
    rule_destructive_no_confirm,
    rule_network_no_allowlist,
    rule_hygiene,
]


def audit(manifest: dict[str, Any]) -> list[Finding]:
    """Run every rule against the manifest. Returns findings sorted by severity."""
    findings: list[Finding] = []
    for rule in RULES:
        findings.extend(rule(manifest))
    findings.sort(key=lambda f: (-SEVERITY_ORDER[f.severity], f.rule_id, f.target))
    return findings


def score(findings: list[Finding]) -> int:
    """0–100 risk score: sum of severity weights, capped at 100 (higher = riskier)."""
    return min(100, sum(SEVERITY_WEIGHT[f.severity] for f in findings))


def max_severity(findings: list[Finding]) -> str | None:
    if not findings:
        return None
    return max(findings, key=lambda f: SEVERITY_ORDER[f.severity]).severity

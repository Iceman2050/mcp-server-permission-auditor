"""Report rendering: JSON and human-readable least-privilege audit reports."""

from __future__ import annotations

import json
from typing import Any

from .rules import Finding, max_severity, score

SEVERITY_BADGE = {
    "CRITICAL": "[CRITICAL]",
    "HIGH": "[HIGH]    ",
    "MEDIUM": "[MEDIUM]  ",
    "LOW": "[LOW]     ",
}


def build_report(manifest: dict[str, Any], findings: list[Finding]) -> dict[str, Any]:
    """Assemble the structured report dict (also the JSON output shape)."""
    by_severity: dict[str, int] = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for f in findings:
        by_severity[f.severity] += 1
    least_privilege_plan = _least_privilege_plan(manifest, findings)
    return {
        "server": manifest["name"],
        "version": manifest["version"],
        "risk_score": score(findings),
        "max_severity": max_severity(findings),
        "summary": {
            "total_findings": len(findings),
            "by_severity": by_severity,
            "tools_audited": len(manifest["tools"]),
            "resources_audited": len(manifest["resources"]),
        },
        "findings": [
            {
                "rule_id": f.rule_id,
                "severity": f.severity,
                "target": f.target,
                "message": f.message,
                "fix": f.fix,
            }
            for f in findings
        ],
        "least_privilege_plan": least_privilege_plan,
    }


def _least_privilege_plan(
    manifest: dict[str, Any], findings: list[Finding]
) -> list[str]:
    """Ordered remediation checklist: most dangerous first, deduplicated."""
    steps: list[str] = []
    seen: set[str] = set()

    def add(step: str) -> None:
        if step not in seen:
            seen.add(step)
            steps.append(step)

    rule_ids = {f.rule_id for f in findings}
    if "wildcard-permission" in rule_ids:
        add("1. Eliminate every wildcard ('*') permission — enumerate the exact "
            "capabilities each tool needs.")
    if "write-plus-network" in rule_ids or "exec-plus-network" in rule_ids:
        add("2. Break up tools that combine write/exec with network egress into "
            "single-purpose tools (write-only OR network-only).")
    if "broad-fs-scope" in rule_ids:
        add("3. Narrow filesystem scopes from roots/globs to the exact "
            "directories each tool requires.")
    if "credential-env" in rule_ids:
        add("4. Stop passing credential-bearing env vars through; inject secrets "
            "server-side via config files or a secret manager.")
    if "unscoped-resource" in rule_ids:
        add("5. Add explicit scope restrictions to every resource.")
    if "destructive-no-confirm" in rule_ids:
        add("6. Require per-invocation user confirmation on delete/exec tools.")
    if "network-no-allowlist" in rule_ids:
        add("7. Pin allowed_hosts on every tool with network egress.")
    if "sensitive-path-read" in rule_ids:
        add("8. Exclude credential paths (~/.ssh, ~/.aws, /etc, key files) from "
            "read scopes.")
    if "undocumented-tool" in rule_ids or "excessive-tool-surface" in rule_ids:
        add("9. Document every tool and consolidate the tool surface — fewer, "
            "well-scoped tools beat many vague ones.")
    if not steps:
        add("No remediation needed — the manifest already follows "
            "least-privilege. Re-run the audit on every manifest change.")
    return steps


def render_text(report: dict[str, Any]) -> str:
    """Human-readable report."""
    lines: list[str] = []
    lines.append("=" * 72)
    lines.append(f"MCP Permission Audit — {report['server']} v{report['version']}")
    lines.append("=" * 72)
    lines.append(f"Risk score : {report['risk_score']}/100 "
                 f"(max severity: {report['max_severity'] or 'none'})")
    s = report["summary"]
    lines.append(f"Findings   : {s['total_findings']} "
                 f"(C:{s['by_severity']['CRITICAL']} H:{s['by_severity']['HIGH']} "
                 f"M:{s['by_severity']['MEDIUM']} L:{s['by_severity']['LOW']})")
    lines.append(f"Audited    : {s['tools_audited']} tools, "
                 f"{s['resources_audited']} resources")
    lines.append("")
    if report["findings"]:
        lines.append("FINDINGS (most severe first)")
        lines.append("-" * 72)
        for f in report["findings"]:
            badge = SEVERITY_BADGE[f["severity"]]
            lines.append(f"{badge} {f['rule_id']} — {f['target']}")
            lines.append(f"          {f['message']}")
            lines.append(f"          Fix: {f['fix']}")
            lines.append("")
    lines.append("LEAST-PRIVILEGE REMEDIATION PLAN")
    lines.append("-" * 72)
    for step in report["least_privilege_plan"]:
        lines.append(f"  {step}")
    lines.append("")
    lines.append("Note: this is a static manifest analysis — it audits what the "
                 "server *declares*, not what it does at runtime.")
    return "\n".join(lines)


def render_json(report: dict[str, Any]) -> str:
    return json.dumps(report, indent=2)

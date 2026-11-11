> **Archived — superseded by [mcp-permission-firewall](https://github.com/Iceman2050/mcp-permission-firewall).** This tool is no longer maintained. MCP server permission auditing and least-privilege remediation now live in the canonical repo linked above; use it instead.

# mcp-server-permission-auditor

A real, working CLI that audits **MCP (Model Context Protocol) server manifests** for overbroad
permissions — and tells you exactly how to fix them. Feed it the JSON manifest describing your
server's tools, resources, and permission scopes; it flags dangerous patterns and emits a
scored, least-privilege remediation report.

## Why

MCP servers hand AI models capabilities: filesystem access, shell execution, network egress.
A single over-permissioned tool — `fs:write` + network in one place, a wildcard `*` scope, a
credential-bearing env var passed through — turns any prompt injection into data exfiltration
or remote code execution. This auditor catches those declarations *before* the server ships.

## Install

```bash
pip install git+https://github.com/Iceman2050/mcp-server-permission-auditor.git
# or from source:
pip install -e .
```

## Usage

```bash
mcp-audit audit examples/minimal-server.json
mcp-audit audit my-server.json --format json -o report.json
mcp-audit audit my-server.json --fail-on high   # exit 1 on high+ findings (default: medium)
```

Exit codes: `0` = clean below the threshold, `1` = findings at/above `--fail-on`,
`2` = usage/parse error. Drop it into CI — a risky manifest fails the build.

## Manifest schema

```jsonc
{
  "name": "my-mcp-server",
  "version": "1.0.0",
  "permissions": ["fs:read"],          // server-wide grants ("*" = critical finding)
  "env_passthrough": ["DEBUG"],       // env vars exposed to the server context
  "tools": [
    {
      "name": "read_note",
      "description": "Reads one markdown note.",
      "capabilities": ["fs:read"],    // fs:read | fs:write | fs:delete | process:exec | shell | net:egress ...
      "scopes": ["/srv/data/notes/*"],// paths/URIs the tool may touch
      "network": false,
      "allowed_hosts": ["api.example.com"],
      "env": [],
      "requires_confirmation": false
    }
  ],
  "resources": [
    { "uri": "notes://daily", "access": "read", "scopes": ["notes://daily"] }
  ]
}
```

Both flat (`tools: [...]`) and nested (`capabilities: { tools: [...] }`) layouts are accepted.

## Detection rules

| Rule | Severity | What it catches |
|---|---|---|
| `wildcard-permission` | CRITICAL | `*` / `fs:*` permissions, server- or tool-level |
| `write-plus-network` | CRITICAL | Tool combining filesystem write with network egress |
| `exec-plus-network` | CRITICAL | Tool combining process/shell exec with network egress |
| `unscoped-resource` | HIGH | Resource with no scope restriction |
| `broad-fs-scope` | HIGH | Scopes covering the filesystem root, `~`, or `file:///**` |
| `credential-env` | HIGH | Secret-looking env vars (`*_SECRET`, `*_TOKEN`, `*_KEY`, …) passed through |
| `destructive-no-confirm` | HIGH | Delete/exec tools without `requires_confirmation` |
| `sensitive-path-read` | MEDIUM | Read scopes over `~/.ssh`, `~/.aws`, `/etc`, `*.pem` |
| `network-no-allowlist` | MEDIUM | Network egress with no `allowed_hosts` allowlist |
| `undocumented-tool` | LOW | Tool with no description |
| `excessive-tool-surface` | LOW | More than 25 tools exposed |

Every finding ships with a concrete **Fix** — a least-privilege remediation step. The report
ends with an ordered remediation plan (wildcards first, hygiene last) and a 0–100 risk score.

## Example output

```
========================================================================
MCP Permission Audit — kitchen-sink-mcp v0.3.1
========================================================================
Risk score : 100/100 (max severity: CRITICAL)
Findings   : 17 (C:3 H:7 M:5 L:2)
Audited    : 6 tools, 2 resources

FINDINGS (most severe first)
------------------------------------------------------------------------
[CRITICAL] exec-plus-network — tool:run_anything
          Tool 'run_anything' combines process execution with network egress — a classic remote-code-execution primitive.
          Fix: Remove network egress from 'run_anything' or remove the exec capability. ...
```

## Honest scope

This is a **static manifest analysis**: it audits what the server *declares*, not what it does
at runtime. A clean report means the declarations follow least privilege — it cannot prove the
implementation honors them, and it cannot see capabilities a manifest omits. Heuristic severity
weights are documented in `src/mcp_audit/rules.py`; nothing here is a safety certification.

## Development

```bash
python -m pytest -q   # full suite
```

## License

MIT — see [LICENSE](LICENSE).

---

## Built by Ingenious AI

This tool is part of the Ingenious AI security-tooling ecosystem — 11 platforms covering AI
disclosure compliance, model lifecycle, agent security, breach hunting, and more. Get early
access:

- [DisclosureGuard](https://wa.me/5016691053?text=Hi%2C%20I%20want%20early%20access%20to%20DisclosureGuard)
- [ModelMinder](https://wa.me/5016691053?text=Hi%2C%20I%20want%20early%20access%20to%20ModelMinder)
- [TermsWatch](https://wa.me/5016691053?text=Hi%2C%20I%20want%20early%20access%20to%20TermsWatch)
- [Vibe-Code Audit](https://wa.me/5016691053?text=Hi%2C%20I%20want%20early%20access%20to%20Vibe-Code%20Audit)
- [Rogue-Agent Defense](https://wa.me/5016691053?text=Hi%2C%20I%20want%20early%20access%20to%20Rogue-Agent%20Defense)
- [BreachHunter](https://wa.me/5016691053?text=Hi%2C%20I%20want%20early%20access%20to%20BreachHunter)
- [ChatBreaker](https://wa.me/5016691053?text=Hi%2C%20I%20want%20early%20access%20to%20ChatBreaker)
- [Agent Flight Recorder](https://wa.me/5016691053?text=Hi%2C%20I%20want%20early%20access%20to%20Agent%20Flight%20Recorder)
- [Agent Auth Gateway](https://wa.me/5016691053?text=Hi%2C%20I%20want%20early%20access%20to%20Agent%20Auth%20Gateway)
- [DomainGuard](https://wa.me/5016691053?text=Hi%2C%20I%20want%20early%20access%20to%20DomainGuard)
- [ContentCraft AI](https://wa.me/5016691053?text=Hi%2C%20I%20want%20early%20access%20to%20ContentCraft%20AI)

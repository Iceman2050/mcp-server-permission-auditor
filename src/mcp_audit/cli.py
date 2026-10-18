"""CLI: mcp-audit — audit an MCP server manifest for overbroad permissions."""

from __future__ import annotations

import argparse
import sys

from . import __version__
from .manifest import ManifestError, load_manifest
from .report import build_report, render_json, render_text
from .rules import SEVERITY_ORDER, audit, max_severity

EXIT_OK = 0          # no findings at/above the fail threshold
EXIT_FINDINGS = 1    # findings at/above the fail threshold
EXIT_ERROR = 2       # usage / parse error


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="mcp-audit",
        description="Audit an MCP server manifest for overbroad permissions "
                    "and emit a least-privilege remediation report.",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    audit_p = sub.add_parser("audit", help="Audit a manifest file.")
    audit_p.add_argument("manifest", help="Path to the MCP server manifest (JSON).")
    audit_p.add_argument(
        "--format", choices=["text", "json"], default="text",
        help="Report output format (default: text).",
    )
    audit_p.add_argument(
        "--fail-on", choices=["critical", "high", "medium", "low"], default="medium",
        help="Exit %(prog)s with code 1 when findings at/above this severity "
             "exist (default: medium).",
    )
    audit_p.add_argument(
        "-o", "--output", default=None,
        help="Write the report to this file instead of stdout.",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    try:
        manifest = load_manifest(args.manifest)
    except ManifestError as exc:
        print(f"mcp-audit: error: {exc}", file=sys.stderr)
        return EXIT_ERROR

    findings = audit(manifest)
    report = build_report(manifest, findings)
    rendered = render_json(report) if args.format == "json" else render_text(report)

    if args.output:
        try:
            with open(args.output, "w", encoding="utf-8") as fh:
                fh.write(rendered + "\n")
        except OSError as exc:
            print(f"mcp-audit: error: cannot write output: {exc}", file=sys.stderr)
            return EXIT_ERROR
    else:
        print(rendered)

    threshold = SEVERITY_ORDER[args.fail_on.upper()]
    worst = max_severity(findings)
    if worst is not None and SEVERITY_ORDER[worst] >= threshold:
        return EXIT_FINDINGS
    return EXIT_OK


if __name__ == "__main__":
    sys.exit(main())

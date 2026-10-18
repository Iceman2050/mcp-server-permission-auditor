"""CLI end-to-end tests: exit codes, formats, thresholds, file output."""
import json
import os

import pytest

from mcp_audit.cli import EXIT_ERROR, EXIT_FINDINGS, EXIT_OK, main

EXAMPLES = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "examples")


def _dangerous():
    return os.path.join(EXAMPLES, "dangerous-server.json")


def _minimal():
    return os.path.join(EXAMPLES, "minimal-server.json")


def test_dangerous_example_exits_findings(capsys):
    rc = main(["audit", _dangerous()])
    assert rc == EXIT_FINDINGS
    out = capsys.readouterr().out
    assert "[CRITICAL]" in out
    assert "write-plus-network" in out or "wildcard-permission" in out


def test_minimal_example_exits_ok(capsys):
    rc = main(["audit", _minimal()])
    assert rc == EXIT_OK
    out = capsys.readouterr().out
    assert "Risk score : 0/100" in out


def test_fail_on_critical_still_fails_on_criticals():
    assert main(["audit", _dangerous(), "--fail-on", "critical"]) == EXIT_FINDINGS


def test_fail_on_low_never_relaxes():
    # minimal example is fully clean, so even --fail-on low passes
    assert main(["audit", _minimal(), "--fail-on", "low"]) == EXIT_OK


def test_json_format_parses(capsys):
    rc = main(["audit", _dangerous(), "--format", "json"])
    assert rc == EXIT_FINDINGS
    parsed = json.loads(capsys.readouterr().out)
    assert parsed["risk_score"] > 0
    assert parsed["summary"]["total_findings"] == len(parsed["findings"])


def test_missing_file_is_error(capsys):
    assert main(["audit", "/no/such/manifest.json"]) == EXIT_ERROR
    assert "error" in capsys.readouterr().err


def test_invalid_json_is_error(tmp_path, capsys):
    p = tmp_path / "bad.json"
    p.write_text("{oops", encoding="utf-8")
    assert main(["audit", str(p)]) == EXIT_ERROR


def test_output_file_written(tmp_path):
    out = tmp_path / "report.txt"
    rc = main(["audit", _minimal(), "-o", str(out)])
    assert rc == EXIT_OK
    assert "MCP Permission Audit" in out.read_text(encoding="utf-8")


def test_dangerous_finding_count_is_substantial(capsys):
    main(["audit", _dangerous(), "--format", "json"])
    parsed = json.loads(capsys.readouterr().out)
    # dangerous-server.json is built to trip many rules
    assert parsed["summary"]["total_findings"] >= 8
    assert parsed["summary"]["by_severity"]["CRITICAL"] >= 2

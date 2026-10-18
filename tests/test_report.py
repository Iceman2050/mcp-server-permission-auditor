"""Report rendering tests: structure, remediation plan, text + JSON output."""
import json

from mcp_audit.manifest import normalize_manifest
from mcp_audit.report import build_report, render_json, render_text
from mcp_audit.rules import audit


def _report(**overrides):
    base = {"name": "rep-server", "tools": [], "resources": []}
    base.update(overrides)
    manifest = normalize_manifest(base)
    return build_report(manifest, audit(manifest))


def test_report_shape():
    r = _report(permissions=["*"])
    assert r["server"] == "rep-server"
    assert r["risk_score"] > 0
    assert r["max_severity"] == "CRITICAL"
    assert r["summary"]["total_findings"] == len(r["findings"])
    assert isinstance(r["least_privilege_plan"], list) and r["least_privilege_plan"]


def test_clean_report():
    r = _report(tools=[{"name": "t", "capabilities": ["fs:read"],
                        "scopes": ["/srv/*"], "description": "reads"}],
                resources=[{"uri": "x://y", "access": "read", "scopes": ["x://y"]}])
    assert r["risk_score"] == 0
    assert r["max_severity"] is None
    assert r["findings"] == []
    assert any("No remediation needed" in s for s in r["least_privilege_plan"])


def test_plan_orders_wildcard_first():
    r = _report(permissions=["*"],
                tools=[{"name": "t", "capabilities": ["fs:read"],
                        "scopes": ["/srv/*"]}])  # undocumented -> step 9
    plan = r["least_privilege_plan"]
    assert plan[0].startswith("1. Eliminate every wildcard")


def test_plan_deduplicates_repeated_rules():
    r = _report(env_passthrough=["A_TOKEN", "B_SECRET"])
    plan = r["least_privilege_plan"]
    env_steps = [s for s in plan if "credential-bearing env" in s]
    assert len(env_steps) == 1


def test_text_render_contains_sections():
    r = _report(permissions=["*"])
    text = render_text(r)
    assert "MCP Permission Audit" in text
    assert "Risk score" in text
    assert "FINDINGS" in text
    assert "LEAST-PRIVILEGE REMEDIATION PLAN" in text
    assert "[CRITICAL]" in text
    assert "static manifest analysis" in text  # honest-scope note


def test_text_render_clean_server():
    r = _report()
    text = render_text(r)
    assert "Risk score : 0/100" in text
    assert "FINDINGS" not in text


def test_json_render_round_trips():
    r = _report(permissions=["*"])
    parsed = json.loads(render_json(r))
    assert parsed["server"] == "rep-server"
    assert parsed["summary"]["by_severity"]["CRITICAL"] >= 1
    assert all("fix" in f for f in parsed["findings"])

"""Manifest parsing + normalization tests."""
import json

import pytest

from mcp_audit.manifest import ManifestError, load_manifest, normalize_manifest


def _write(path, obj):
    path.write_text(json.dumps(obj), encoding="utf-8")
    return str(path)


def test_load_valid_manifest(tmp_path):
    p = _write(tmp_path / "m.json", {"name": "srv", "tools": [], "resources": []})
    m = load_manifest(p)
    assert m["name"] == "srv"
    assert m["version"] == "0.0.0"
    assert m["tools"] == [] and m["resources"] == []


def test_load_missing_file(tmp_path):
    with pytest.raises(ManifestError, match="not found"):
        load_manifest(str(tmp_path / "nope.json"))


def test_load_invalid_json(tmp_path):
    p = tmp_path / "bad.json"
    p.write_text("{not json", encoding="utf-8")
    with pytest.raises(ManifestError, match="not valid JSON"):
        load_manifest(str(p))


def test_root_must_be_object(tmp_path):
    p = _write(tmp_path / "m.json", ["not", "an", "object"])
    with pytest.raises(ManifestError, match="must be a JSON object"):
        load_manifest(str(p))


def test_name_required(tmp_path):
    p = _write(tmp_path / "m.json", {"tools": []})
    with pytest.raises(ManifestError, match='"name"'):
        load_manifest(str(p))


def test_tool_name_required():
    with pytest.raises(ManifestError, match="tools\\[0\\]"):
        normalize_manifest({"name": "s", "tools": [{"capabilities": ["fs:read"]}]})


def test_resource_uri_required():
    with pytest.raises(ManifestError, match="resources\\[0\\]"):
        normalize_manifest({"name": "s", "resources": [{"access": "read"}]})


def test_nested_capabilities_layout():
    m = normalize_manifest({
        "name": "s",
        "capabilities": {
            "tools": [{"name": "t", "capabilities": ["fs:read"]}],
            "resources": [{"uri": "notes://x"}],
        },
    })
    assert [t["name"] for t in m["tools"]] == ["t"]
    assert [r["uri"] for r in m["resources"]] == ["notes://x"]


def test_tool_defaults():
    m = normalize_manifest({"name": "s", "tools": [{"name": "t"}]})
    t = m["tools"][0]
    assert t["description"] == ""
    assert t["capabilities"] == []
    assert t["network"] is False
    assert t["requires_confirmation"] is False
    assert t["allowed_hosts"] == []


def test_resource_access_lowercased():
    m = normalize_manifest({"name": "s", "resources": [{"uri": "x://y", "access": "WRITE"}]})
    assert m["resources"][0]["access"] == "write"


def test_string_coercion():
    m = normalize_manifest({
        "name": "s",
        "tools": [{"name": "t", "capabilities": "fs:read", "scopes": "/srv/*"}],
    })
    assert m["tools"][0]["capabilities"] == ["fs:read"]
    assert m["tools"][0]["scopes"] == ["/srv/*"]


def test_server_level_env_passthrough():
    m = normalize_manifest({"name": "s", "env_passthrough": "MY_TOKEN"})
    assert m["env_passthrough"] == ["MY_TOKEN"]

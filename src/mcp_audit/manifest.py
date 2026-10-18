"""Manifest parsing + normalization for the MCP permission auditor.

The manifest is the *declared* surface of an MCP server: the tools it
exposes, the resources it serves, and the permission scopes it claims.
This module turns the raw JSON into a normalized structure the rule
engine can reason about. It never executes anything and performs no
network I/O.
"""

from __future__ import annotations

import json
from typing import Any


class ManifestError(ValueError):
    """Raised when the manifest cannot be parsed or is structurally invalid."""


def load_manifest(path: str) -> dict[str, Any]:
    """Read + parse a JSON manifest file. Raises ManifestError on any failure."""
    try:
        with open(path, "r", encoding="utf-8") as fh:
            raw = json.load(fh)
    except FileNotFoundError as exc:
        raise ManifestError(f"manifest file not found: {path}") from exc
    except json.JSONDecodeError as exc:
        raise ManifestError(f"manifest is not valid JSON ({path}): {exc}") from exc
    except OSError as exc:
        raise ManifestError(f"cannot read manifest ({path}): {exc}") from exc
    return normalize_manifest(raw)


def _as_list(value: Any) -> list:
    if value is None:
        return []
    if isinstance(value, list):
        return value
    return [value]


def normalize_manifest(raw: Any) -> dict[str, Any]:
    """Validate the top-level shape and normalize tools/resources lists.

    Tolerates both `{"tools": [...]}` and `{"capabilities": {"tools": [...]}}`
    style layouts, plus per-server `permissions`/`env_passthrough` blocks.
    """
    if not isinstance(raw, dict):
        raise ManifestError("manifest root must be a JSON object")
    if not raw.get("name"):
        raise ManifestError('manifest must declare a "name" field')

    tools = _as_list(raw.get("tools"))
    resources = _as_list(raw.get("resources"))
    # Some manifests nest declarations under "capabilities".
    caps = raw.get("capabilities")
    if isinstance(caps, dict):
        tools = tools or _as_list(caps.get("tools"))
        resources = resources or _as_list(caps.get("resources"))

    normalized_tools: list[dict[str, Any]] = []
    for i, tool in enumerate(tools):
        if not isinstance(tool, dict):
            raise ManifestError(f"tools[{i}] must be an object")
        if not tool.get("name"):
            raise ManifestError(f"tools[{i}] must declare a \"name\" field")
        normalized_tools.append(
            {
                "name": str(tool["name"]),
                "description": str(tool.get("description") or ""),
                "capabilities": [str(c) for c in _as_list(tool.get("capabilities"))],
                "scopes": [str(s) for s in _as_list(tool.get("scopes"))],
                "permissions": [str(p) for p in _as_list(tool.get("permissions"))],
                "network": bool(tool.get("network", False)),
                "allowed_hosts": [str(h) for h in _as_list(tool.get("allowed_hosts"))],
                "env": [str(e) for e in _as_list(tool.get("env"))],
                "requires_confirmation": bool(tool.get("requires_confirmation", False)),
            }
        )

    normalized_resources: list[dict[str, Any]] = []
    for i, res in enumerate(resources):
        if not isinstance(res, dict):
            raise ManifestError(f"resources[{i}] must be an object")
        if not res.get("uri"):
            raise ManifestError(f"resources[{i}] must declare a \"uri\" field")
        normalized_resources.append(
            {
                "uri": str(res["uri"]),
                "access": str(res.get("access") or "read").lower(),
                "scopes": [str(s) for s in _as_list(res.get("scopes"))],
            }
        )

    return {
        "name": str(raw["name"]),
        "version": str(raw.get("version") or "0.0.0"),
        "description": str(raw.get("description") or ""),
        "tools": normalized_tools,
        "resources": normalized_resources,
        "permissions": [str(p) for p in _as_list(raw.get("permissions"))],
        "env_passthrough": [str(e) for e in _as_list(raw.get("env_passthrough"))],
    }

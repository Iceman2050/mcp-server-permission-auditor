"""Rule-engine tests: every rule fires on its anti-pattern and stays silent otherwise."""
from mcp_audit.manifest import normalize_manifest
from mcp_audit.rules import audit, max_severity, score


def _manifest(**overrides):
    base = {"name": "test-server", "tools": [], "resources": []}
    base.update(overrides)
    return normalize_manifest(base)


def _tool(name="t", **kw):
    t = {"name": name}
    t.update(kw)
    return t


def _rule_ids(findings):
    return {f.rule_id for f in findings}


# --- wildcard permissions -------------------------------------------------

def test_wildcard_server_permission_is_critical():
    fs = audit(_manifest(permissions=["*"]))
    assert "wildcard-permission" in _rule_ids(fs)
    assert max_severity(fs) == "CRITICAL"


def test_wildcard_tool_permission_is_critical():
    fs = audit(_manifest(tools=[_tool(permissions=["fs:*"])]))
    assert "wildcard-permission" in _rule_ids(fs)


def test_explicit_permissions_do_not_fire():
    fs = audit(_manifest(permissions=["fs:read"],
                         tools=[_tool(capabilities=["fs:read"],
                                      scopes=["/srv/data/*"],
                                      description="reads data")]))
    assert "wildcard-permission" not in _rule_ids(fs)


# --- dangerous combos ------------------------------------------------------

def test_write_plus_network_is_critical():
    fs = audit(_manifest(tools=[_tool(capabilities=["fs:write"], network=True)]))
    assert "write-plus-network" in _rule_ids(fs)
    assert max_severity(fs) == "CRITICAL"


def test_exec_plus_network_is_critical():
    fs = audit(_manifest(tools=[_tool(capabilities=["shell"], network=True)]))
    assert "exec-plus-network" in _rule_ids(fs)


def test_write_without_network_is_quiet():
    fs = audit(_manifest(tools=[_tool(capabilities=["fs:write"],
                                      scopes=["/srv/out/*"],
                                      requires_confirmation=True,
                                      description="writes exports")]))
    assert "write-plus-network" not in _rule_ids(fs)
    assert "exec-plus-network" not in _rule_ids(fs)


def test_network_flag_alone_counts_as_egress():
    # network:true is normalized into the capability set
    fs = audit(_manifest(tools=[_tool(capabilities=["fs:read", "fs:write"],
                                      network=True)]))
    assert "write-plus-network" in _rule_ids(fs)


# --- resources ---------------------------------------------------------------

def test_unscoped_resource_is_high():
    fs = audit(_manifest(resources=[{"uri": "notes://x", "access": "read"}]))
    assert "unscoped-resource" in _rule_ids(fs)


def test_scoped_resource_is_quiet():
    fs = audit(_manifest(resources=[{"uri": "notes://x", "access": "read",
                                     "scopes": ["notes://x"]}],
                            tools=[_tool(capabilities=["fs:read"],
                                         scopes=["/srv/*"],
                                         description="ok")]))
    assert "unscoped-resource" not in _rule_ids(fs)


def test_broad_resource_root_is_high():
    fs = audit(_manifest(resources=[{"uri": "file:///**", "access": "read",
                                     "scopes": ["x"]}],
                            tools=[_tool(capabilities=["fs:read"],
                                         scopes=["/srv/*"],
                                         description="ok")]))
    assert "broad-fs-scope" in _rule_ids(fs)


# --- broad filesystem scopes --------------------------------------------------

def test_root_scope_is_high():
    fs = audit(_manifest(tools=[_tool(capabilities=["fs:read"], scopes=["/"],
                                      description="reads everything")]))
    assert "broad-fs-scope" in _rule_ids(fs)


def test_narrow_scope_is_quiet():
    fs = audit(_manifest(tools=[_tool(capabilities=["fs:read"],
                                      scopes=["/srv/data/invoices/*"],
                                      description="reads invoices")]))
    assert "broad-fs-scope" not in _rule_ids(fs)


# --- credential env ------------------------------------------------------------

def test_credential_env_is_high():
    fs = audit(_manifest(env_passthrough=["AWS_SECRET_ACCESS_KEY", "DEBUG"]))
    assert "credential-env" in _rule_ids(fs)
    names = [f.evidence["env"] for f in fs if f.rule_id == "credential-env"]
    assert names == ["AWS_SECRET_ACCESS_KEY"]  # DEBUG must not fire


def test_tool_level_credential_env():
    fs = audit(_manifest(tools=[_tool(env=["GITHUB_TOKEN"])]))
    assert "credential-env" in _rule_ids(fs)


# --- sensitive path read ----------------------------------------------------------

def test_ssh_path_read_is_medium():
    fs = audit(_manifest(tools=[_tool(capabilities=["fs:read"],
                                      scopes=["~/.ssh/*"],
                                      description="reads ssh config")]))
    assert "sensitive-path-read" in _rule_ids(fs)


def test_pem_glob_read_fires():
    fs = audit(_manifest(tools=[_tool(capabilities=["fs:read"],
                                      scopes=["/srv/certs/*.pem"],
                                      description="reads certs")]))
    assert "sensitive-path-read" in _rule_ids(fs)


# --- destructive without confirmation ------------------------------------------------

def test_delete_without_confirmation_is_high():
    fs = audit(_manifest(tools=[_tool(capabilities=["fs:delete"],
                                      description="cleans cache")]))
    assert "destructive-no-confirm" in _rule_ids(fs)


def test_exec_without_confirmation_is_high():
    fs = audit(_manifest(tools=[_tool(capabilities=["process:exec"],
                                      description="runs job")]))
    assert "destructive-no-confirm" in _rule_ids(fs)


def test_confirmation_silences_destructive_rule():
    fs = audit(_manifest(tools=[_tool(capabilities=["fs:delete"],
                                      requires_confirmation=True,
                                      description="cleans cache")]))
    assert "destructive-no-confirm" not in _rule_ids(fs)


# --- network without allowlist -------------------------------------------------------

def test_network_without_allowlist_is_medium():
    fs = audit(_manifest(tools=[_tool(capabilities=["fs:read"], network=True,
                                      description="fetches")]))
    assert "network-no-allowlist" in _rule_ids(fs)


def test_network_with_allowlist_is_quiet():
    fs = audit(_manifest(tools=[_tool(network=True,
                                      allowed_hosts=["api.example.com"],
                                      description="fetches")]))
    assert "network-no-allowlist" not in _rule_ids(fs)


# --- hygiene --------------------------------------------------------------------------

def test_undocumented_tool_is_low():
    fs = audit(_manifest(tools=[_tool(capabilities=["fs:read"],
                                      scopes=["/srv/*"])]))
    lows = [f for f in fs if f.rule_id == "undocumented-tool"]
    assert len(lows) == 1 and lows[0].severity == "LOW"


def test_documented_tool_is_quiet():
    fs = audit(_manifest(tools=[_tool(capabilities=["fs:read"],
                                      scopes=["/srv/*"],
                                      description="reads data")]))
    assert "undocumented-tool" not in _rule_ids(fs)


def test_excessive_tool_surface():
    tools = [_tool(name=f"t{i}", capabilities=["fs:read"], scopes=["/srv/*"],
                   description="ok") for i in range(30)]
    fs = audit(_manifest(tools=tools))
    assert "excessive-tool-surface" in _rule_ids(fs)


# --- scoring / ordering -------------------------------------------------------------------

def test_clean_manifest_scores_zero():
    m = _manifest(tools=[_tool(capabilities=["fs:read"],
                               scopes=["/srv/data/*"],
                               description="reads data")],
                  resources=[{"uri": "notes://x", "access": "read",
                              "scopes": ["notes://x"]}])
    fs = audit(m)
    assert fs == []
    assert score(fs) == 0
    assert max_severity(fs) is None


def test_score_is_capped_at_100():
    m = _manifest(permissions=["*"],
                  tools=[_tool(name="evil", capabilities=["fs:write", "shell"],
                               network=True, scopes=["/"],
                               env=["ROOT_PASSWORD"])])
    fs = audit(m)
    assert score(fs) == 100  # multiple criticals must not exceed 100


def test_findings_sorted_by_severity_desc():
    m = _manifest(permissions=["*"],
                  tools=[_tool(capabilities=["fs:read"], scopes=["/srv/*"])])
    fs = audit(m)
    severities = [f.severity for f in fs]
    order = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}
    assert severities == sorted(severities, key=lambda s: -order[s])
    assert severities[0] == "CRITICAL"


def test_finding_carries_fix_guidance():
    fs = audit(_manifest(permissions=["*"]))
    f = next(f for f in fs if f.rule_id == "wildcard-permission")
    assert f.fix and len(f.fix) > 20
    assert f.target == "server"

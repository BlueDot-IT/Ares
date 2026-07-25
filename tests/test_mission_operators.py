from __future__ import annotations

import pytest
from ares.mission.operators import get_operator, OPERATORS


def test_all_tempest_and_ares_operators_exist():
    required = {
        "coordinator", "recon", "scanner", "validator", "analyst",
        "exploiter", "infiltrator", "exfiltrator", "ghost",
    }
    assert required.issubset(OPERATORS.keys())


def test_unknown_operator_raises():
    with pytest.raises(ValueError, match="unknown operator role: non-existent"):
        get_operator("non-existent")


def test_scanner_can_use_secrets():
    scanner = get_operator("scanner")
    assert "redteam_secrets" in scanner.allowed_toolsets


def test_validator_cannot_use_post_exploitation():
    validator = get_operator("validator")
    # Validator should only be allowed safe scanning toolsets, not remote execution/exploitation/stealth/etc.
    allowed = {"redteam_static", "redteam_secrets", "redteam_deps"}
    assert all(ts in allowed for ts in validator.allowed_toolsets)


def test_imported_roles_are_risk_and_tool_bounded():
    assert get_operator("exploiter").max_risk == "exploit"
    assert get_operator("infiltrator").max_risk == "post-exploitation"
    assert get_operator("exfiltrator").allows_tool("smbclient")
    assert not get_operator("exfiltrator").allows_tool("msfconsole_raw")
    assert not get_operator("ghost").allows_tool("impacket_secretsdump_raw")


def test_operator_allowlists_exist_in_ghostmcp_contract_or_ares_fallback():
    import ghostmcp.server as ghost_server

    from lib.ghostmcp_runner import GhostMCPToolRunner

    runner = GhostMCPToolRunner(transport="inproc")
    manifest_names = {
        str(item["name"]).removesuffix("_tool")
        for item in ghost_server.TOOL_MANIFEST.export(
            ghost_server.__version__
        )["tools"]
    }
    catalog = manifest_names | set(runner.tools)
    for role_id in (
        "recon",
        "exploiter",
        "infiltrator",
        "exfiltrator",
        "ghost",
    ):
        assert set(get_operator(role_id).allowed_tools) <= catalog
    runner.close()

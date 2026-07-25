from __future__ import annotations

import pytest
from ares.mission.profiles import get_profile, PROFILES


def test_required_profiles_exist():
    required = {
        "source-code-audit", "secrets-audit", "dependency-audit", "report-only",
        "authorized-operator-validation",
    }
    assert required.issubset(PROFILES.keys())


def test_unknown_profile_raises():
    with pytest.raises(ValueError, match="unknown mission profile: non-existent"):
        get_profile("non-existent")


def test_secrets_audit_enables_only_secrets():
    profile = get_profile("secrets-audit")
    assert profile.enabled_toolsets == ("redteam_secrets",)


def test_report_only_max_risk_safe():
    profile = get_profile("report-only")
    assert profile.max_risk == "safe"


def test_authorized_operator_profile_is_explicitly_high_risk():
    profile = get_profile("authorized-operator-validation")
    assert profile.enabled_toolsets == ("ghostmcp",)
    assert profile.max_risk == "post-exploitation"

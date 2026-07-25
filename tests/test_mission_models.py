from __future__ import annotations

from ares.mission.model import MissionRun, MissionScope, MissionStatus, MissionPhase


def test_mission_defaults():
    scope = MissionScope(target="test_target")
    run = MissionRun(id="run1", profile_id="source-code-audit", scope=scope)
    assert run.status == MissionStatus.CREATED
    assert run.phase == MissionPhase.PLAN


def test_scope_stores_target():
    scope = MissionScope(target="test_target", allowed_paths=["/tmp"])
    assert scope.target == "test_target"
    assert scope.allowed_paths == ["/tmp"]


def test_metadata_default_independent():
    scope = MissionScope(target="target")
    run1 = MissionRun(id="run1", profile_id="source-code-audit", scope=scope)
    run2 = MissionRun(id="run2", profile_id="source-code-audit", scope=scope)
    
    run1.metadata["key"] = "value"
    assert "key" not in run2.metadata

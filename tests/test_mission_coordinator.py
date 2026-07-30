from __future__ import annotations

import tempfile
import time
from pathlib import Path

import pytest

from ares.mission.coordinator import MissionCoordinator, _host_from_target
from ares.mission.model import MissionRun, MissionScope, MissionStatus, MissionPhase
from ares.mission.tasks import MissionTask, TaskStatus
from ares.mission.approvals import task_approval_digest
from ares.state.db import StateDB
from ares.tools.registry import ToolRegistry


@pytest.mark.parametrize(
    ("target", "expected"),
    [
        ("example.test:443", "example.test"),
        ("https://example.test/path", "example.test"),
        ("2001:db8::1", "2001:db8::1"),
        ("[2001:db8::1]:443", "2001:db8::1"),
        ("https://[2001:db8::1]/", "2001:db8::1"),
    ],
)
def test_host_from_target_preserves_ipv6(
    target: str,
    expected: str,
) -> None:
    assert _host_from_target(target) == expected


def test_validation_and_seeding():
    with tempfile.TemporaryDirectory() as tmpdir:
        # Resolve the tmpdir path so relative path comparisons are consistent
        tmpdir_path = Path(tmpdir).resolve()
        
        # Setup scope
        scope = MissionScope(
            target=str(tmpdir_path / "src"),
            allowed_paths=[str(tmpdir_path)],
            forbidden_paths=[],
            allowed_hosts=[],
            forbidden_actions=[],
            max_risk="scan",
        )
        
        # Create src subdirectory so target path resolution is valid
        (tmpdir_path / "src").mkdir()

        mission = MissionRun(
            id="m1",
            profile_id="source-code-audit",
            scope=scope,
            status=MissionStatus.CREATED,
            phase=MissionPhase.PLAN,
        )

        coordinator = MissionCoordinator(mission)

        # 1. Valid scanner task passes
        task = MissionTask(
            id="t1",
            mission_id="m1",
            role_id="scanner",
            phase="scan",
            tool_name="redteam_secret_scan",
            toolset="redteam_secrets",
            target=str(tmpdir_path / "src"),
            description="Valid secret scan task",
        )
        valid, reason = coordinator.validate_task(task)
        assert valid is True, reason

        # 2. Wrong mission id fails
        task_wrong_m = MissionTask(
            id="t2",
            mission_id="m_wrong",
            role_id="scanner",
            phase="scan",
            tool_name="redteam_secret_scan",
            toolset="redteam_secrets",
            target=str(tmpdir_path / "src"),
            description="Valid secret scan task",
        )
        valid, reason = coordinator.validate_task(task_wrong_m)
        assert valid is False
        assert "mission_id mismatch" in reason

        # 3. Unknown role fails
        task_wrong_role = MissionTask(
            id="t3",
            mission_id="m1",
            role_id="non_existent_role",
            phase="scan",
            tool_name="redteam_secret_scan",
            toolset="redteam_secrets",
            target=str(tmpdir_path / "src"),
            description="Valid secret scan task",
        )
        valid, reason = coordinator.validate_task(task_wrong_role)
        assert valid is False
        assert "unknown operator role" in reason

        # 4. Wrong toolset fails
        task_wrong_toolset = MissionTask(
            id="t4",
            mission_id="m1",
            role_id="scanner",
            phase="scan",
            tool_name="some_exfil_tool",
            toolset="redteam_exfil",
            target=str(tmpdir_path / "src"),
            description="Invalid toolset",
        )
        valid, reason = coordinator.validate_task(task_wrong_toolset)
        assert valid is False
        assert "not enabled in profile" in reason

        # 5. Forbidden path fails
        task_forbidden_path = MissionTask(
            id="t5",
            mission_id="m1",
            role_id="scanner",
            phase="scan",
            tool_name="redteam_secret_scan",
            toolset="redteam_secrets",
            target=str(tmpdir_path / ".git"),
            description="Scanning git",
        )
        valid, reason = coordinator.validate_task(task_forbidden_path)
        assert valid is False
        assert "forbidden" in reason

        # 6. Outside allowed path fails
        task_outside_path = MissionTask(
            id="t6",
            mission_id="m1",
            role_id="scanner",
            phase="scan",
            tool_name="redteam_secret_scan",
            toolset="redteam_secrets",
            target="/etc/passwd",
            description="Scanning outside target",
        )
        valid, reason = coordinator.validate_task(task_outside_path)
        assert valid is False
        assert "outside allowed scope paths" in reason

        # 7. Empty description fails
        task_empty_desc = MissionTask(
            id="t7",
            mission_id="m1",
            role_id="scanner",
            phase="scan",
            tool_name="redteam_secret_scan",
            toolset="redteam_secrets",
            target=str(tmpdir_path / "src"),
            description="   ",
        )
        valid, reason = coordinator.validate_task(task_empty_desc)
        assert valid is False
        assert "description is empty" in reason


def test_task_seeding():
    with tempfile.TemporaryDirectory() as tmpdir:
        tmpdir_path = Path(tmpdir).resolve()
        
        # Test secrets-audit seeding
        scope_sec = MissionScope(target=str(tmpdir_path))
        m_sec = MissionRun(id="m_sec", profile_id="secrets-audit", scope=scope_sec)
        coord_sec = MissionCoordinator(m_sec)
        tasks_sec = coord_sec.seed_initial_tasks()
        assert len(tasks_sec) == 3
        # Ensure correct roles and dependencies
        assert tasks_sec[0].role_id == "scanner"
        assert tasks_sec[0].toolset == "redteam_secrets"
        assert tasks_sec[1].role_id == "validator"
        assert tasks_sec[1].depends_on == [tasks_sec[0].id]
        assert tasks_sec[2].role_id == "analyst"
        assert tasks_sec[2].depends_on == [tasks_sec[1].id]

        # Test dependency-audit seeding
        scope_dep = MissionScope(target=str(tmpdir_path))
        m_dep = MissionRun(id="m_dep", profile_id="dependency-audit", scope=scope_dep)
        coord_dep = MissionCoordinator(m_dep)
        tasks_dep = coord_dep.seed_initial_tasks()
        assert len(tasks_dep) == 2
        assert tasks_dep[0].role_id == "scanner"
        assert tasks_dep[0].toolset == "redteam_deps"
        assert tasks_dep[1].role_id == "analyst"
        assert tasks_dep[1].depends_on == [tasks_dep[0].id]

        # Test source-code-audit seeding
        scope_sca = MissionScope(target=str(tmpdir_path))
        m_sca = MissionRun(id="m_sca", profile_id="source-code-audit", scope=scope_sca)
        coord_sca = MissionCoordinator(m_sca)
        tasks_sca = coord_sca.seed_initial_tasks()
        assert len(tasks_sca) == 4
        # Validate validator depends on both scanner tasks
        validator_task = [t for t in tasks_sca if t.role_id == "validator"][0]
        scanner_ids = [t.id for t in tasks_sca if t.role_id == "scanner"]
        assert set(validator_task.depends_on) == set(scanner_ids)

        # Test report-only seeding
        scope_rep = MissionScope(target=str(tmpdir_path))
        m_rep = MissionRun(id="m_rep", profile_id="report-only", scope=scope_rep)
        coord_rep = MissionCoordinator(m_rep)
        tasks_rep = coord_rep.seed_initial_tasks()
        assert len(tasks_rep) == 1
        assert tasks_rep[0].role_id == "analyst"


def test_imported_operator_validation_is_fail_closed():
    with tempfile.TemporaryDirectory() as tmpdir:
        target = "127.0.0.1"
        mission = MissionRun(
            id="m_advanced",
            profile_id="authorized-operator-validation",
            scope=MissionScope(
                target=target,
                allowed_hosts=[target],
                max_risk="post-exploitation",
            ),
        )
        coordinator = MissionCoordinator(mission)
        allowed = MissionTask(
            id="t_allowed",
            mission_id=mission.id,
            role_id="infiltrator",
            phase="post-exploitation",
            tool_name="smbmap",
            toolset="ghostmcp",
            target=target,
            description="Validate the authorized lateral-access boundary.",
            supporting_evidence_tool_call_ids=[1],
        )
        valid, reason = coordinator.validate_task(allowed)
        assert valid is True, reason

        wrong_tool = MissionTask(
            **{**allowed.__dict__, "id": "t_wrong_tool", "tool_name": "msfconsole_raw"}
        )
        valid, reason = coordinator.validate_task(wrong_tool)
        assert valid is False
        assert "not allowed for role infiltrator" in reason

        low_risk_mission = MissionRun(
            id="m_low_risk",
            profile_id="authorized-operator-validation",
            scope=MissionScope(target=target, allowed_hosts=[target], max_risk="scan"),
        )
        low_risk_task = MissionTask(
            **{**allowed.__dict__, "mission_id": low_risk_mission.id, "id": "t_low_risk"}
        )
        valid, reason = MissionCoordinator(low_risk_mission).validate_task(low_risk_task)
        assert valid is False
        assert "requires risk ceiling post-exploitation" in reason


def test_scope_rejects_allowed_path_ancestor_and_argument_host_divergence():
    with tempfile.TemporaryDirectory() as tmpdir:
        root = Path(tmpdir).resolve()
        allowed = root / "only-here"
        allowed.mkdir()
        local_mission = MissionRun(
            id="m_local_scope",
            profile_id="secrets-audit",
            scope=MissionScope(target=str(allowed), allowed_paths=[str(allowed)]),
        )
        ancestor_task = MissionTask(
            id="t_ancestor",
            mission_id=local_mission.id,
            role_id="scanner",
            phase="scan",
            tool_name="redteam_secret_scan",
            toolset="redteam_secrets",
            target=str(root),
            description="Attempt ancestor scan.",
        )
        valid, _ = MissionCoordinator(local_mission).validate_task(ancestor_task)
        assert valid is False

        network_mission = MissionRun(
            id="m_network_scope",
            profile_id="authorized-operator-validation",
            scope=MissionScope(
                target="10.0.0.5",
                allowed_hosts=["10.0.0.5"],
                max_risk="post-exploitation",
            ),
        )
        divergent = MissionTask(
            id="t_divergent",
            mission_id=network_mission.id,
            role_id="infiltrator",
            phase="post-exploitation",
            tool_name="smbmap",
            toolset="ghostmcp",
            target="10.0.0.5",
            args={"host": "10.0.0.6"},
            description="Validate one approved path.",
        )
        valid, reason = MissionCoordinator(network_mission).validate_task(divergent)
        assert valid is False
        assert "outside allowed host scope" in reason


def test_advanced_initial_task_uses_approval_and_preserves_tool_arguments():
    with tempfile.TemporaryDirectory() as tmpdir:
        db = StateDB(Path(tmpdir) / "state.db")
        calls = []
        registry = ToolRegistry()
        registry.register(
            name="smbmap",
            toolset="ghostmcp",
            risk="active",
            schema={"type": "object", "properties": {"host": {"type": "string"}}},
            handler=lambda args, **_: calls.append(args) or {"summary": "bounded access check"},
        )
        mission = MissionRun(
            id="m_approved",
            profile_id="authorized-operator-validation",
            scope=MissionScope(
                target="127.0.0.1",
                allowed_hosts=["127.0.0.1"],
                max_risk="post-exploitation",
            ),
        )
        db.create_mission(mission)
        evidence_session = db.create_session(
            prompt="evidence", target="127.0.0.1"
        )
        db.record_mission_operator_run(
            mission_id=mission.id, task_id=None, role_id="recon",
            session_id=evidence_session, status="completed",
        )
        evidence_id = db.record_tool_call(
            evidence_session, tool="nmap_basic",
            args={"target": "127.0.0.1"}, result={"open": [445]},
        )
        task = MissionTask(
            id="t_approved",
            mission_id=mission.id,
            role_id="infiltrator",
            phase="post-exploitation",
            tool_name="smbmap",
            toolset="ghostmcp",
            target="127.0.0.1",
            args={"host": "127.0.0.1"},
            description="Validate one authorized lateral-access boundary.",
            supporting_evidence_tool_call_ids=[evidence_id],
            approval_receipt_id="receipt-approved",
        )
        db.record_approval_receipt(
            receipt_id="receipt-approved", mission_id=mission.id,
            task_id=task.id, task_digest=task_approval_digest(task),
            source="pytest", approver="operator", approved_at=time.time(),
        )
        MissionCoordinator(mission).run_deterministic(
            registry,
            db,
            initial_tasks=[task],
            approval_callback=lambda _call, _entry: True,
        )
        assert calls == [{"host": "127.0.0.1"}]
        assert db.get_mission(mission.id)["status"] == "completed"

        denied_mission = MissionRun(
            id="m_denied",
            profile_id="authorized-operator-validation",
            scope=mission.scope,
        )
        denied_task = MissionTask(
            **{**task.__dict__, "id": "t_denied", "mission_id": denied_mission.id}
        )
        MissionCoordinator(denied_mission).run_deterministic(
            registry,
            db,
            initial_tasks=[denied_task],
        )
        assert db.get_mission(denied_mission.id)["status"] == "blocked"

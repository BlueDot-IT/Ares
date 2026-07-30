from __future__ import annotations

import time

import pytest

from ares.autonomy.graph import AttackSurfaceGraph, NodeKind
from ares.autonomy.recovery import ReconRecoveryPolicy
from ares.mission.approvals import task_approval_digest
from ares.mission.coordinator import MissionCoordinator
from ares.mission.findings import FindingState, MissionFinding, Severity
from ares.mission.model import MissionRun, MissionScope
from ares.mission.tasks import MissionTask
from ares.state.db import StateDB
from ares.tools.registry import ToolRegistry


def test_explicit_finding_lifecycle_and_version_only_guard() -> None:
    finding = MissionFinding(
        id="f1",
        mission_id="m1",
        title="Observed version",
        severity=Severity.INFO,
        state=FindingState.OBSERVED,
        evidence_tool_call_ids=[1, 2],
        reproduction_steps=["Repeat the bounded probe."],
        confidence=0.9,
        confidence_rationale="Two tools agree.",
        severity_rationale="Impact would be material if demonstrated.",
        validator_note="Behavior reproduced safely.",
        version_only=True,
    )
    finding.hypothesize()
    finding.corroborate()
    with pytest.raises(ValueError, match="version-only"):
        finding.validate()
    finding.version_only = False
    finding.validate()
    assert finding.state == FindingState.SAFELY_VALIDATED
    finding.report()
    assert finding.state == FindingState.REPORTED


def test_recovery_preserves_http_404_error_evidence_and_is_bounded(
    tmp_path,
) -> None:
    db = StateDB(tmp_path / "state.db")
    mission = MissionRun(
        id="m404",
        profile_id="autonomous-recon",
        scope=MissionScope(
            target="127.0.0.1",
            allowed_hosts=["127.0.0.1"],
            max_risk="active",
        ),
    )
    db.create_mission(mission)
    session = db.create_session(prompt="test", target="127.0.0.1")
    call_id = db.record_tool_call(
        session,
        tool="http_probe",
        args={"url": "http://127.0.0.1/"},
        status="error",
        error="HTTP Error 404: Not Found",
    )
    policy = ReconRecoveryPolicy(
        state_db=db,
        mission_id=mission.id,
        target_allowed=lambda value: value == "127.0.0.1",
    )
    task = MissionTask(
        id="t1", mission_id=mission.id, role_id="recon", phase="recon",
        tool_name="http_probe", toolset="ghostmcp", target="127.0.0.1",
        description="probe", args={"url": "http://127.0.0.1/"},
    )
    item = {
        "id": "cov1", "capability": "web.probe",
        "subject": {
            "attributes": {"host_address": "127.0.0.1", "port": 80}
        },
    }
    decision = policy.decide(
        original_task=task,
        coverage_item=item,
        original_tool_call_id=call_id,
    )
    assert decision.strategy == "preserve_http_response"
    assert decision.task is None
    db.record_recovery_attempt(
        mission_id=mission.id,
        coverage_id="cov1",
        original_tool_call_id=call_id,
        recovery_tool_call_id=None,
        strategy=decision.strategy,
        status="completed",
    )
    assert policy.decide(
        original_task=task,
        coverage_item=item,
        original_tool_call_id=call_id,
    ).task is None


def test_advanced_role_requires_mission_evidence_and_single_use_receipt(
    tmp_path,
) -> None:
    db = StateDB(tmp_path / "state.db")
    mission = MissionRun(
        id="m_advanced_receipt",
        profile_id="authorized-operator-validation",
        scope=MissionScope(
            target="127.0.0.1",
            allowed_hosts=["127.0.0.1"],
            max_risk="post-exploitation",
        ),
    )
    db.create_mission(mission)
    evidence_session = db.create_session(prompt="evidence", target="127.0.0.1")
    db.record_mission_operator_run(
        mission_id=mission.id, task_id=None, role_id="recon",
        session_id=evidence_session, status="completed",
    )
    evidence_id = db.record_tool_call(
        evidence_session, tool="nmap_basic",
        args={"target": "127.0.0.1"}, result={"open": [445]},
    )
    task = MissionTask(
        id="advanced-1",
        mission_id=mission.id,
        role_id="infiltrator",
        phase="post-exploitation",
        tool_name="smbmap",
        toolset="ghostmcp",
        target="127.0.0.1",
        description="Validate one explicitly authorized access boundary.",
        args={"host": "127.0.0.1"},
        supporting_evidence_tool_call_ids=[evidence_id],
        approval_receipt_id="receipt-1",
    )
    digest = task_approval_digest(task)
    db.record_approval_receipt(
        receipt_id="receipt-1", mission_id=mission.id, task_id=task.id,
        task_digest=digest, source="operator-cli", approver="test-operator",
        approved_at=time.time(), expires_at=time.time() + 60,
    )
    with pytest.raises(Exception):
        db.record_approval_receipt(
            receipt_id="receipt-1", mission_id=mission.id, task_id=task.id,
            task_digest="0" * 64, source="replace", approver="attacker",
            approved_at=time.time(),
        )
    registry = ToolRegistry()
    calls = []
    registry.register(
        name="smbmap", toolset="ghostmcp", risk="active",
        schema={"type": "object"}, handler=lambda args, **_: calls.append(args) or {},
    )
    report = MissionCoordinator(mission).run_deterministic(
        registry, db, initial_tasks=[task],
        approval_callback=lambda _call, _entry: True,
    )
    assert calls == [{"host": "127.0.0.1"}]
    assert db.get_approval_receipt("receipt-1")["used_at"] is not None
    assert db.consume_approval_receipt("receipt-1") is False
    assert f"Supporting Evidence Tool Calls: {evidence_id}" in report
    assert "Approval Receipt: receipt-1" in report


@pytest.mark.parametrize(
    ("status", "result", "target", "expected"),
    [
        ("error", {"open": [445]}, "127.0.0.1", "did not complete"),
        ("ok", {}, "127.0.0.1", "no observed result"),
        ("ok", {"open": [445]}, "127.0.0.2", "not bound to task target"),
    ],
)
def test_advanced_role_rejects_weak_or_cross_target_evidence(
    tmp_path, status, result, target, expected
) -> None:
    db = StateDB(tmp_path / "state.db")
    mission = MissionRun(
        id=f"m-evidence-{status}-{target}",
        profile_id="authorized-operator-validation",
        scope=MissionScope(
            target="127.0.0.1",
            allowed_hosts=["127.0.0.1", "127.0.0.2"],
            max_risk="post-exploitation",
        ),
    )
    db.create_mission(mission)
    session_id = db.create_session(prompt="evidence", target=target)
    db.record_mission_operator_run(
        mission_id=mission.id,
        task_id="recon",
        role_id="recon",
        session_id=session_id,
        status="completed",
    )
    evidence_id = db.record_tool_call(
        session_id,
        tool="nmap_basic",
        args={"target": target},
        status=status,
        result=result,
        error="failed" if status == "error" else None,
    )
    task = MissionTask(
        id="advanced",
        mission_id=mission.id,
        role_id="infiltrator",
        phase="post-exploitation",
        tool_name="smbmap",
        toolset="ghostmcp",
        target="127.0.0.1",
        description="Validate one boundary.",
        args={"host": "127.0.0.1"},
        supporting_evidence_tool_call_ids=[evidence_id],
        approval_receipt_id="receipt",
    )
    valid, reason = MissionCoordinator(
        mission
    )._validate_advanced_authorization(task, db)
    assert valid is False
    assert expected in reason


def test_recovery_claim_is_atomic_and_survives_interruption(tmp_path) -> None:
    db = StateDB(tmp_path / "state.db")
    mission = MissionRun(
        id="m-recovery-claim",
        profile_id="autonomous-recon",
        scope=MissionScope(
            target="127.0.0.1",
            allowed_hosts=["127.0.0.1"],
            max_risk="active",
        ),
    )
    db.create_mission(mission)
    first = db.record_recovery_attempt(
        mission_id=mission.id,
        coverage_id="coverage-1",
        original_tool_call_id=None,
        recovery_tool_call_id=None,
        strategy="http_banner_fallback",
        status="reserved",
    )
    second = db.record_recovery_attempt(
        mission_id=mission.id,
        coverage_id="coverage-1",
        original_tool_call_id=None,
        recovery_tool_call_id=None,
        strategy="http_banner_fallback",
        status="reserved",
    )
    assert first > 0
    assert second == 0


def test_tls_recovery_uses_only_explicitly_allowed_sni(tmp_path) -> None:
    db = StateDB(tmp_path / "state.db")
    mission = MissionRun(
        id="m-sni",
        profile_id="autonomous-recon",
        scope=MissionScope(
            target="192.0.2.10",
            allowed_hosts=["192.0.2.10", "mail.example.test"],
            max_risk="active",
        ),
    )
    db.create_mission(mission)
    graph = AttackSurfaceGraph(db, mission.id)
    domain = graph.upsert_node(
        kind=NodeKind.DOMAIN,
        key="mail.example.test",
    )
    address = graph.upsert_node(
        kind=NodeKind.HOST,
        key="192.0.2.10",
    )
    graph.connect(domain, address, "resolves_to")
    session_id = db.create_session(prompt="tls", target="192.0.2.10")
    tool_call_id = db.record_tool_call(
        session_id,
        tool="sslscan",
        args={"host": "192.0.2.10", "port": 443},
        status="error",
        error="certificate hostname mismatch",
    )
    task = MissionTask(
        id="tls",
        mission_id=mission.id,
        role_id="recon",
        phase="recon",
        tool_name="sslscan",
        toolset="ghostmcp",
        target="192.0.2.10",
        description="Assess TLS.",
        args={"host": "192.0.2.10", "port": 443},
    )
    item = {
        "id": "tls-coverage",
        "capability": "tls.assessment",
        "subject": {
            "attributes": {
                "host_address": "192.0.2.10",
                "port": 443,
            }
        },
    }
    allowed = ReconRecoveryPolicy(
        state_db=db,
        mission_id=mission.id,
        target_allowed=lambda value: value in {
            "192.0.2.10", "mail.example.test"
        },
    ).decide(
        original_task=task,
        coverage_item=item,
        original_tool_call_id=tool_call_id,
    )
    assert allowed.strategy == "tls_sni_fallback"
    assert allowed.task is not None
    assert allowed.task.target == "mail.example.test"

    denied = ReconRecoveryPolicy(
        state_db=db,
        mission_id=mission.id,
        target_allowed=lambda value: value == "192.0.2.10",
    ).decide(
        original_task=task,
        coverage_item={**item, "id": "tls-coverage-denied"},
        original_tool_call_id=tool_call_id,
    )
    assert denied.strategy == "tls_certificate_fallback"
    assert denied.task is not None
    assert denied.task.target == "192.0.2.10"


def test_cross_mission_task_id_collision_is_rejected(tmp_path) -> None:
    db = StateDB(tmp_path / "state.db")
    for mission_id in ("mission-a", "mission-b"):
        db.create_mission(
            MissionRun(
                id=mission_id,
                profile_id="autonomous-recon",
                scope=MissionScope(target="127.0.0.1"),
            )
        )
    first = MissionTask(
        id="same-task",
        mission_id="mission-a",
        role_id="recon",
        phase="recon",
        tool_name="nmap_basic",
        toolset="ghostmcp",
        target="127.0.0.1",
        description="First mission task.",
    )
    second = MissionTask(
        id="same-task",
        mission_id="mission-b",
        role_id="recon",
        phase="recon",
        tool_name="nmap_basic",
        toolset="ghostmcp",
        target="127.0.0.1",
        description="Second mission task.",
    )
    db.record_mission_task(first)
    with pytest.raises(ValueError, match="already owned"):
        db.record_mission_task(second)
    assert [row["id"] for row in db.list_mission_tasks("mission-a")] == [
        "same-task"
    ]
    assert db.list_mission_tasks("mission-b") == []


def test_existing_mission_id_cannot_change_profile_or_scope(tmp_path) -> None:
    db = StateDB(tmp_path / "state.db")
    original = MissionRun(
        id="fixed-mission",
        profile_id="autonomous-recon",
        scope=MissionScope(
            target="127.0.0.1",
            allowed_hosts=["127.0.0.1"],
            max_risk="active",
        ),
    )
    db.create_mission(original)
    confused = MissionRun(
        id=original.id,
        profile_id="authorized-operator-validation",
        scope=MissionScope(
            target="127.0.0.1",
            allowed_hosts=["127.0.0.1"],
            max_risk="post-exploitation",
        ),
    )
    with pytest.raises(ValueError, match="different profile, scope"):
        MissionCoordinator(confused).run_deterministic(
            ToolRegistry(),
            db,
            initial_tasks=[],
        )

    changed_ports = MissionRun(
        id=original.id,
        profile_id=original.profile_id,
        scope=original.scope,
        metadata={"port_scope": "1-2000"},
    )
    with pytest.raises(ValueError, match="execution metadata"):
        MissionCoordinator(changed_ports).run_deterministic(
            ToolRegistry(),
            db,
            initial_tasks=[],
        )

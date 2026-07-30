from __future__ import annotations

import math
import time

import pytest

from ares.mission.approvals import (
    APPROVAL_DIGEST_SCHEMA,
    parse_approval_receipts,
    task_approval_digest,
)
from ares.mission.context import build_mission_context_pack
from ares.mission.findings import FindingState, MissionFinding, Severity
from ares.mission.model import MissionRun, MissionScope
from ares.mission.report import render_mission_report
from ares.mission.tasks import MissionTask
from ares.state.db import StateDB


def _task(**overrides) -> MissionTask:
    values = {
        "id": "task-1",
        "mission_id": "mission-1",
        "role_id": "infiltrator",
        "phase": "post-exploitation",
        "tool_name": "smbmap",
        "toolset": "ghostmcp",
        "target": "192.0.2.10",
        "description": "Validate one boundary.",
        "args": {"host": "192.0.2.10"},
        "depends_on": ["recon-1"],
        "supporting_evidence_tool_call_ids": [7],
    }
    values.update(overrides)
    return MissionTask(**values)


def test_approval_digest_binds_contract_description_and_dependencies() -> None:
    assert APPROVAL_DIGEST_SCHEMA.endswith(".v1")
    baseline = task_approval_digest(_task())
    assert task_approval_digest(_task(description="Different")) != baseline
    assert task_approval_digest(_task(depends_on=["other"])) != baseline


@pytest.mark.parametrize(
    "field,value",
    [
        ("task_digest", "g" * 64),
        ("approved_at", math.nan),
        ("approved_at", math.inf),
        ("approved_at", time.time() + 301),
        ("expires_at", math.inf),
    ],
)
def test_receipt_parser_rejects_malformed_digest_and_times(
    field: str, value: object
) -> None:
    receipt = {
        "id": "r1",
        "task_id": "task-1",
        "task_digest": "a" * 64,
        "source": "operator",
        "approver": "person",
        "approved_at": time.time(),
        "expires_at": time.time() + 60,
    }
    receipt[field] = value
    with pytest.raises(ValueError):
        parse_approval_receipts([receipt])


def test_receipt_expiry_must_follow_approval() -> None:
    now = time.time()
    with pytest.raises(ValueError, match="expires before approval"):
        parse_approval_receipts([{
            "id": "r1",
            "task_id": "task-1",
            "task_digest": "a" * 64,
            "source": "operator",
            "approver": "person",
            "approved_at": now,
            "expires_at": now - 1,
        }])


def test_contradictory_evidence_requires_resolution() -> None:
    finding = MissionFinding(
        id="f1", mission_id="m1", title="Behavior", severity=Severity.HIGH,
        state=FindingState.CORROBORATED,
        evidence_tool_call_ids=[1, 2],
        contradictory_evidence_tool_call_ids=[3],
        reproduction_steps=["Repeat bounded proof."],
        confidence=0.9,
        confidence_rationale="Two independent observations.",
        severity_rationale="Bounded impact was observed.",
        validator_note="Reproduced.",
    )
    assert finding.can_validate() is False
    finding.contradiction_resolution = (
        "Evidence 3 used a different virtual host and does not reproduce "
        "the assessed endpoint."
    )
    finding.validate()
    assert finding.state == FindingState.SAFELY_VALIDATED


def test_report_never_calls_unresolved_or_inconclusive_scope_clean() -> None:
    mission = MissionRun(
        id="m1", profile_id="autonomous-recon",
        scope=MissionScope(target="192.0.2.10"),
    )
    report = render_mission_report(
        mission=mission,
        tasks=[],
        findings=[{
            "id": "f1", "title": "Possible issue", "severity": "low",
            "state": "hypothesized",
        }],
        evidence_chunks=[],
        coverage_items=[{
            "status": "inconclusive", "capability": "web.probe",
            "subject_node_id": "n1", "attempts": 1,
        }],
    )
    assert "Scope appears clean" not in report
    assert "unresolved finding hypotheses" in report.lower()


def test_authorized_report_and_analyst_context_are_truthful() -> None:
    mission = MissionRun(
        id="m1", profile_id="authorized-operator-validation",
        scope=MissionScope(target="192.0.2.10"),
    )
    report = render_mission_report(
        mission=mission, tasks=[], findings=[], evidence_chunks=[]
    )
    assert "active, exploit, or post-exploitation" in report
    context = build_mission_context_pack(
        mission,
        role_id="analyst",
        findings=[
            {"id": "legacy", "title": "Old", "severity": "high",
             "state": "validated"},
            {"id": "safe", "title": "Safe", "severity": "high",
             "state": "safely_validated"},
        ],
    )
    assert "safe: Safe" in context
    assert "legacy: Old" not in context


def test_reported_findings_remain_visible_in_report_and_context() -> None:
    mission = MissionRun(
        id="m-reported",
        profile_id="source-code-audit",
        scope=MissionScope(target="src"),
    )
    finding = {
        "id": "reported-1",
        "title": "Reported issue",
        "severity": "high",
        "state": "reported",
        "confidence": 0.9,
        "validator_note": "Safely reproduced before reporting.",
        "recommendation": "Fix the issue.",
    }
    report = render_mission_report(
        mission=mission,
        tasks=[],
        findings=[finding],
        evidence_chunks=[],
    )
    assert "1 confirmed (1 reported)" in report
    assert "Reported issue" in report
    assert "- **State**: reported" in report
    context = build_mission_context_pack(
        mission,
        role_id="analyst",
        findings=[finding],
    )
    assert "reported-1: Reported issue" in context


def test_expired_receipt_cannot_be_consumed_atomically(tmp_path) -> None:
    db = StateDB(tmp_path / "state.db")
    mission = MissionRun(
        id="m-expired",
        profile_id="authorized-operator-validation",
        scope=MissionScope(target="192.0.2.10"),
    )
    db.create_mission(mission)
    db.record_approval_receipt(
        receipt_id="expired",
        mission_id=mission.id,
        task_id="task-1",
        task_digest="a" * 64,
        source="test",
        approver="test",
        approved_at=time.time() - 120,
        expires_at=time.time() - 60,
    )
    assert db.consume_approval_receipt("expired") is False
    assert db.get_approval_receipt("expired")["used_at"] is None


def test_current_schema_preserves_reported_state_on_reopen(tmp_path) -> None:
    path = tmp_path / "state.db"
    db = StateDB(path)
    mission = MissionRun(
        id="m-reopen",
        profile_id="source-code-audit",
        scope=MissionScope(target="src"),
    )
    db.create_mission(mission)
    db.record_mission_finding(
        MissionFinding(
            id="reported",
            mission_id=mission.id,
            title="Reported issue",
            severity=Severity.HIGH,
            state=FindingState.REPORTED,
        )
    )
    assert db.list_mission_findings(mission.id)[0]["state"] == "reported"
    reopened = StateDB(path)
    assert reopened.list_mission_findings(mission.id)[0]["state"] == (
        "reported"
    )

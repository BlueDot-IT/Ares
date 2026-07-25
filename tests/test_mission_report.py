from __future__ import annotations

from ares.mission.model import MissionRun, MissionScope, MissionStatus, MissionPhase
from ares.mission.report import render_mission_report


def test_mission_report_rendering():
    scope = MissionScope(
        target="src",
        allowed_paths=["src"],
        forbidden_paths=["tests"],
        allowed_hosts=["localhost"],
        forbidden_actions=["read_env"],
        max_risk="scan",
    )
    mission = MissionRun(
        id="m_report_test",
        profile_id="source-code-audit",
        scope=scope,
        status=MissionStatus.COMPLETED,
        phase=MissionPhase.REPORT,
    )

    tasks = [
        {"id": "t1", "role_id": "scanner", "phase": "scan", "description": "Scan secrets", "status": "completed"},
        {"id": "t2", "role_id": "analyst", "phase": "report", "description": "Report", "status": "blocked", "block_reason": "waiting"},
    ]
    findings = [
        {
            "id": "f1",
            "title": "API Key Exposure",
            "severity": "medium",
            "state": "validated",
            "affected_component": "config.py",
            "confidence": 0.85,
            "validator_note": "Found hardcoded key",
            "recommendation": "Rotate keys",
            "redacted": "api_key = ***REDACTED***",
        },
        {
            "id": "f2",
            "title": "Invalid Finding",
            "state": "refuted",
            "validator_note": "Not a finding",
        }
    ]
    evidence = [
        {"id": 42, "source_type": "manual", "source_id": "note", "tags": ["secrets"], "content": "api_key = 123"}
    ]

    report = render_mission_report(mission=mission, tasks=tasks, findings=findings, evidence_chunks=evidence)

    assert "# ARES Mission Report" in report
    assert "## Summary" in report
    assert "## Scope" in report
    assert "## Tasks" in report
    assert "## Validated Findings" in report
    assert "## Refuted Findings" in report
    assert "## Evidence" in report
    assert "## Limitations" in report
    assert "## Recommendations" in report

    assert "m_report_test" in report
    assert "Rotate keys" in report
    assert "api_key = ***REDACTED***" in report
    assert "Not a finding" in report
    assert "Memory Chunk 42" in report
    assert "Analysis is static" in report

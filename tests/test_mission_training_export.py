from __future__ import annotations

import json
import tempfile
from pathlib import Path

from ares.state.db import StateDB
from ares.mission.model import MissionRun, MissionScope, MissionStatus, MissionPhase
from ares.mission.tasks import MissionTask, TaskStatus
from ares.mission.findings import MissionFinding, Severity, FindingState
from ares.training.export import export_mission_traces


def test_export_mission_traces_workflow():
    with tempfile.TemporaryDirectory() as tmpdir:
        tmp_path = Path(tmpdir).resolve()
        db_path = tmp_path / "state.db"
        state_db = StateDB(db_path)

        # 1. Create a completed mission
        scope = MissionScope(
            target="src",
            allowed_paths=["src"],
            max_risk="scan",
        )
        mission = MissionRun(
            id="m_export_test",
            profile_id="secrets-audit",
            scope=scope,
            status=MissionStatus.COMPLETED,
            phase=MissionPhase.REPORT,
        )
        state_db.create_mission(mission)

        # 2. Record some tasks (including blocked and pending)
        task_completed = MissionTask(
            id="t_comp",
            mission_id="m_export_test",
            role_id="scanner",
            phase="scan",
            tool_name="redteam_secret_scan",
            toolset="redteam_secrets",
            target="src",
            description="Scan secrets",
            status=TaskStatus.COMPLETED,
        )
        task_blocked = MissionTask(
            id="t_block",
            mission_id="m_export_test",
            role_id="analyst",
            phase="report",
            tool_name=None,
            toolset="redteam_report",
            target="src",
            description="Report",
            status=TaskStatus.BLOCKED,
            block_reason="waiting",
        )
        state_db.record_mission_task(task_completed)
        state_db.record_mission_task(task_blocked)

        # 3. Record findings (validated and refuted with secret values)
        finding_validated = MissionFinding(
            id="f_val",
            mission_id="m_export_test",
            title="Hardcoded API Key secret=12345",
            severity=Severity.HIGH,
            state=FindingState.VALIDATED,
            affected_component="src/config.py",
            confidence=0.8,
            validator_note="Found supersecrettoken = \"xyz\"",
            recommendation="Change password immediately.",
            redacted="supersecrettoken = \"***REDACTED***\"",
        )
        finding_refuted = MissionFinding(
            id="f_ref",
            mission_id="m_export_test",
            title="Refuted key",
            severity=Severity.LOW,
            state=FindingState.REFUTED,
            affected_component="src/dummy.py",
            validator_note="False positive",
        )
        state_db.record_mission_finding(finding_validated)
        state_db.record_mission_finding(finding_refuted)

        # 4. Record operator runs and memory chunks
        session_id = state_db.create_session(prompt="test", target="src")
        state_db.record_mission_operator_run(
            mission_id="m_export_test",
            task_id="t_comp",
            role_id="scanner",
            session_id=session_id,
            status="completed",
        )
        state_db.add_memory_chunk(
            session_id=session_id,
            source_type="tool_call",
            source_id="redteam_secret_scan",
            target="src",
            tags=["recon"],
            content="api_key = 123456789abc",
        )

        # 5. Export mission traces
        out_path = tmp_path / "traces.jsonl"
        count = export_mission_traces(state_db, out_path)
        assert count == 1
        assert out_path.exists()

        # 6. Parse and assert on JSONL content
        lines = out_path.read_text(encoding="utf-8").strip().split("\n")
        assert len(lines) == 1
        
        record = json.loads(lines[0])
        assert record["type"] == "mission_trace"
        assert record["mission_id"] == "m_export_test"
        assert record["profile_id"] == "secrets-audit"
        
        # Verify blocked tasks are included
        task_ids = {t["id"] for t in record["tasks"]}
        assert "t_comp" in task_ids
        assert "t_block" in task_ids

        # Verify refuted findings are included
        finding_ids = {f["id"] for f in record["findings"]}
        assert "f_val" in finding_ids
        assert "f_ref" in finding_ids

        # Verify secrets are redacted in findings
        for f in record["findings"]:
            if f["id"] == "f_val":
                assert "12345" not in f["title"]
                assert "xyz" not in f["validator_note"]

        # Verify report summary contains redacted content
        assert "12345" not in record["report_summary"]
        assert "xyz" not in record["report_summary"]

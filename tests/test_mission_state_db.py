from __future__ import annotations

import tempfile
from pathlib import Path

from ares.state.db import StateDB, STATE_SCHEMA_VERSION
from ares.mission.model import MissionRun, MissionScope, MissionStatus, MissionPhase
from ares.mission.tasks import MissionTask, TaskStatus
from ares.mission.findings import MissionFinding, Severity, FindingState


def test_mission_state_db_crud():
    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = Path(tmpdir) / "test_state.db"
        db = StateDB(db_path)

        # 1. Schema version still works
        assert db.schema_version() == STATE_SCHEMA_VERSION

        # 2. Create mission
        scope = MissionScope(
            target="target_system",
            allowed_paths=["/path/to/target"],
            forbidden_paths=["/path/to/forbidden"],
            allowed_hosts=["192.168.1.1"],
            forbidden_actions=["read_env"],
            max_risk="scan",
        )
        mission = MissionRun(
            id="mission_1",
            profile_id="source-code-audit",
            scope=scope,
            status=MissionStatus.CREATED,
            phase=MissionPhase.PLAN,
            metadata={"source": "pytest"},
        )

        db.create_mission(mission)

        # 3. Get mission
        fetched = db.get_mission("mission_1")
        assert fetched is not None
        assert fetched["id"] == "mission_1"
        assert fetched["profile_id"] == "source-code-audit"
        assert fetched["target"] == "target_system"
        assert fetched["status"] == "created"
        assert fetched["phase"] == "plan"
        assert fetched["metadata"] == {"source": "pytest"}
        assert fetched["scope"] == {
            "target": "target_system",
            "allowed_paths": ["/path/to/target"],
            "forbidden_paths": ["/path/to/forbidden"],
            "allowed_hosts": ["192.168.1.1"],
            "forbidden_actions": ["read_env"],
            "max_risk": "scan",
        }

        # 4. List missions
        missions = db.list_missions()
        assert len(missions) == 1
        assert missions[0]["id"] == "mission_1"

        # Update mission status & phase
        db.update_mission_status("mission_1", "running", "scan")
        fetched = db.get_mission("mission_1")
        assert fetched["status"] == "running"
        assert fetched["phase"] == "scan"

        # Update status only
        db.update_mission_status("mission_1", "completed")
        fetched = db.get_mission("mission_1")
        assert fetched["status"] == "completed"
        assert fetched["phase"] == "scan"

        # 5. Record task
        task = MissionTask(
            id="task_1",
            mission_id="mission_1",
            role_id="scanner",
            phase="scan",
            tool_name="redteam_secret_scan",
            toolset="redteam_secrets",
            target="src",
            description="Scan source files",
            args={"root": "src"},
            depends_on=[],
            status=TaskStatus.PENDING,
            block_reason="",
        )
        db.record_mission_task(task)

        # 6. List tasks
        tasks = db.list_mission_tasks("mission_1")
        assert len(tasks) == 1
        assert tasks[0]["id"] == "task_1"
        assert tasks[0]["args"] == {"root": "src"}
        assert tasks[0]["depends_on"] == []
        assert tasks[0]["status"] == "pending"

        # 7. Update task status
        db.update_mission_task_status("task_1", "completed")
        tasks = db.list_mission_tasks("mission_1")
        assert tasks[0]["status"] == "completed"

        db.update_mission_task_status("task_1", "blocked", "Waiting for approval")
        tasks = db.list_mission_tasks("mission_1")
        assert tasks[0]["status"] == "blocked"
        assert tasks[0]["block_reason"] == "Waiting for approval"

        # 8. Record finding
        finding = MissionFinding(
            id="finding_1",
            mission_id="mission_1",
            title="API Key Exposure",
            severity=Severity.HIGH,
            state=FindingState.HYPOTHESIS,
            affected_component="config.py",
            evidence_chunk_ids=[10, 11],
            confidence=0.5,
            validator_note="",
            recommendation="Rotate key",
        )
        db.record_mission_finding(finding)

        # 9. List findings
        findings = db.list_mission_findings("mission_1")
        assert len(findings) == 1
        assert findings[0]["id"] == "finding_1"
        assert findings[0]["severity"] == "high"
        assert findings[0]["state"] == "hypothesis"
        assert findings[0]["evidence_chunk_ids"] == [10, 11]

        # Update finding to validated in memory first and record again
        finding.validator_note = "Valid"
        finding.confidence = 0.8
        finding.validate()
        db.record_mission_finding(finding)

        findings = db.list_mission_findings("mission_1")
        assert findings[0]["state"] == "validated"
        assert findings[0]["validator_note"] == "Valid"
        assert findings[0]["confidence"] == 0.8

        # 10. Record operator run
        run_id = db.record_mission_operator_run(
            mission_id="mission_1",
            task_id="task_1",
            role_id="scanner",
            session_id=None,
            status="started",
            summary="Started scanning files",
        )
        assert run_id > 0

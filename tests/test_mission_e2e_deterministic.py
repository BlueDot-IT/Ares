from __future__ import annotations

import tempfile
from pathlib import Path

from ares.tools.registry import ToolRegistry
from ares.state.db import StateDB
from ares.mission.model import MissionRun, MissionScope, MissionStatus, MissionPhase
from ares.mission.coordinator import MissionCoordinator
from ares.mission.tools import register_mission_tools


def test_e2e_deterministic_secrets_audit():
    with tempfile.TemporaryDirectory() as tmpdir:
        tmp_path = Path(tmpdir).resolve()
        
        # 1. Create a dummy file with a secret
        src_dir = tmp_path / "src"
        src_dir.mkdir()
        config_file = src_dir / "config.py"
        config_file.write_text("api_key = \"supersecretkey42\"\n", encoding="utf-8")

        # 2. Setup StateDB
        db_path = tmp_path / "state.db"
        state_db = StateDB(db_path)

        # 3. Setup ToolRegistry
        registry = ToolRegistry()
        register_mission_tools(registry)

        # 4. Setup Mission Run
        scope = MissionScope(
            target=str(src_dir),
            allowed_paths=[str(tmp_path)],
        )
        mission = MissionRun(
            id="m_e2e_test",
            profile_id="secrets-audit",
            scope=scope,
            status=MissionStatus.CREATED,
            phase=MissionPhase.PLAN,
        )

        coordinator = MissionCoordinator(mission)

        # 5. Run deterministic mission
        report = coordinator.run_deterministic(registry, state_db)

        # 6. Verify database records
        db_mission = state_db.get_mission("m_e2e_test")
        assert db_mission["status"] == "completed"

        db_tasks = state_db.list_mission_tasks("m_e2e_test")
        assert len(db_tasks) == 3
        statuses = {t["status"] for t in db_tasks}
        assert "completed" in statuses

        db_findings = state_db.list_mission_findings("m_e2e_test")
        assert len(db_findings) == 1
        assert db_findings[0]["state"] == "validated"
        assert db_findings[0]["confidence"] == 0.75
        assert db_findings[0]["validator_note"] == "Validated as scoped static evidence. Manual review still required."
        assert "supersecretkey42" not in db_findings[0]["redacted"]
        assert "***REDACTED***" in db_findings[0]["redacted"]

        # 7. Check rendered report
        assert "# ARES Mission Report" in report
        assert "api_key =" in report and "***REDACTED***" in report
        assert "Validated Findings" in report

from __future__ import annotations

import tempfile
from pathlib import Path

from ares.config.loader import load_config
from ares.state.db import StateDB
from ares.mission.model import MissionRun, MissionScope, MissionStatus, MissionPhase
from ares.mission.coordinator import MissionCoordinator


def test_mission_agentic_loop():
    with tempfile.TemporaryDirectory() as tmpdir:
        tmp_path = Path(tmpdir).resolve()
        
        # 1. Create a dummy file with a secret
        src_dir = tmp_path / "src"
        src_dir.mkdir()
        config_file = src_dir / "config.py"
        config_file.write_text("api_key = \"supersecretkey42\"\n", encoding="utf-8")

        # 2. Setup database
        db_path = tmp_path / "state.db"
        state_db = StateDB(db_path)

        # 3. Setup environment and config
        import os
        orig_home = os.environ.get("APP_HOME")
        os.environ["APP_HOME"] = str(tmp_path)

        try:
            config = load_config()
            
            # 4. Setup Mission Run
            scope = MissionScope(
                target=str(src_dir),
                allowed_paths=[str(tmp_path)],
            )
            mission = MissionRun(
                id="m_agentic_test",
                profile_id="secrets-audit",
                scope=scope,
                status=MissionStatus.CREATED,
                phase=MissionPhase.PLAN,
            )

            coordinator = MissionCoordinator(mission)

            # 5. Run agentic loop
            report = coordinator.run_agentic(config=config, state_db=state_db, max_tasks=10)

            # 6. Verify database records
            db_mission = state_db.get_mission("m_agentic_test")
            assert db_mission["status"] == "completed"

            db_tasks = state_db.list_mission_tasks("m_agentic_test")
            assert len(db_tasks) == 3
            statuses = {t["status"] for t in db_tasks}
            assert "completed" in statuses

            db_findings = state_db.list_mission_findings("m_agentic_test")
            assert len(db_findings) == 1
            assert db_findings[0]["state"] == "validated"

            # 7. Check rendered report
            assert "# ARES Mission Report" in report
            assert "api_key =" in report and "***REDACTED***" in report
            assert "Validated Findings" in report

        finally:
            if orig_home is not None:
                os.environ["APP_HOME"] = orig_home
            else:
                os.environ.pop("APP_HOME", None)

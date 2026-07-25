from __future__ import annotations

import tempfile
from pathlib import Path
from typer.testing import CliRunner

from ares.cli import app
from ares.state.db import StateDB

runner = CliRunner()


def test_mission_cli_workflow():
    with tempfile.TemporaryDirectory() as tmpdir:
        tmp_path = Path(tmpdir).resolve()
        
        # 1. Create dummy files
        src_dir = tmp_path / "src"
        src_dir.mkdir()
        config_file = src_dir / "config.py"
        config_file.write_text("api_key = \"mysecret\"\n", encoding="utf-8")

        # Set up environment home so load_config uses tmpdir
        import os
        orig_home = os.environ.get("APP_HOME")
        os.environ["APP_HOME"] = str(tmp_path)

        try:
            # Initialize database in tmp APP_HOME
            db = StateDB(tmp_path / "state.db")

            # 2. Test dry-run
            res_dry = runner.invoke(
                app,
                [
                    "mission-run",
                    "--profile", "secrets-audit",
                    "--target", str(src_dir),
                    "--dry-run",
                ]
            )
            assert res_dry.exit_code == 0
            assert "Planned Tasks:" in res_dry.stdout
            assert "secrets-audit" in res_dry.stdout

            # 3. Test real run
            report_out = tmp_path / "report.md"
            res_run = runner.invoke(
                app,
                [
                    "mission-run",
                    "--profile", "secrets-audit",
                    "--target", str(src_dir),
                    "--out", str(report_out),
                ]
            )
            assert res_run.exit_code == 0
            assert "Mission completed successfully." in res_run.stdout
            assert report_out.exists()

            # 4. Test mission-list
            res_list = runner.invoke(app, ["mission-list"])
            assert res_list.exit_code == 0
            assert "secrets-audit" in res_list.stdout

            # Extract mission ID from DB
            with db._connection() as conn:
                row = conn.execute("SELECT id FROM missions").fetchone()
            mission_id = row["id"]

            # 5. Test mission-report
            report_out2 = tmp_path / "report2.md"
            res_rep = runner.invoke(
                app,
                [
                    "mission-report",
                    mission_id,
                    "--out", str(report_out2),
                ]
            )
            assert res_rep.exit_code == 0
            assert report_out2.exists()
            assert "ARES Mission Report" in report_out2.read_text(encoding="utf-8")

            # 6. Test nested app subcommands: mission run, mission list, mission report
            report_out3 = tmp_path / "report3.md"
            res_run_sub = runner.invoke(
                app,
                [
                    "mission", "run",
                    "--profile", "secrets-audit",
                    "--target", str(src_dir),
                    "--out", str(report_out3),
                ]
            )
            assert res_run_sub.exit_code == 0
            assert "Mission completed successfully." in res_run_sub.stdout
            assert report_out3.exists()

            # Test mission list sub-typer
            res_list_sub = runner.invoke(app, ["mission", "list"])
            assert res_list_sub.exit_code == 0
            assert "secrets-audit" in res_list_sub.stdout

            # Test mission report sub-typer
            report_out4 = tmp_path / "report4.md"
            res_rep_sub = runner.invoke(
                app,
                [
                    "mission", "report",
                    mission_id,
                    "--out", str(report_out4),
                ]
            )
            assert res_rep_sub.exit_code == 0
            assert report_out4.exists()

        finally:
            if orig_home is not None:
                os.environ["APP_HOME"] = orig_home
            else:
                os.environ.pop("APP_HOME", None)

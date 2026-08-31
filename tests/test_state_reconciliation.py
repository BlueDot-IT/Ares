from __future__ import annotations

import json
import sqlite3
import tempfile
import unittest
from pathlib import Path

from typer.testing import CliRunner

from ares.cli import app
from ares.state.db import (
    MISSION_RECONCILIATION_SUMMARY,
    StateDB,
)


def _build_stale_state(path: Path, *, extra_run: bool = False) -> StateDB:
    db = StateDB(path)
    with db._connection() as conn:
        conn.executemany(
            """
            INSERT INTO sessions (
                id, created_at, prompt, target, status
            ) VALUES (?, ?, ?, ?, ?)
            """,
            [
                (117, 1.0, "unrelated", "example.test", "running"),
                (149, 2.0, "Deterministic mission run", "src", "running"),
            ],
        )
        conn.execute(
            """
            INSERT INTO missions (
                id, created_at, profile_id, target, scope_json,
                status, phase, metadata_json
            ) VALUES (
                'mission-complete', 2.0, 'secrets-audit', 'src', '{}',
                'completed', 'plan', '{}'
            )
            """
        )
        conn.executemany(
            """
            INSERT INTO mission_tasks (
                id, mission_id, created_at, role_id, phase, tool_name,
                toolset, target, description, args_json, depends_on_json,
                status, block_reason
            ) VALUES (?, 'mission-complete', 2.0, ?, 'scan', NULL,
                      'test', 'src', ?, '{}', '[]', 'completed', '')
            """,
            [
                ("task-one", "scanner", "First task"),
                ("task-two", "analyst", "Second task"),
            ],
        )
        conn.executemany(
            """
            INSERT INTO mission_operator_runs (
                id, mission_id, task_id, role_id, session_id,
                started_at, finished_at, status, summary
            ) VALUES (?, 'mission-complete', ?, ?, 149, ?, NULL,
                      'running', '')
            """,
            [
                (1, "task-one", "scanner", 3.0),
                (2, "task-two", "analyst", 4.0),
            ],
        )
        if extra_run:
            conn.execute(
                """
                INSERT INTO mission_operator_runs (
                    id, mission_id, task_id, role_id, session_id,
                    started_at, finished_at, status, summary
                ) VALUES (
                    3, 'mission-complete', 'task-two', 'analyst', 149,
                    5.0, NULL, 'running', ''
                )
                """
            )
    return db


class StateReconciliationTests(unittest.TestCase):
    def test_cli_preview_does_not_migrate_or_modify_schema_v3_state(self):
        with tempfile.TemporaryDirectory() as tmp:
            home = Path(tmp)
            path = home / "state.db"
            _build_stale_state(path)
            with sqlite3.connect(path) as conn:
                conn.execute(
                    "UPDATE ares_schema_meta SET value = '3' "
                    "WHERE key = 'schema_version'"
                )

            before = path.read_bytes()
            before_mtime = path.stat().st_mtime_ns
            result = CliRunner().invoke(
                app,
                [
                    "mission",
                    "reconcile-state",
                    "--run-id",
                    "1",
                    "--run-id",
                    "2",
                    "--session-id",
                    "149",
                ],
                env={"APP_HOME": str(home)},
            )

            self.assertEqual(result.exit_code, 0, result.output)
            self.assertEqual(path.read_bytes(), before)
            self.assertEqual(path.stat().st_mtime_ns, before_mtime)
            with sqlite3.connect(f"{path.resolve().as_uri()}?mode=ro", uri=True) as conn:
                self.assertEqual(
                    conn.execute(
                        "SELECT value FROM ares_schema_meta "
                        "WHERE key = 'schema_version'"
                    ).fetchone()[0],
                    "3",
                )

    def test_cli_preview_refuses_to_create_a_missing_database(self):
        with tempfile.TemporaryDirectory() as tmp:
            home = Path(tmp)
            path = home / "state.db"
            result = CliRunner().invoke(
                app,
                [
                    "mission",
                    "reconcile-state",
                    "--run-id",
                    "1",
                    "--session-id",
                    "149",
                ],
                env={"APP_HOME": str(home)},
            )

            self.assertEqual(result.exit_code, 1, result.output)
            self.assertIn("Reconciliation refused", result.output)
            self.assertFalse(path.exists())

    def test_preview_apply_and_repeat_are_guarded_and_idempotent(self):
        with tempfile.TemporaryDirectory() as tmp:
            db = _build_stale_state(Path(tmp) / "state.db")

            preview = db.reconcile_completed_mission_lifecycle(
                run_ids=(1, 2),
                session_ids=(149,),
            )
            self.assertFalse(preview["applied"])
            self.assertEqual(preview["stale_runs"], 2)
            self.assertEqual(preview["updated_runs"], 0)
            with db._connection() as conn:
                self.assertEqual(
                    conn.execute(
                        "SELECT status FROM sessions WHERE id = 149"
                    ).fetchone()["status"],
                    "running",
                )

            applied = db.reconcile_completed_mission_lifecycle(
                run_ids=(2, 1),
                session_ids=(149,),
                apply=True,
            )
            self.assertTrue(applied["applied"])
            self.assertEqual(applied["updated_runs"], 2)
            self.assertEqual(applied["updated_sessions"], 1)
            self.assertIsNotNone(applied["finished_at"])

            with db._connection() as conn:
                runs = conn.execute(
                    """
                    SELECT status, finished_at, summary
                    FROM mission_operator_runs
                    WHERE id IN (1, 2) ORDER BY id
                    """
                ).fetchall()
                self.assertEqual(
                    {row["status"] for row in runs},
                    {"completed"},
                )
                self.assertEqual(
                    len({row["finished_at"] for row in runs}),
                    1,
                )
                self.assertEqual(
                    {row["summary"] for row in runs},
                    {MISSION_RECONCILIATION_SUMMARY},
                )
                self.assertEqual(
                    conn.execute(
                        "SELECT status FROM sessions WHERE id = 149"
                    ).fetchone()["status"],
                    "completed",
                )
                self.assertEqual(
                    conn.execute(
                        "SELECT status FROM sessions WHERE id = 117"
                    ).fetchone()["status"],
                    "running",
                )

            repeated = db.reconcile_completed_mission_lifecycle(
                run_ids=(1, 2),
                session_ids=(149,),
                apply=True,
            )
            self.assertEqual(repeated["stale_runs"], 0)
            self.assertEqual(repeated["already_reconciled_runs"], 2)
            self.assertEqual(repeated["updated_runs"], 0)
            self.assertEqual(repeated["updated_sessions"], 0)

    def test_reconciliation_rejects_runs_outside_explicit_allowlist(self):
        with tempfile.TemporaryDirectory() as tmp:
            db = _build_stale_state(
                Path(tmp) / "state.db",
                extra_run=True,
            )

            with self.assertRaisesRegex(
                ValueError,
                "outside the explicit run allowlist",
            ):
                db.reconcile_completed_mission_lifecycle(
                    run_ids=(1, 2),
                    session_ids=(149,),
                    apply=True,
                )

            with db._connection() as conn:
                self.assertEqual(
                    conn.execute(
                        """
                        SELECT count(*) FROM mission_operator_runs
                        WHERE status = 'running' AND finished_at IS NULL
                        """
                    ).fetchone()[0],
                    3,
                )
                self.assertEqual(
                    conn.execute(
                        "SELECT status FROM sessions WHERE id = 149"
                    ).fetchone()["status"],
                    "running",
                )

    def test_cli_previews_then_applies_the_exact_allowlist(self):
        with tempfile.TemporaryDirectory() as tmp:
            home = Path(tmp)
            db = _build_stale_state(home / "state.db")
            runner = CliRunner()
            args = [
                "mission",
                "reconcile-state",
                "--run-id",
                "1",
                "--run-id",
                "2",
                "--session-id",
                "149",
            ]

            preview = runner.invoke(app, args, env={"APP_HOME": str(home)})
            self.assertEqual(preview.exit_code, 0, preview.output)
            preview_payload = json.loads(preview.output)
            self.assertFalse(preview_payload["applied"])
            self.assertIn("fresh backup", preview_payload["next_step"])

            applied = runner.invoke(
                app,
                [*args, "--apply"],
                env={"APP_HOME": str(home)},
            )
            self.assertEqual(applied.exit_code, 0, applied.output)
            applied_payload = json.loads(applied.output)
            self.assertEqual(applied_payload["updated_runs"], 2)
            self.assertEqual(applied_payload["updated_sessions"], 1)

            with db._connection() as conn:
                self.assertEqual(
                    conn.execute(
                        "SELECT status FROM sessions WHERE id = 117"
                    ).fetchone()["status"],
                    "running",
                )


if __name__ == "__main__":
    unittest.main()

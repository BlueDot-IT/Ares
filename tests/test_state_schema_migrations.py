import json
import sqlite3
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))


class StateSchemaMigrationTests(unittest.TestCase):
    def test_v2_mission_data_migrates_to_explicit_lifecycle(self):
        from ares.state.db import STATE_SCHEMA_VERSION, StateDB

        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "state.db"
            conn = sqlite3.connect(path)
            try:
                conn.executescript(
                    """
                    CREATE TABLE ares_schema_meta (
                        key TEXT PRIMARY KEY,
                        value TEXT NOT NULL
                    );
                    INSERT INTO ares_schema_meta VALUES ('schema_version', '2');
                    CREATE TABLE missions (
                        id TEXT PRIMARY KEY,
                        created_at REAL NOT NULL,
                        profile_id TEXT NOT NULL,
                        target TEXT NOT NULL,
                        scope_json TEXT NOT NULL,
                        status TEXT NOT NULL,
                        phase TEXT NOT NULL,
                        metadata_json TEXT NOT NULL DEFAULT '{}'
                    );
                    CREATE TABLE mission_tasks (
                        id TEXT PRIMARY KEY,
                        mission_id TEXT NOT NULL,
                        created_at REAL NOT NULL,
                        role_id TEXT NOT NULL,
                        phase TEXT NOT NULL,
                        tool_name TEXT,
                        toolset TEXT NOT NULL,
                        target TEXT NOT NULL,
                        description TEXT NOT NULL,
                        args_json TEXT NOT NULL DEFAULT '{}',
                        depends_on_json TEXT NOT NULL DEFAULT '[]',
                        status TEXT NOT NULL,
                        block_reason TEXT
                    );
                    CREATE TABLE mission_findings (
                        id TEXT PRIMARY KEY,
                        mission_id TEXT NOT NULL,
                        title TEXT NOT NULL,
                        severity TEXT NOT NULL,
                        state TEXT NOT NULL,
                        affected_component TEXT,
                        evidence_chunk_ids_json TEXT NOT NULL DEFAULT '[]',
                        confidence REAL NOT NULL DEFAULT 0,
                        validator_note TEXT,
                        recommendation TEXT,
                        redacted TEXT
                    );
                    INSERT INTO missions VALUES (
                        'legacy-mission', 1.0, 'secrets-audit', 'src',
                        '{}', 'completed', 'report', '{}'
                    );
                    INSERT INTO mission_tasks VALUES (
                        'legacy-task', 'legacy-mission', 2.0, 'scanner',
                        'scan', 'redteam_secret_scan', 'redteam_secrets',
                        'src', 'Legacy task', '{}', '[]', 'completed', ''
                    );
                    INSERT INTO mission_findings VALUES (
                        'legacy-finding', 'legacy-mission', 'Legacy finding',
                        'high', 'validated', 'src/app.py', '[9]', 0.8,
                        'old validation', 'rotate', 'redacted'
                    );
                    INSERT INTO mission_findings VALUES (
                        'legacy-reported', 'legacy-mission', 'Legacy report',
                        'medium', 'reported', 'src/old.py', '[10]', 0.8,
                        'old report', 'review', 'redacted'
                    );
                    """
                )
                conn.commit()
            finally:
                conn.close()

            db = StateDB(path)
            self.assertEqual(db.schema_version(), STATE_SCHEMA_VERSION)
            task = db.list_mission_tasks("legacy-mission")[0]
            self.assertEqual(task["supporting_evidence_tool_call_ids"], [])
            self.assertEqual(task["approval_receipt_id"], "")
            findings = {
                row["id"]: row
                for row in db.list_mission_findings("legacy-mission")
            }
            finding = findings["legacy-finding"]
            self.assertEqual(finding["state"], "hypothesized")
            self.assertEqual(finding["evidence_tool_call_ids"], [])
            self.assertEqual(finding["contradiction_resolution"], "")
            self.assertEqual(
                findings["legacy-reported"]["state"],
                "hypothesized",
            )
            with db._connection() as check:
                tables = {
                    row["name"]
                    for row in check.execute(
                        "SELECT name FROM sqlite_master WHERE type = 'table'"
                    )
                }
            self.assertIn("mission_recovery_attempts", tables)
            self.assertIn("mission_approval_receipts", tables)

    def test_legacy_beta_database_is_upgraded_without_losing_data(self):
        from ares.state.db import STATE_SCHEMA_VERSION, StateDB

        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "state.db"
            conn = sqlite3.connect(path)
            try:
                conn.execute(
                    """
                    CREATE TABLE sessions (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        created_at REAL NOT NULL,
                        prompt TEXT NOT NULL,
                        target TEXT,
                        status TEXT NOT NULL DEFAULT 'running'
                    )
                    """
                )
                conn.execute(
                    """
                    CREATE TABLE tool_calls (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        session_id INTEGER NOT NULL,
                        created_at REAL NOT NULL,
                        tool TEXT NOT NULL,
                        args_json TEXT NOT NULL,
                        status TEXT NOT NULL,
                        result_json TEXT,
                        error TEXT
                    )
                    """
                )
                conn.execute(
                    "INSERT INTO sessions (created_at, prompt, target, status) VALUES (1.0, 'legacy prompt', '127.0.0.1', 'running')"
                )
                conn.execute(
                    """
                    INSERT INTO tool_calls (session_id, created_at, tool, args_json, status, result_json, error)
                    VALUES (1, 2.0, 'legacy.tool', '{}', 'ok', '{"summary": "kept"}', NULL)
                    """
                )
                conn.commit()
            finally:
                conn.close()

            db = StateDB(path)

            self.assertEqual(db.schema_version(), STATE_SCHEMA_VERSION)
            sessions = db.list_sessions()
            self.assertEqual(len(sessions), 1)
            self.assertEqual(sessions[0]["prompt"], "legacy prompt")
            self.assertIn("agent", sessions[0])
            self.assertIn("model", sessions[0])
            self.assertIn("mode", sessions[0])

            calls = db.list_tool_calls(1)
            self.assertEqual(len(calls), 1)
            self.assertEqual(calls[0]["tool"], "legacy.tool")
            self.assertIn("duration_ms", calls[0])
            self.assertEqual(calls[0]["duration_ms"], 0)
            with db._connection() as conn:
                table_names = {
                    row["name"]
                    for row in conn.execute(
                        """
                        SELECT name FROM sqlite_master
                        WHERE type = 'table'
                        """
                    ).fetchall()
                }
            self.assertIn("attack_surface_nodes", table_names)
            self.assertIn("attack_surface_edges", table_names)
            self.assertIn("mission_coverage", table_names)
            self.assertIn("mission_planner_cycles", table_names)

            new_session_id = db.create_session(prompt="new prompt", target="127.0.0.1", agent="default", model="unit", mode="safe-active")
            call_id = db.record_tool_call(
                session_id=new_session_id,
                tool="unit.tool",
                args={"target": "127.0.0.1"},
                status="ok",
                result={"summary": "new"},
                duration_ms=5,
            )
            self.assertGreater(call_id, 0)

    def test_memory_fts_is_rebuilt_for_existing_rows(self):
        from ares.state.db import StateDB

        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "state.db"
            conn = sqlite3.connect(path)
            try:
                conn.execute(
                    """
                    CREATE TABLE memory_chunks (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        session_id INTEGER,
                        source_type TEXT NOT NULL,
                        source_id TEXT,
                        target TEXT,
                        tags_json TEXT NOT NULL DEFAULT '[]',
                        content TEXT NOT NULL,
                        created_at REAL NOT NULL
                    )
                    """
                )
                conn.execute(
                    """
                    INSERT INTO memory_chunks (session_id, source_type, source_id, target, tags_json, content, created_at)
                    VALUES (NULL, 'manual', 'note', '127.0.0.1', ?, 'legacy memory marker', 1.0)
                    """,
                    (json.dumps(["manual"]),),
                )
                conn.commit()
            finally:
                conn.close()

            db = StateDB(path)
            results = db.search_memory_chunks(query="legacy", target="127.0.0.1", limit=5)

            self.assertEqual(len(results), 1)
            self.assertEqual(results[0]["source_type"], "manual")
            self.assertIn("manual", results[0]["tags"])


if __name__ == "__main__":
    unittest.main()

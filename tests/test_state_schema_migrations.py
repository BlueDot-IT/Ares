import json
import sqlite3
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))


class StateSchemaMigrationTests(unittest.TestCase):
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

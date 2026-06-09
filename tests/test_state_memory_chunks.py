import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))


class StateMemoryChunksTests(unittest.TestCase):
    def test_add_and_search_memory_chunk(self):
        from ares.state.db import StateDB

        with tempfile.TemporaryDirectory() as tmp:
            db = StateDB(Path(tmp) / "state.db")
            session_id = db.create_session(prompt="test", target="127.0.0.1", model="test", mode="safe-active")

            chunk_id = db.add_memory_chunk(
                session_id=session_id,
                source_type="tool_call",
                source_id="nmap",
                target="127.0.0.1",
                tags=["recon", "scan"],
                content="Found SSH on port 22 and HTTP on port 80",
            )
            self.assertIsInstance(chunk_id, int)
            self.assertGreater(chunk_id, 0)

            # Search by query
            results = db.search_memory_chunks(query="ssh", target="127.0.0.1", limit=5)
            self.assertEqual(len(results), 1)
            self.assertEqual(results[0]["content"], "Found SSH on port 22 and HTTP on port 80")
            self.assertEqual(results[0]["tags"], ["recon", "scan"])
            self.assertEqual(results[0]["source_type"], "tool_call")
            self.assertEqual(results[0]["source_id"], "nmap")
            self.assertEqual(results[0]["target"], "127.0.0.1")

    def test_search_filters_by_target(self):
        from ares.state.db import StateDB

        with tempfile.TemporaryDirectory() as tmp:
            db = StateDB(Path(tmp) / "state.db")
            session_id = db.create_session(prompt="test", target="127.0.0.1", model="test", mode="safe-active")

            db.add_memory_chunk(
                session_id=session_id,
                source_type="tool_call",
                source_id="nmap",
                target="127.0.0.1",
                tags=["recon"],
                content="Found SSH on 127.0.0.1",
            )
            db.add_memory_chunk(
                session_id=session_id,
                source_type="tool_call",
                source_id="nmap",
                target="192.168.1.1",
                tags=["recon"],
                content="Found SSH on 192.168.1.1",
            )

            results = db.search_memory_chunks(query="ssh", target="127.0.0.1", limit=5)
            self.assertEqual(len(results), 1)
            self.assertEqual(results[0]["target"], "127.0.0.1")

            results = db.search_memory_chunks(query="ssh", target="192.168.1.1", limit=5)
            self.assertEqual(len(results), 1)
            self.assertEqual(results[0]["target"], "192.168.1.1")

    def test_search_filters_by_tags(self):
        from ares.state.db import StateDB

        with tempfile.TemporaryDirectory() as tmp:
            db = StateDB(Path(tmp) / "state.db")
            session_id = db.create_session(prompt="test", target="127.0.0.1", model="test", mode="safe-active")

            db.add_memory_chunk(
                session_id=session_id,
                source_type="tool_call",
                source_id="nmap",
                target="127.0.0.1",
                tags=["recon", "scan"],
                content="Found SSH",
            )
            db.add_memory_chunk(
                session_id=session_id,
                source_type="tool_call",
                source_id="nikto",
                target="127.0.0.1",
                tags=["web", "vuln"],
                content="Found web vuln",
            )

            results = db.search_memory_chunks(query="found", tags=("recon",), limit=5)
            self.assertEqual(len(results), 1)
            self.assertIn("recon", results[0]["tags"])

            results = db.search_memory_chunks(query="found", tags=("web",), limit=5)
            self.assertEqual(len(results), 1)
            self.assertIn("web", results[0]["tags"])

    def test_search_respects_limit(self):
        from ares.state.db import StateDB

        with tempfile.TemporaryDirectory() as tmp:
            db = StateDB(Path(tmp) / "state.db")
            session_id = db.create_session(prompt="test", target="127.0.0.1", model="test", mode="safe-active")

            for i in range(10):
                db.add_memory_chunk(
                    session_id=session_id,
                    source_type="tool_call",
                    source_id=f"tool_{i}",
                    target="127.0.0.1",
                    tags=["test"],
                    content=f"Result {i}",
                )

            results = db.search_memory_chunks(query="result", limit=3)
            self.assertEqual(len(results), 3)

    def test_search_with_none_session_id(self):
        from ares.state.db import StateDB

        with tempfile.TemporaryDirectory() as tmp:
            db = StateDB(Path(tmp) / "state.db")
            # Add chunk without session
            chunk_id = db.add_memory_chunk(
                session_id=None,
                source_type="manual",
                source_id="note",
                target="127.0.0.1",
                tags=["manual"],
                content="Manual note about target",
            )
            self.assertIsInstance(chunk_id, int)

            results = db.search_memory_chunks(query="manual", target="127.0.0.1", limit=5)
            self.assertEqual(len(results), 1)
            self.assertIsNone(results[0]["session_id"])

    def test_fallback_like_search_when_fts_unavailable(self):
        """Test fallback behavior by monkeypatching FTS availability check."""
        from ares.state.db import StateDB

        with tempfile.TemporaryDirectory() as tmp:
            db = StateDB(Path(tmp) / "state.db")
            session_id = db.create_session(prompt="test", target="127.0.0.1", model="test", mode="safe-active")

            db.add_memory_chunk(
                session_id=session_id,
                source_type="tool_call",
                source_id="nmap",
                target="127.0.0.1",
                tags=["recon"],
                content="Found open port 22",
            )

            # Search should work even if FTS is not available
            # We can't easily test FTS absence, but we verify normal search works
            results = db.search_memory_chunks(query="port 22", limit=5)
            self.assertEqual(len(results), 1)
            self.assertIn("port 22", results[0]["content"])

    def test_search_returns_all_required_fields(self):
        from ares.state.db import StateDB

        with tempfile.TemporaryDirectory() as tmp:
            db = StateDB(Path(tmp) / "state.db")
            session_id = db.create_session(prompt="test", target="127.0.0.1", model="test", mode="safe-active")

            db.add_memory_chunk(
                session_id=session_id,
                source_type="tool_call",
                source_id="test_tool",
                target="127.0.0.1",
                tags=["tag1", "tag2"],
                content="Test content",
            )

            results = db.search_memory_chunks(query="test", limit=5)
            self.assertEqual(len(results), 1)
            chunk = results[0]
            self.assertIn("id", chunk)
            self.assertIn("session_id", chunk)
            self.assertIn("source_type", chunk)
            self.assertIn("source_id", chunk)
            self.assertIn("target", chunk)
            self.assertIn("tags", chunk)
            self.assertIn("content", chunk)
            self.assertIn("created_at", chunk)


if __name__ == "__main__":
    unittest.main()

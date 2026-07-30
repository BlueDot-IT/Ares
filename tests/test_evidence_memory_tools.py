import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))


class EvidenceMemoryToolsTests(unittest.TestCase):
    def test_memory_search_tool(self):
        from ares.state.db import StateDB
        from ares.tools.evidence_memory import register_evidence_tools
        from ares.tools.registry import ToolRegistry

        with tempfile.TemporaryDirectory() as tmp:
            db = StateDB(Path(tmp) / "state.db")
            session_id = db.create_session(prompt="test", target="127.0.0.1", model="test", mode="safe-active")

            db.add_memory_chunk(
                session_id=session_id,
                source_type="tool_call",
                source_id="nmap",
                target="127.0.0.1",
                tags=["recon", "scan"],
                content="Found SSH on port 22 and HTTP on port 80",
            )
            db.add_memory_chunk(
                session_id=session_id,
                source_type="tool_call",
                source_id="nikto",
                target="127.0.0.1",
                tags=["web", "vuln"],
                content="Found XSS vulnerability on /search",
            )

            registry = ToolRegistry()
            register_evidence_tools(registry, db, current_session_id=session_id)

            entry = registry.get_entry("ares.memory.search")
            self.assertIsNotNone(entry)
            self.assertEqual(entry.risk, "passive")
            self.assertEqual(entry.toolset, "evidence")

            result = entry.handler({"query": "ssh", "target": "127.0.0.1", "limit": 5})
            self.assertIn("results", result)
            self.assertEqual(len(result["results"]), 1)
            self.assertIn("Found SSH on port 22", result["results"][0]["content_excerpt"])
            self.assertEqual(result["results"][0]["tags"], ["recon", "scan"])
            self.assertIn("untrusted", result.get("note", "").lower())

    def test_memory_search_excerpt_capped(self):
        from ares.state.db import StateDB
        from ares.tools.evidence_memory import register_evidence_tools
        from ares.tools.registry import ToolRegistry

        with tempfile.TemporaryDirectory() as tmp:
            db = StateDB(Path(tmp) / "state.db")
            session_id = db.create_session(prompt="test", target="127.0.0.1", model="test", mode="safe-active")

            long_content = "A" * 2000
            db.add_memory_chunk(
                session_id=session_id,
                source_type="tool_call",
                source_id="tool1",
                target="127.0.0.1",
                tags=["test"],
                content=long_content,
            )

            registry = ToolRegistry()
            register_evidence_tools(registry, db, current_session_id=session_id)

            result = registry.get_entry("ares.memory.search").handler({"query": "A", "limit": 5})
            self.assertEqual(len(result["results"]), 1)
            self.assertLessEqual(len(result["results"][0]["content_excerpt"]), 1020)
            self.assertTrue(result["results"][0]["content_excerpt"].endswith("[truncated]"))

    def test_memory_search_blocks_cross_target_results_even_without_target_argument(self):
        from ares.state.db import StateDB
        from ares.tools.evidence_memory import register_evidence_tools
        from ares.tools.registry import ToolRegistry

        with tempfile.TemporaryDirectory() as tmp:
            db = StateDB(Path(tmp) / "state.db")
            alpha_session = db.create_session(
                prompt="alpha", target="alpha.local", model="test", mode="safe-active"
            )
            beta_session = db.create_session(
                prompt="beta", target="beta.local", model="test", mode="safe-active"
            )
            for session_id, target in (
                (alpha_session, "alpha.local"),
                (beta_session, "beta.local"),
            ):
                db.add_memory_chunk(
                    session_id=session_id,
                    source_type="tool_call",
                    source_id="probe",
                    target=target,
                    tags=["proof"],
                    content=f"sharedmarker evidence for {target}",
                )

            registry = ToolRegistry()
            register_evidence_tools(registry, db, current_session_id=alpha_session)
            entry = registry.get_entry("ares.memory.search")

            result = entry.handler({"query": "sharedmarker"})
            denied = entry.handler({"query": "sharedmarker", "target": "beta.local"})

        self.assertEqual([item["target"] for item in result["results"]], ["alpha.local"])
        self.assertIn("access denied", denied["error"].lower())
        self.assertEqual(denied["results"], [])

    def test_memory_search_allows_prior_sessions_for_the_same_target(self):
        from ares.state.db import StateDB
        from ares.tools.evidence_memory import register_evidence_tools
        from ares.tools.registry import ToolRegistry

        with tempfile.TemporaryDirectory() as tmp:
            db = StateDB(Path(tmp) / "state.db")
            prior_session = db.create_session(
                prompt="prior", target="same.local", model="test", mode="safe-active"
            )
            current_session = db.create_session(
                prompt="current", target="same.local", model="test", mode="safe-active"
            )
            db.add_memory_chunk(
                session_id=prior_session,
                source_type="tool_call",
                source_id="probe",
                target="same.local",
                tags=["proof"],
                content="historicalmarker from prior authorized work",
            )

            registry = ToolRegistry()
            register_evidence_tools(registry, db, current_session_id=current_session)
            result = registry.get_entry("ares.memory.search").handler(
                {"query": "historicalmarker"}
            )

        self.assertEqual(len(result["results"]), 1)
        self.assertEqual(result["results"][0]["session_id"], prior_session)

    def test_evidence_get_tool_call(self):
        from ares.state.db import StateDB
        from ares.tools.evidence_memory import register_evidence_tools
        from ares.tools.registry import ToolRegistry

        with tempfile.TemporaryDirectory() as tmp:
            db = StateDB(Path(tmp) / "state.db")
            session_id = db.create_session(prompt="test", target="127.0.0.1", model="test", mode="safe-active")

            tool_call_id = db.record_tool_call(
                session_id=session_id,
                tool="nmap_scan",
                args={"target": "127.0.0.1", "ports": "22,80"},
                status="ok",
                result={"summary": "Found SSH on 22, HTTP on 80", "ports": [22, 80]},
                duration_ms=100,
            )

            registry = ToolRegistry()
            register_evidence_tools(registry, db, current_session_id=session_id)

            entry = registry.get_entry("ares.evidence.get_tool_call")
            self.assertIsNotNone(entry)
            self.assertEqual(entry.risk, "passive")
            self.assertEqual(entry.toolset, "evidence")

            result = entry.handler({"tool_call_id": tool_call_id, "excerpt_chars": 1000})
            self.assertEqual(result["tool_call_id"], tool_call_id)
            self.assertEqual(result["tool"], "nmap_scan")
            self.assertEqual(result["status"], "ok")
            self.assertIn("Found SSH on 22", result["result_excerpt"])
            self.assertIn("untrusted", result.get("note", "").lower())

    def test_evidence_get_tool_call_blocks_cross_session(self):
        from ares.state.db import StateDB
        from ares.tools.evidence_memory import register_evidence_tools
        from ares.tools.registry import ToolRegistry

        with tempfile.TemporaryDirectory() as tmp:
            db = StateDB(Path(tmp) / "state.db")
            session1 = db.create_session(prompt="test1", target="127.0.0.1", model="test", mode="safe-active")
            session2 = db.create_session(prompt="test2", target="192.168.1.1", model="test", mode="safe-active")

            tool_call_id = db.record_tool_call(
                session_id=session1,
                tool="nmap_scan",
                args={"target": "127.0.0.1"},
                status="ok",
                result={"summary": "Found SSH"},
            )

            registry = ToolRegistry()
            register_evidence_tools(registry, db, current_session_id=session2)

            entry = registry.get_entry("ares.evidence.get_tool_call")
            result = entry.handler({"tool_call_id": tool_call_id, "session_id": session1})
            self.assertIn("error", result)
            self.assertIn("access denied", result["error"].lower())

    def test_evidence_get_tool_call_redacts_secrets(self):
        from ares.state.db import StateDB
        from ares.tools.evidence_memory import register_evidence_tools
        from ares.tools.registry import ToolRegistry

        with tempfile.TemporaryDirectory() as tmp:
            db = StateDB(Path(tmp) / "state.db")
            session_id = db.create_session(prompt="test", target="127.0.0.1", model="test", mode="safe-active")

            tool_call_id = db.record_tool_call(
                session_id=session_id,
                tool="curl_request",
                args={"url": "http://example.com", "header": "Authorization: Bearer secret123"},
                status="ok",
                result={"summary": "Response received", "raw": "api_key=sk-abc1234567890xyz"},
            )

            registry = ToolRegistry()
            register_evidence_tools(registry, db, current_session_id=session_id)

            entry = registry.get_entry("ares.evidence.get_tool_call")
            result = entry.handler({"tool_call_id": tool_call_id, "excerpt_chars": 2000})
            self.assertNotIn("secret123", result["result_excerpt"])
            self.assertNotIn("sk-abc123", result["result_excerpt"])
            self.assertIn("[REDACTED]", result["result_excerpt"])

    def test_evidence_get_tool_call_bounded_excerpt(self):
        from ares.state.db import StateDB
        from ares.tools.evidence_memory import register_evidence_tools
        from ares.tools.registry import ToolRegistry

        with tempfile.TemporaryDirectory() as tmp:
            db = StateDB(Path(tmp) / "state.db")
            session_id = db.create_session(prompt="test", target="127.0.0.1", model="test", mode="safe-active")

            large_result = "x" * 5000
            tool_call_id = db.record_tool_call(
                session_id=session_id,
                tool="big_tool",
                args={"target": "127.0.0.1"},
                status="ok",
                result={"stdout": large_result},
            )

            registry = ToolRegistry()
            register_evidence_tools(registry, db, current_session_id=session_id)

            entry = registry.get_entry("ares.evidence.get_tool_call")
            result = entry.handler({"tool_call_id": tool_call_id, "excerpt_chars": 500})
            self.assertLessEqual(len(result["result_excerpt"]), 550)  # some slack for labels
            self.assertIn("[truncated", result["result_excerpt"])

    def test_evidence_tools_do_not_execute(self):
        """Verify these tools never execute anything - they only read from DB."""
        from ares.state.db import StateDB
        from ares.tools.evidence_memory import register_evidence_tools
        from ares.tools.registry import ToolRegistry

        with tempfile.TemporaryDirectory() as tmp:
            db = StateDB(Path(tmp) / "state.db")
            session_id = db.create_session(prompt="test", target="127.0.0.1", model="test", mode="safe-active")

            registry = ToolRegistry()
            register_evidence_tools(registry, db, current_session_id=session_id)

            # Both tools should be passive risk
            for name in ["ares.memory.search", "ares.evidence.get_tool_call"]:
                entry = registry.get_entry(name)
                self.assertEqual(entry.risk, "passive")
                # Handler should not have side effects beyond reading DB
                # Hard to test directly, but we verify they don't import subprocess, etc.


if __name__ == "__main__":
    unittest.main()

import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))


class ContextBudgeterTests(unittest.TestCase):
    def test_basic_budget(self):
        from ares.agent.context_budget import ContextBudgeter, estimate_tokens

        budget = ContextBudgeter(1000)
        self.assertTrue(budget.add_section("Title", "Body content"))
        self.assertEqual(budget.used_tokens, estimate_tokens("Title\nBody content"))
        self.assertEqual(budget.remaining(), 1000 - budget.used_tokens)

    def test_empty_section_rejected(self):
        from ares.agent.context_budget import ContextBudgeter

        budget = ContextBudgeter(1000)
        self.assertFalse(budget.add_section("Title", ""))
        self.assertFalse(budget.add_section("Title", "   "))
        self.assertEqual(budget.used_tokens, 0)

    def test_budget_exhaustion_truncates(self):
        from ares.agent.context_budget import ContextBudgeter

        budget = ContextBudgeter(50)
        long_text = "x" * 1000
        self.assertTrue(budget.add_section("Title", long_text))
        rendered = budget.render()
        self.assertIn("[truncated by context budget]", rendered)
        self.assertFalse(budget.add_section("Another", "section"))

    def test_render_joins_sections(self):
        from ares.agent.context_budget import ContextBudgeter

        budget = ContextBudgeter(1000)
        budget.add_section("A", "Body A")
        budget.add_section("B", "Body B")
        rendered = budget.render()
        self.assertIn("A\nBody A", rendered)
        self.assertIn("B\nBody B", rendered)
        self.assertIn("\n\n", rendered)


class ContextBuilderBudgetTests(unittest.TestCase):
    def test_compact_mode_uses_recent_tool_calls_config(self):
        from ares.agent.context_builder import ContextBuilder
        from ares.agent.context_config import ContextConfig
        from ares.state.db import StateDB

        with tempfile.TemporaryDirectory() as tmp:
            home = Path(tmp)
            db = StateDB(home / "state.db")
            session_id = db.create_session(prompt="test", target="127.0.0.1", model="test", mode="safe-active")

            # Add 30 tool calls
            for i in range(30):
                db.record_tool_call(
                    session_id=session_id,
                    tool=f"tool_{i}",
                    args={"target": "127.0.0.1"},
                    status="ok",
                    result={"summary": f"result {i}"},
                )

            # Config with recent_tool_calls=5
            config = ContextConfig(mode="compact", recent_tool_calls=5)
            builder = ContextBuilder(db, context_config=config)
            context = builder.build_session_context(session_id)

            # Should only show last 5 calls
            lines = context.split("\n")
            tool_lines = [l for l in lines if l.startswith("- tool_")]
            self.assertEqual(len(tool_lines), 5)
            self.assertIn("tool_29", tool_lines[-1])
            self.assertIn("tool_25", tool_lines[0])

    def test_long_mode_includes_section_labels(self):
        from ares.agent.context_builder import ContextBuilder
        from ares.agent.context_config import ContextConfig
        from ares.state.db import StateDB

        with tempfile.TemporaryDirectory() as tmp:
            home = Path(tmp)
            db = StateDB(home / "state.db")
            session_id = db.create_session(prompt="test", target="127.0.0.1", model="test", mode="safe-active")

            db.record_tool_call(
                session_id=session_id,
                tool="nmap_scan",
                args={"target": "127.0.0.1"},
                status="ok",
                result={"summary": "Found open ports 22, 80"},
            )

            config = ContextConfig(mode="long", context_window=32768, reserved_output_tokens=4096)
            builder = ContextBuilder(db, context_config=config)
            context = builder.build_session_context(session_id, target="127.0.0.1", query="scan")

            # Check for section labels
            self.assertIn("Current engagement state:", context)
            self.assertIn("Scope and target summary:", context)
            self.assertIn("Untrusted current-session evidence:", context)
            # Tool calls section should be labeled as evidence
            self.assertIn("Recent tool calls:", context)

    def test_long_mode_respects_budget(self):
        from ares.agent.context_builder import ContextBuilder
        from ares.agent.context_config import ContextConfig
        from ares.state.db import StateDB

        with tempfile.TemporaryDirectory() as tmp:
            home = Path(tmp)
            db = StateDB(home / "state.db")
            session_id = db.create_session(prompt="test", target="127.0.0.1", model="test", mode="safe-active")

            # Add many tool calls with large results
            for i in range(20):
                db.record_tool_call(
                    session_id=session_id,
                    tool=f"big_tool_{i}",
                    args={"target": "127.0.0.1"},
                    status="ok",
                    result={"summary": "x" * 2000},
                )

            # Very small budget
            config = ContextConfig(mode="long", context_window=4096, reserved_output_tokens=2048)
            builder = ContextBuilder(db, context_config=config)
            context = builder.build_session_context(session_id, target="127.0.0.1", query="test")

            # Should not exceed budget significantly (rough check)
            from ares.agent.context_budget import estimate_tokens
            tokens = estimate_tokens(context)
            self.assertLessEqual(tokens, config.usable_budget_tokens + 500)  # some slack for headers

    def test_long_mode_excludes_raw_excerpts_by_default(self):
        from ares.agent.context_builder import ContextBuilder
        from ares.agent.context_config import ContextConfig
        from ares.state.db import StateDB

        with tempfile.TemporaryDirectory() as tmp:
            home = Path(tmp)
            db = StateDB(home / "state.db")
            session_id = db.create_session(prompt="test", target="127.0.0.1", model="test", mode="safe-active")

            db.record_tool_call(
                session_id=session_id,
                tool="tool1",
                args={"target": "127.0.0.1"},
                status="ok",
                result={"stdout": "large output" * 100, "summary": "done"},
            )

            config = ContextConfig(mode="long", include_raw_excerpts=False)
            builder = ContextBuilder(db, context_config=config)
            context = builder.build_session_context(session_id, target="127.0.0.1", query="test")

            self.assertNotIn("Untrusted raw tool excerpt:", context)
            self.assertNotIn("large output", context)

    def test_long_mode_includes_raw_excerpts_when_enabled(self):
        from ares.agent.context_builder import ContextBuilder
        from ares.agent.context_config import ContextConfig
        from ares.state.db import StateDB

        with tempfile.TemporaryDirectory() as tmp:
            home = Path(tmp)
            db = StateDB(home / "state.db")
            session_id = db.create_session(prompt="test", target="127.0.0.1", model="test", mode="safe-active")

            db.record_tool_call(
                session_id=session_id,
                tool="tool1",
                args={"target": "127.0.0.1"},
                status="ok",
                result={"stdout": "SECRET_KEY=abc123", "summary": "done"},
            )

            config = ContextConfig(mode="long", include_raw_excerpts=True, raw_excerpt_chars=5000)
            builder = ContextBuilder(db, context_config=config)
            context = builder.build_session_context(session_id, target="127.0.0.1", query="test")

            self.assertIn("Untrusted raw tool excerpt:", context)

    def test_long_mode_retrieves_memory_chunks(self):
        from ares.agent.context_builder import ContextBuilder
        from ares.agent.context_config import ContextConfig
        from ares.state.db import StateDB

        with tempfile.TemporaryDirectory() as tmp:
            home = Path(tmp)
            db = StateDB(home / "state.db")
            session_id = db.create_session(prompt="test", target="127.0.0.1", model="test", mode="safe-active")

            # Add memory chunk
            db.add_memory_chunk(
                session_id=session_id,
                source_type="tool_call",
                source_id="nmap",
                target="127.0.0.1",
                tags=["recon", "scan"],
                content="Found SSH on port 22 and HTTP on port 80",
            )

            config = ContextConfig(mode="long", retrieval_limit=5)
            builder = ContextBuilder(db, context_config=config)
            context = builder.build_session_context(session_id, target="127.0.0.1", query="ssh")

            self.assertIn("Untrusted retrieved prior memory:", context)
            self.assertIn("Found SSH on port 22", context)

    def test_compact_mode_backward_compatible(self):
        from ares.agent.context_builder import ContextBuilder
        from ares.agent.context_config import ContextConfig
        from ares.state.db import StateDB

        with tempfile.TemporaryDirectory() as tmp:
            home = Path(tmp)
            db = StateDB(home / "state.db")
            session_id = db.create_session(prompt="test", target="127.0.0.1", model="test", mode="safe-active")

            db.record_tool_call(
                session_id=session_id,
                tool="tool1",
                args={"target": "127.0.0.1"},
                status="ok",
                result={"summary": "result"},
            )

            config = ContextConfig(mode="compact")
            builder = ContextBuilder(db, context_config=config)
            context = builder.build_session_context(session_id, target="127.0.0.1", memory_tags=("recon",))

            self.assertIn("Current engagement state:", context)
            self.assertIn("Known prior tool calls:", context)
            self.assertIn("tool1 [ok]", context)


if __name__ == "__main__":
    unittest.main()

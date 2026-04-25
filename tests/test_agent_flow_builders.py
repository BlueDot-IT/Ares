import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))


class PromptBuilderTests(unittest.TestCase):
    def test_system_prompt_contains_scope_policy_and_termination_rules(self):
        from ares.agent.prompt_builder import PromptBuilder
        from ares.policy.context import PolicyContext

        prompt = PromptBuilder().build_system_prompt(
            target="127.0.0.1",
            policy=PolicyContext(max_risk="active", allow_private_only=True),
            playbooks=["1. Start passive, then active."],
        )

        self.assertIn("authorized penetration testing agent", prompt)
        self.assertIn("Target: 127.0.0.1", prompt)
        self.assertIn("max_risk: active", prompt)
        self.assertIn("Never act outside scope", prompt)
        self.assertIn("Use tools instead of guessing", prompt)
        self.assertIn("Terminate", prompt)
        self.assertIn("Start passive", prompt)


class ContextBuilderTests(unittest.TestCase):
    def test_context_summary_includes_prior_tool_calls_without_raw_bloat(self):
        from ares.agent.context_builder import ContextBuilder
        from ares.state.db import StateDB

        db_path = Path(self.tmpdir) / "state.db"
        db = StateDB(db_path)
        sid = db.create_session(prompt="scan", target="127.0.0.1", model="unit", mode="safe-active")
        db.record_tool_call(
            session_id=sid,
            tool="nmap_basic",
            args={"target": "127.0.0.1"},
            status="ok",
            result={"stdout": "X" * 5000, "summary": "open 80/tcp"},
        )

        summary = ContextBuilder(db).build_session_context(sid)

        self.assertIn("Known prior tool calls", summary)
        self.assertIn("nmap_basic", summary)
        self.assertIn("open 80/tcp", summary)
        self.assertLess(len(summary), 2000)

    def setUp(self):
        import tempfile
        self._tmp = tempfile.TemporaryDirectory()
        self.tmpdir = self._tmp.name

    def tearDown(self):
        self._tmp.cleanup()


class PlaybookLoaderTests(unittest.TestCase):
    def test_selects_web_playbook_for_http_context(self):
        from ares.playbooks.registry import PlaybookRegistry

        registry = PlaybookRegistry.builtin()
        selected = registry.select_for_context(target="https://example.test", services=[{"service": "http"}])
        names = [p.name for p in selected]

        self.assertIn("web-application-enum", names)
        self.assertTrue(any("Probe HTTP" in p.content for p in selected))


if __name__ == "__main__":
    unittest.main()

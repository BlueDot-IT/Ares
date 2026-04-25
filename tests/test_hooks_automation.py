import sys
import tempfile
import textwrap
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))


class HooksAutomationTests(unittest.TestCase):
    def test_run_once_executes_python_hooks_and_auto_writes_report(self):
        from ares.agent.runtime import ModelResponse
        from ares.config.loader import AppConfig, HooksConfig, LLMConfig, PolicyConfig
        from ares.run import run_once
        from ares.state.db import StateDB
        from ares.tools.registry import ToolRegistry

        class FakeModel:
            def complete(self, messages, tools):
                return ModelResponse(final_text="finished cleanly")

        with tempfile.TemporaryDirectory() as tmp:
            home = Path(tmp)
            hooks_dir = home / "hooks"
            hooks_dir.mkdir(parents=True, exist_ok=True)
            (hooks_dir / "session_finish_hook.py").write_text(
                textwrap.dedent(
                    """
                    from pathlib import Path

                    HANDLED_EVENTS = ("session_finished",)

                    def handle_event(event):
                        marker = Path(event["home"]) / f"hook-{event['session_id']}.txt"
                        marker.write_text(event.get("report_path", "missing"), encoding="utf-8")
                        return {"marker": str(marker)}
                    """
                ).strip()
                + "\n",
                encoding="utf-8",
            )
            config = AppConfig(
                home=home,
                llm=LLMConfig(model="unit-model"),
                policy=PolicyConfig(max_risk="passive"),
                hooks=HooksConfig(auto_report_on_finish=True),
            )

            result = run_once(
                prompt="write a summary",
                target="127.0.0.1",
                config=config,
                model=FakeModel(),
                registry=ToolRegistry(),
            )

            db = StateDB(home / "state.db")
            session = db.list_sessions()[0]
            report_path = home / "reports" / f"session-{session['id']}.md"
            marker_path = home / f"hook-{session['id']}.txt"

            self.assertEqual(result.final_response, "finished cleanly")
            self.assertTrue(report_path.exists())
            self.assertTrue(marker_path.exists())
            self.assertEqual(marker_path.read_text(encoding="utf-8"), str(report_path))


if __name__ == "__main__":
    unittest.main()

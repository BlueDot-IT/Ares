import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))


class StateDBTests(unittest.TestCase):
    def test_create_session_and_record_tool_call(self):
        from ares.state.db import StateDB

        with tempfile.TemporaryDirectory() as tmp:
            db = StateDB(Path(tmp) / "state.db")
            session_id = db.create_session(
                prompt="enumerate",
                target="127.0.0.1",
                model="unit-model",
                mode="safe-active",
            )
            db.record_tool_call(
                session_id=session_id,
                tool="split_targets",
                args={"targets": "127.0.0.1;localhost"},
                status="ok",
                result={"targets": ["127.0.0.1", "localhost"]},
                duration_ms=12,
            )

            sessions = db.list_sessions()
            calls = db.list_tool_calls(session_id)
            db.record_message(session_id=session_id, role="user", content="hello")
            messages = db.list_messages(session_id)

            self.assertEqual(len(sessions), 1)
            self.assertEqual(sessions[0]["id"], session_id)
            self.assertEqual(sessions[0]["prompt"], "enumerate")
            self.assertEqual(sessions[0]["target"], "127.0.0.1")
            self.assertEqual(calls[0]["tool"], "split_targets")
            self.assertEqual(json.loads(calls[0]["args_json"]), {"targets": "127.0.0.1;localhost"})
            self.assertEqual(json.loads(calls[0]["result_json"]), {"targets": ["127.0.0.1", "localhost"]})
            self.assertEqual(calls[0]["status"], "ok")
            self.assertEqual(calls[0]["duration_ms"], 12)
            self.assertEqual(messages[0]["role"], "user")
            self.assertEqual(messages[0]["content"], "hello")


class RunStateIntegrationTests(unittest.TestCase):
    def test_run_once_persists_session_and_tool_call(self):
        from ares.agent.runtime import ModelResponse, ToolCall
        from ares.config.loader import AppConfig, LLMConfig, PolicyConfig
        from ares.run import run_once
        from ares.state.db import StateDB

        class FakeModel:
            def __init__(self):
                self.responses = [
                    ModelResponse(tool_calls=[ToolCall(name="split_targets", args={"targets": "127.0.0.1;localhost"})]),
                    ModelResponse(final_text="done"),
                ]

            def complete(self, messages, tools):
                return self.responses.pop(0)

        with tempfile.TemporaryDirectory() as tmp:
            home = Path(tmp)
            config = AppConfig(
                home=home,
                llm=LLMConfig(model="unit-model"),
                policy=PolicyConfig(max_risk="passive"),
            )
            result = run_once(
                prompt="split targets",
                target="127.0.0.1",
                model=FakeModel(),
                config=config,
                max_iterations=4,
            )

            db = StateDB(home / "state.db")
            sessions = db.list_sessions()
            calls = db.list_tool_calls(sessions[0]["id"])
            messages = db.list_messages(sessions[0]["id"])

            self.assertEqual(result.final_response, "done")
            self.assertEqual(len(sessions), 1)
            self.assertEqual(sessions[0]["target"], "127.0.0.1")
            self.assertEqual(sessions[0]["model"], "unit-model")
            self.assertEqual(len(calls), 1)
            self.assertEqual(calls[0]["tool"], "split_targets")
            self.assertEqual(calls[0]["status"], "ok")
            self.assertEqual(messages[0]["role"], "system")
            self.assertTrue(any(message["role"] == "tool" for message in messages))
            self.assertEqual(messages[-1]["role"], "assistant")


if __name__ == "__main__":
    unittest.main()

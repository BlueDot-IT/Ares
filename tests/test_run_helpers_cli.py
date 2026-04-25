import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))


class RunApprovalAndHelpersTests(unittest.TestCase):
    def test_run_once_denies_dangerous_tool_by_default_and_allows_when_flag_set(self):
        from ares.agent.runtime import ModelResponse, ToolCall
        from ares.config.loader import AppConfig, LLMConfig, PolicyConfig
        from ares.run import run_once
        from ares.tools.registry import ToolRegistry

        def make_model():
            class FakeModel:
                def __init__(self):
                    self.responses = [
                        ModelResponse(tool_calls=[ToolCall(name="exploit_tool", args={"target": "127.0.0.1"})]),
                        ModelResponse(final_text="done"),
                    ]

                def complete(self, messages, tools):
                    return self.responses.pop(0)
            return FakeModel()

        registry = ToolRegistry()
        registry.register(
            name="exploit_tool",
            toolset="unit",
            risk="exploit",
            schema={"name": "exploit_tool", "description": "exploit", "parameters": {"type": "object"}},
            handler=lambda args, **_: {"ok": True},
        )
        with tempfile.TemporaryDirectory() as tmp:
            config = AppConfig(home=Path(tmp), llm=LLMConfig(model="unit"), policy=PolicyConfig(max_risk="exploit"))
            denied = run_once(prompt="run exploit", target="127.0.0.1", config=config, model=make_model(), registry=registry)
            allowed = run_once(prompt="run exploit", target="127.0.0.1", config=config, model=make_model(), registry=registry, approve_dangerous=True)

        self.assertEqual(denied.tool_results[0].status, "error")
        self.assertIn("approval denied", denied.tool_results[0].error)
        self.assertEqual(allowed.tool_results[0].status, "ok")

    def test_run_once_emits_session_and_runtime_events(self):
        from ares.agent.runtime import ModelResponse, ToolCall
        from ares.config.loader import AppConfig, LLMConfig, PolicyConfig
        from ares.run import run_once
        from ares.tools.registry import ToolRegistry

        class FakeModel:
            def __init__(self):
                self.responses = [
                    ModelResponse(tool_calls=[ToolCall(name="echo_tool", args={"text": "hello"})]),
                    ModelResponse(final_text="done"),
                ]

            def complete(self, messages, tools):
                return self.responses.pop(0)

        registry = ToolRegistry()
        registry.register(
            name="echo_tool",
            toolset="unit",
            risk="passive",
            schema={"name": "echo_tool", "description": "echo", "parameters": {"type": "object"}},
            handler=lambda args, **_: {"echo": args["text"]},
        )
        events = []
        session_ids = []

        with tempfile.TemporaryDirectory() as tmp:
            config = AppConfig(home=Path(tmp), llm=LLMConfig(model="unit"), policy=PolicyConfig(max_risk="passive"))
            result = run_once(
                prompt="say hello",
                target="127.0.0.1",
                config=config,
                model=FakeModel(),
                registry=registry,
                event_callback=events.append,
                session_started_callback=session_ids.append,
            )

        self.assertEqual(result.final_response, "done")
        self.assertEqual(len(session_ids), 1)
        self.assertEqual(events[0]["type"], "session_started")
        self.assertTrue(any(event["type"] == "tool_call" and event.get("tool") == "echo_tool" for event in events))
        self.assertTrue(any(event["type"] == "tool_result" and event.get("tool") == "echo_tool" for event in events))
        self.assertTrue(any(event["type"] == "final_response" and event.get("final_response") == "done" for event in events))
        self.assertEqual(events[-1]["type"], "session_finished")

    def test_doctor_snapshot_and_tool_list_helpers(self):
        from ares.config.loader import AppConfig, LLMConfig, PolicyConfig
        from ares.run import build_doctor_snapshot, list_registered_tools
        from ares.tools.registry import ToolRegistry

        registry = ToolRegistry()
        registry.register(
            name="echo_tool",
            toolset="unit",
            risk="passive",
            schema={"name": "echo_tool", "description": "echo", "parameters": {"type": "object"}},
            handler=lambda args, **_: args,
        )
        config = AppConfig(home=Path("/tmp/ares-test"), llm=LLMConfig(model="unit"), policy=PolicyConfig(max_risk="passive"))

        tools = list_registered_tools(registry)
        snapshot = build_doctor_snapshot(config=config, registry=registry)

        self.assertEqual(tools[0]["name"], "echo_tool")
        self.assertEqual(tools[0]["risk"], "passive")
        self.assertEqual(snapshot["llm_model"], "unit")
        self.assertEqual(snapshot["registered_tools"], 1)


if __name__ == "__main__":
    unittest.main()

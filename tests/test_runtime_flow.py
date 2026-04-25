import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))


class _FakeModel:
    def __init__(self, responses):
        self.responses = list(responses)
        self.calls = []

    def complete(self, messages, tools):
        self.calls.append({"messages": list(messages), "tools": tools})
        return self.responses.pop(0)


class RuntimeFlowTests(unittest.TestCase):
    def test_runtime_uses_system_context_messages_and_stable_tool_schemas(self):
        from ares.agent.dispatcher import ToolDispatcher
        from ares.agent.runtime import AgentRuntime, ModelResponse, ToolCall
        from ares.policy.context import PolicyContext
        from ares.tools.registry import ToolRegistry

        registry = ToolRegistry()
        registry.register(
            name="echo_tool",
            toolset="unit",
            risk="passive",
            schema={"name": "echo_tool", "description": "echo", "parameters": {"type": "object"}},
            handler=lambda args, **_: {"echo": args.get("text", "")},
        )
        model = _FakeModel([
            ModelResponse(tool_calls=[ToolCall(name="echo_tool", args={"text": "hi"})]),
            ModelResponse(final_text="done"),
        ])
        runtime = AgentRuntime(
            model=model,
            registry=registry,
            policy=PolicyContext(max_risk="passive"),
            system_prompt="SYSTEM RULES",
            context_summary="STATE SUMMARY",
            dispatcher=ToolDispatcher(registry=registry, policy=PolicyContext(max_risk="passive")),
        )

        result = runtime.run("task")

        self.assertEqual(result.final_response, "done")
        self.assertEqual(model.calls[0]["messages"][0], {"role": "system", "content": "SYSTEM RULES"})
        self.assertEqual(model.calls[0]["messages"][1], {"role": "user", "content": "STATE SUMMARY"})
        self.assertEqual(model.calls[0]["messages"][2], {"role": "user", "content": "task"})
        self.assertIs(model.calls[0]["tools"], model.calls[1]["tools"])

    def test_runtime_emits_provider_stream_deltas_before_final_response(self):
        from ares.agent.runtime import AgentRuntime, ModelResponse
        from ares.policy.context import PolicyContext
        from ares.tools.registry import ToolRegistry

        events = []

        class StreamingModel:
            def complete_with_events(self, messages, tools, event_callback):
                event_callback({"type": "assistant_delta", "provider": "openrouter", "text": "Scanning "})
                event_callback({"type": "assistant_delta", "provider": "openrouter", "text": "authorized scope..."})
                return ModelResponse(final_text="Scanning authorized scope...")

        runtime = AgentRuntime(
            model=StreamingModel(),
            registry=ToolRegistry(),
            policy=PolicyContext(max_risk="passive"),
            event_callback=events.append,
        )

        result = runtime.run("task")

        self.assertEqual(result.final_response, "Scanning authorized scope...")
        self.assertEqual(
            [event["type"] for event in events],
            ["assistant_delta", "assistant_delta", "final_response"],
        )
        self.assertEqual(events[0]["provider"], "openrouter")
        self.assertEqual(events[0]["text"], "Scanning ")
        self.assertEqual(events[1]["text"], "authorized scope...")
        self.assertEqual(events[-1]["final_response"], "Scanning authorized scope...")

    def test_dispatcher_persists_and_returns_compact_tool_result(self):
        from ares.agent.dispatcher import ToolDispatcher
        from ares.agent.runtime import ToolCall
        from ares.policy.context import PolicyContext
        from ares.state.db import StateDB
        from ares.tools.registry import ToolRegistry

        registry = ToolRegistry()
        registry.register(
            name="echo_tool",
            toolset="unit",
            risk="passive",
            schema={"name": "echo_tool", "description": "echo", "parameters": {"type": "object"}},
            handler=lambda args, **_: {"stdout": "X" * 5000, "summary": "small summary"},
        )
        db = StateDB(Path(self.tmpdir) / "state.db")
        sid = db.create_session(prompt="task", target="127.0.0.1", model="unit", mode="safe-active")
        dispatcher = ToolDispatcher(registry=registry, policy=PolicyContext(max_risk="passive"), recorder=db, session_id=sid)

        result = dispatcher.dispatch(ToolCall(name="echo_tool", args={}))
        calls = db.list_tool_calls(sid)

        self.assertEqual(result.status, "ok")
        self.assertEqual(result.result["summary"], "small summary")
        self.assertNotIn("stdout", result.result)
        self.assertEqual(calls[0]["tool"], "echo_tool")
        self.assertEqual(calls[0]["status"], "ok")

    def setUp(self):
        import tempfile
        self._tmp = tempfile.TemporaryDirectory()
        self.tmpdir = self._tmp.name

    def tearDown(self):
        self._tmp.cleanup()


if __name__ == "__main__":
    unittest.main()

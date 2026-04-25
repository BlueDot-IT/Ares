import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))


class _FakeModel:
    def __init__(self, responses):
        self.responses = list(responses)
        self.calls = []

    def complete(self, messages, tools):
        self.calls.append({"messages": list(messages), "tools": list(tools)})
        if not self.responses:
            raise AssertionError("model called too many times")
        return self.responses.pop(0)


class AgentRuntimeTests(unittest.TestCase):
    def test_runtime_executes_tool_call_and_returns_final_response(self):
        from ares.agent.runtime import AgentRuntime, ModelResponse, ToolCall
        from ares.policy.context import PolicyContext
        from ares.tools.registry import ToolRegistry

        registry = ToolRegistry()
        registry.register(
            name="echo_tool",
            toolset="unit",
            risk="passive",
            schema={
                "name": "echo_tool",
                "description": "Echo text",
                "parameters": {
                    "type": "object",
                    "properties": {"text": {"type": "string"}},
                    "required": ["text"],
                },
            },
            handler=lambda args, **_: {"echo": args["text"]},
        )
        model = _FakeModel(
            [
                ModelResponse(tool_calls=[ToolCall(name="echo_tool", args={"text": "hello"})]),
                ModelResponse(final_text="done"),
            ]
        )

        runtime = AgentRuntime(model=model, registry=registry, policy=PolicyContext(max_risk="passive"))
        result = runtime.run("say hello")

        self.assertEqual(result.final_response, "done")
        self.assertEqual(len(result.tool_results), 1)
        self.assertEqual(result.tool_results[0].result, {"echo": "hello"})
        self.assertEqual(result.tool_results[0].status, "ok")
        self.assertEqual(len(model.calls), 2)
        self.assertEqual(model.calls[0]["tools"][0]["function"]["name"], "echo_tool")
        self.assertEqual(model.calls[1]["messages"][-1]["role"], "tool")

    def test_runtime_records_policy_denial_without_executing_handler(self):
        from ares.agent.runtime import AgentRuntime, ModelResponse, ToolCall
        from ares.policy.context import PolicyContext
        from ares.tools.registry import ToolRegistry

        executed = []
        registry = ToolRegistry()
        registry.register(
            name="scan_tool",
            toolset="unit",
            risk="active",
            schema={"name": "scan_tool", "description": "scan", "parameters": {"type": "object"}},
            handler=lambda args, **_: executed.append(args) or {"ok": True},
        )
        model = _FakeModel(
            [
                ModelResponse(tool_calls=[ToolCall(name="scan_tool", args={"target": "8.8.8.8"})]),
                ModelResponse(final_text="stopped"),
            ]
        )

        runtime = AgentRuntime(
            model=model,
            registry=registry,
            policy=PolicyContext(max_risk="active", allow_private_only=True),
        )
        result = runtime.run("scan public target")

        self.assertEqual(result.final_response, "stopped")
        self.assertEqual(executed, [])
        self.assertEqual(result.tool_results[0].status, "error")
        self.assertIn("scope policy violation", result.tool_results[0].error)

    def test_runtime_stops_at_max_iterations(self):
        from ares.agent.runtime import AgentRuntime, ModelResponse, ToolCall
        from ares.policy.context import PolicyContext
        from ares.tools.registry import ToolRegistry

        registry = ToolRegistry()
        registry.register(
            name="noop_tool",
            toolset="unit",
            risk="passive",
            schema={"name": "noop_tool", "description": "noop", "parameters": {"type": "object"}},
            handler=lambda args, **_: {"ok": True},
        )
        model = _FakeModel(
            [
                ModelResponse(tool_calls=[ToolCall(name="noop_tool", args={})]),
                ModelResponse(tool_calls=[ToolCall(name="noop_tool", args={})]),
            ]
        )

        runtime = AgentRuntime(
            model=model,
            registry=registry,
            policy=PolicyContext(max_risk="passive"),
            max_iterations=2,
        )
        result = runtime.run("loop")

        self.assertEqual(result.final_response, "")
        self.assertEqual(result.stop_reason, "max_iterations")
        self.assertEqual(len(result.tool_results), 2)


if __name__ == "__main__":
    unittest.main()

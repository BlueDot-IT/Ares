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


class RunHelperTests(unittest.TestCase):
    def test_run_once_registers_ghostmcp_tools_and_executes_tool_call(self):
        from ares.agent.runtime import ModelResponse, ToolCall
        from ares.run import run_once

        model = _FakeModel(
            [
                ModelResponse(tool_calls=[ToolCall(name="split_targets", args={"targets": "127.0.0.1;localhost"})]),
                ModelResponse(final_text="done"),
            ]
        )

        result = run_once(prompt="split targets", target="127.0.0.1", model=model, max_iterations=4)

        self.assertEqual(result.final_response, "done")
        self.assertEqual(result.tool_results[0].tool, "split_targets")
        self.assertEqual(result.tool_results[0].status, "ok")
        self.assertEqual(result.tool_results[0].result, {"targets": ["127.0.0.1", "localhost"]})
        exposed_names = {tool["function"]["name"] for tool in model.calls[0]["tools"]}
        self.assertIn("split_targets", exposed_names)
        self.assertIn("Target: 127.0.0.1", model.calls[0]["messages"][0]["content"])

    def test_run_once_applies_policy_to_registered_ghostmcp_tools(self):
        from ares.agent.runtime import ModelResponse, ToolCall
        from ares.config.loader import AppConfig, LLMConfig, PolicyConfig
        from ares.run import run_once

        model = _FakeModel(
            [
                ModelResponse(tool_calls=[ToolCall(name="nmap_basic", args={"target": "127.0.0.1"})]),
                ModelResponse(final_text="blocked"),
            ]
        )
        config = AppConfig(
            home=Path("/tmp/ares-test"),
            llm=LLMConfig(model="unit-model"),
            policy=PolicyConfig(max_risk="passive"),
        )

        result = run_once(prompt="scan", target="127.0.0.1", model=model, config=config, max_iterations=4)

        self.assertEqual(result.final_response, "blocked")
        self.assertEqual(result.tool_results[0].status, "error")
        self.assertIn("risk policy violation", result.tool_results[0].error)


if __name__ == "__main__":
    unittest.main()

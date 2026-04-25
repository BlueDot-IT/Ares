import sys
import time
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))


class DispatcherTimeoutTests(unittest.TestCase):
    def test_dispatcher_times_out_slow_tool(self):
        from ares.agent.dispatcher import ToolDispatcher
        from ares.agent.runtime import ToolCall
        from ares.policy.context import PolicyContext
        from ares.tools.registry import ToolRegistry

        registry = ToolRegistry()

        def slow_handler(args, **kwargs):
            time.sleep(0.2)
            return {"ok": True}

        registry.register(
            name="slow_tool",
            toolset="unit",
            risk="passive",
            schema={"name": "slow_tool", "description": "slow", "parameters": {"type": "object"}},
            handler=slow_handler,
        )
        dispatcher = ToolDispatcher(
            registry=registry,
            policy=PolicyContext(max_risk="passive"),
            tool_timeout_seconds=0.01,
        )

        result = dispatcher.dispatch(ToolCall(name="slow_tool", args={"target": "127.0.0.1"}))

        self.assertEqual(result.status, "error")
        self.assertIn("timed out", result.error)


if __name__ == "__main__":
    unittest.main()

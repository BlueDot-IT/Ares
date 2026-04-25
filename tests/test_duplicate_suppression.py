import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))


class DuplicateSuppressionTests(unittest.TestCase):
    def test_dispatcher_blocks_duplicate_successful_tool_call(self):
        from ares.agent.dispatcher import ToolDispatcher
        from ares.agent.runtime import ToolCall
        from ares.policy.context import PolicyContext
        from ares.state.db import StateDB
        from ares.tools.registry import ToolRegistry

        executed = []
        registry = ToolRegistry()
        registry.register(
            name="echo_tool",
            toolset="unit",
            risk="passive",
            schema={"name": "echo_tool", "description": "echo", "parameters": {"type": "object"}},
            handler=lambda args, **_: executed.append(args) or {"ok": True},
        )

        with tempfile.TemporaryDirectory() as tmp:
            db = StateDB(Path(tmp) / "state.db")
            sid = db.create_session(prompt="task", target="127.0.0.1", model="unit", mode="safe-active")
            dispatcher = ToolDispatcher(registry=registry, policy=PolicyContext(max_risk="passive"), recorder=db, session_id=sid)

            first = dispatcher.dispatch(ToolCall(name="echo_tool", args={"target": "127.0.0.1"}))
            second = dispatcher.dispatch(ToolCall(name="echo_tool", args={"target": "127.0.0.1"}))

            self.assertEqual(first.status, "ok")
            self.assertEqual(second.status, "error")
            self.assertIn("duplicate_successful_action", second.error)
            self.assertEqual(len(executed), 1)


if __name__ == "__main__":
    unittest.main()

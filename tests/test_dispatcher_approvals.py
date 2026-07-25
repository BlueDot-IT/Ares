import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))


class DispatcherApprovalTests(unittest.TestCase):
    def test_dispatcher_denies_exploit_tool_when_approval_callback_rejects(self):
        from ares.agent.dispatcher import ToolDispatcher
        from ares.agent.runtime import ToolCall
        from ares.policy.context import PolicyContext
        from ares.tools.registry import ToolRegistry

        executed = []
        registry = ToolRegistry()
        registry.register(
            name="exploit_tool",
            toolset="unit",
            risk="exploit",
            schema={"name": "exploit_tool", "description": "exploit", "parameters": {"type": "object"}},
            handler=lambda args, **_: executed.append(args) or {"ok": True},
        )
        approvals = []

        def approve(call, entry):
            approvals.append((call.name, entry.risk))
            return False

        dispatcher = ToolDispatcher(
            registry=registry,
            policy=PolicyContext(max_risk="exploit", allow_private_only=True),
            approval_callback=approve,
        )

        result = dispatcher.dispatch(ToolCall(name="exploit_tool", args={"target": "127.0.0.1"}))

        self.assertEqual(result.status, "error")
        self.assertIn("approval denied", result.error)
        self.assertEqual(executed, [])
        self.assertEqual(approvals, [("exploit_tool", "exploit")])

    def test_dispatcher_executes_exploit_tool_when_approval_callback_accepts(self):
        from ares.agent.dispatcher import ToolDispatcher
        from ares.agent.runtime import ToolCall
        from ares.policy.context import PolicyContext
        from ares.tools.registry import ToolRegistry

        registry = ToolRegistry()
        registry.register(
            name="exploit_tool",
            toolset="unit",
            risk="exploit",
            schema={"name": "exploit_tool", "description": "exploit", "parameters": {"type": "object"}},
            handler=lambda args, **_: {"ok": True},
        )
        dispatcher = ToolDispatcher(
            registry=registry,
            policy=PolicyContext(max_risk="exploit", allow_private_only=True),
            approval_callback=lambda call, entry: True,
        )

        result = dispatcher.dispatch(ToolCall(name="exploit_tool", args={"target": "127.0.0.1"}))

        self.assertEqual(result.status, "ok")

    def test_role_risk_floor_requires_approval_for_lower_risk_tool(self) -> None:
        from ares.agent.dispatcher import ToolDispatcher
        from ares.agent.runtime import ToolCall
        from ares.policy.context import PolicyContext
        from ares.tools.registry import ToolRegistry

        registry = ToolRegistry()
        registry.register(
            name="smbmap",
            toolset="ghostmcp",
            risk="active",
            schema={"type": "object", "properties": {}},
            handler=lambda _args: {"ok": True},
        )
        dispatcher = ToolDispatcher(
            registry=registry,
            policy=PolicyContext(max_risk="post-exploitation"),
        )
        result = dispatcher.dispatch(
            ToolCall(name="smbmap", required_risk="post-exploitation")
        )
        self.assertEqual(result.status, "error")
        self.assertIn("approval denied", result.error)

        approved = ToolDispatcher(
            registry=registry,
            policy=PolicyContext(max_risk="post-exploitation"),
            approval_callback=lambda _call, _entry: True,
        )
        result = approved.dispatch(
            ToolCall(name="smbmap", required_risk="post-exploitation")
        )
        self.assertEqual(result.status, "ok")
        self.assertEqual(result.result, {"ok": True})


if __name__ == "__main__":
    unittest.main()

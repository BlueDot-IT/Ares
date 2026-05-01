import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))


class PolicyDispatchTests(unittest.TestCase):
    def test_dispatch_blocks_tool_above_policy_risk_ceiling(self):
        from ares.policy.context import PolicyContext
        from ares.tools.registry import ToolRegistry

        registry = ToolRegistry()
        registry.register(
            name="intrusive_tool",
            toolset="unit",
            risk="intrusive",
            schema={"name": "intrusive_tool", "description": "test", "parameters": {"type": "object"}},
            handler=lambda args, **_: {"ok": True},
        )

        with self.assertRaisesRegex(PermissionError, "risk"):
            registry.dispatch(
                "intrusive_tool",
                {"target": "127.0.0.1"},
                policy=PolicyContext(max_risk="active"),
            )

    def test_dispatch_blocks_out_of_scope_public_ip(self):
        from ares.policy.context import PolicyContext
        from ares.tools.registry import ToolRegistry

        registry = ToolRegistry()
        registry.register(
            name="active_tool",
            toolset="unit",
            risk="active",
            schema={"name": "active_tool", "description": "test", "parameters": {"type": "object"}},
            handler=lambda args, **_: {"ok": True},
        )

        with self.assertRaisesRegex(PermissionError, "scope"):
            registry.dispatch(
                "active_tool",
                {"target": "8.8.8.8"},
                policy=PolicyContext(max_risk="active", allow_private_only=True),
            )

    def test_dispatch_allows_in_scope_private_or_loopback_target(self):
        from ares.policy.context import PolicyContext
        from ares.tools.registry import ToolRegistry

        registry = ToolRegistry()
        registry.register(
            name="active_tool",
            toolset="unit",
            risk="active",
            schema={"name": "active_tool", "description": "test", "parameters": {"type": "object"}},
            handler=lambda args, **_: {"target": args["target"]},
        )

        result = registry.dispatch(
            "active_tool",
            {"target": "127.0.0.1"},
            policy=PolicyContext(max_risk="active", allow_private_only=True),
        )

        self.assertEqual(result, {"target": "127.0.0.1"})

    def test_dispatch_blocks_out_of_scope_hostname_and_onion_target_when_private_only(self):
        from ares.policy.context import PolicyContext
        from ares.tools.registry import ToolRegistry

        registry = ToolRegistry()
        registry.register(
            name="active_tool",
            toolset="unit",
            risk="active",
            schema={"name": "active_tool", "description": "test", "parameters": {"type": "object"}},
            handler=lambda args, **_: {"ok": True},
        )

        for target in ("https://example.com", "http://hiddenserviceexample.onion"):
            with self.assertRaisesRegex(PermissionError, "scope"):
                registry.dispatch(
                    "active_tool",
                    {"target": target},
                    policy=PolicyContext(max_risk="active", allow_private_only=True),
                )


if __name__ == "__main__":
    unittest.main()

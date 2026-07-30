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

    def test_bounded_dispatch_covers_domain_file_and_opaque_raw_arguments(self):
        from ares.policy.context import PolicyContext
        from ares.tools.registry import ToolRegistry

        registry = ToolRegistry()
        registry.register(
            name="bounded_tool",
            toolset="unit",
            risk="active",
            schema={"name": "bounded_tool", "description": "test", "parameters": {"type": "object"}},
            handler=lambda args, **_: {"ok": True},
        )
        network_policy = PolicyContext(
            max_risk="active",
            allowed_cidrs=(),
            allowed_hosts=("example.local",),
            scope_bound=True,
        )

        for args in (
            {"domain": "other.local"},
            {"file_path": "/etc/passwd"},
            {"args": "--target other.local"},
        ):
            with self.assertRaisesRegex(PermissionError, "scope"):
                registry.dispatch("bounded_tool", args, policy=network_policy)

        result = registry.dispatch(
            "bounded_tool",
            {"domain": "example.local"},
            policy=network_policy,
        )
        self.assertEqual(result, {"ok": True})

    def test_path_bound_dispatch_rejects_network_targets(self):
        from ares.policy.context import PolicyContext
        from ares.tools.registry import ToolRegistry

        registry = ToolRegistry()
        registry.register(
            name="bounded_tool",
            toolset="unit",
            risk="active",
            schema={"name": "bounded_tool", "description": "test", "parameters": {"type": "object"}},
            handler=lambda args, **_: {"ok": True},
        )

        with self.assertRaisesRegex(PermissionError, "scope"):
            registry.dispatch(
                "bounded_tool",
                {"host": "127.0.0.1"},
                policy=PolicyContext(
                    max_risk="active",
                    allowed_paths=("/tmp/scoped",),
                    scope_bound=True,
                ),
            )


if __name__ == "__main__":
    unittest.main()

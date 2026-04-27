import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))


class GhostMCPAdapterTests(unittest.TestCase):
    def test_register_ghostmcp_tools_adds_callable_tools_to_registry(self):
        from ares.tools.ghostmcp_adapter import register_ghostmcp_tools
        from ares.tools.registry import ToolRegistry

        registry = ToolRegistry()
        count = register_ghostmcp_tools(registry, toolset="ghostmcp.test")

        self.assertGreater(count, 20)
        definitions = registry.get_tool_definitions(enabled_toolsets={"ghostmcp.test"})
        names = {tool["function"]["name"] for tool in definitions}
        self.assertIn("split_targets", names)
        self.assertIn("toolchain_status", names)
        self.assertIn("runtime_probe", names)
        self.assertIn("server_health", names)

        result = registry.dispatch("split_targets", {"targets": "127.0.0.1;localhost"})
        self.assertEqual(result, {"targets": ["127.0.0.1", "localhost"]})

    def test_registered_ghostmcp_tools_include_risk_metadata(self):
        from ares.tools.ghostmcp_adapter import register_ghostmcp_tools
        from ares.tools.registry import ToolRegistry

        registry = ToolRegistry()
        register_ghostmcp_tools(registry, toolset="ghostmcp.test")

        passive_names = {
            tool["function"]["name"]
            for tool in registry.get_tool_definitions(
                enabled_toolsets={"ghostmcp.test"},
                max_risk="passive",
            )
        }
        active_names = {
            tool["function"]["name"]
            for tool in registry.get_tool_definitions(
                enabled_toolsets={"ghostmcp.test"},
                max_risk="active",
            )
        }

        self.assertIn("split_targets", passive_names)
        self.assertNotIn("nmap_basic", passive_names)
        self.assertIn("nmap_basic", active_names)

    def test_register_ghostmcp_tools_preserves_input_schema_from_external_inventory(self):
        from ares.tools.ghostmcp_adapter import register_ghostmcp_tools
        from ares.tools.registry import ToolRegistry

        class _FakeRunner:
            tools = {
                "split_targets": {
                    "name": "split_targets",
                    "description": "Split semicolon targets.",
                    "inputSchema": {
                        "type": "object",
                        "properties": {"targets": {"type": "string"}},
                        "required": ["targets"],
                    },
                    "signature": "(…)"
                }
            }

            def call(self, tool, args):
                return {"targets": args["targets"].split(";")}

        registry = ToolRegistry()
        register_ghostmcp_tools(registry, toolset="ghostmcp.test", runner=_FakeRunner())
        entry = registry.get_entry("split_targets")

        self.assertEqual(entry.schema["parameters"]["properties"], {"targets": {"type": "string"}})
        self.assertEqual(entry.schema["parameters"]["required"], ["targets"])

    def test_registered_ghostmcp_object_schemas_always_include_properties_for_openai(self):
        from ares.tools.ghostmcp_adapter import register_ghostmcp_tools
        from ares.tools.registry import ToolRegistry

        class _FakeRunner:
            tools = {
                "amass_passive": {
                    "name": "amass_passive",
                    "description": "Passive amass inventory.",
                    "inputSchema": {"type": "object"},
                    "signature": "()",
                }
            }

            def call(self, tool, args):
                return {"ok": True}

        registry = ToolRegistry()
        register_ghostmcp_tools(registry, toolset="ghostmcp.test", runner=_FakeRunner())
        definitions = registry.get_tool_definitions(enabled_toolsets={"ghostmcp.test"})

        parameters = definitions[0]["function"]["parameters"]
        self.assertEqual(parameters["type"], "object")
        self.assertEqual(parameters["properties"], {})
        self.assertEqual(parameters["required"], [])


if __name__ == "__main__":
    unittest.main()

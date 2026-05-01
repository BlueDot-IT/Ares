import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))


class OnionClawAdapterTests(unittest.TestCase):
    def test_register_onionclaw_tools_only_exposes_bounded_safe_subset(self):
        from ares.config.loader import OnionClawConfig
        from ares.tools.onionclaw_adapter import register_onionclaw_tools
        from ares.tools.registry import ToolRegistry

        class _FakeRunner:
            tools = {
                "sicry_check_tor": {
                    "name": "sicry_check_tor",
                    "description": "Verify Tor is running.",
                    "inputSchema": {"type": "object"},
                },
                "sicry_renew_identity": {
                    "name": "sicry_renew_identity",
                    "description": "Renew Tor identity.",
                    "inputSchema": {"type": "object"},
                },
                "sicry_check_engines": {
                    "name": "sicry_check_engines",
                    "description": "Check engines.",
                    "inputSchema": {"type": "object"},
                },
                "sicry_search": {
                    "name": "sicry_search",
                    "description": "Search onions.",
                    "inputSchema": {
                        "type": "object",
                        "properties": {"query": {"type": "string"}},
                        "required": ["query"],
                    },
                },
                "sicry_fetch": {
                    "name": "sicry_fetch",
                    "description": "Fetch onion.",
                    "inputSchema": {
                        "type": "object",
                        "properties": {"url": {"type": "string"}},
                        "required": ["url"],
                    },
                },
                "sicry_analyze_nollm": {
                    "name": "sicry_analyze_nollm",
                    "description": "Offline analysis.",
                    "inputSchema": {
                        "type": "object",
                        "properties": {"content": {"type": "string"}},
                        "required": ["content"],
                    },
                },
                "sicry_extract_keywords": {
                    "name": "sicry_extract_keywords",
                    "description": "Extract keywords.",
                    "inputSchema": {
                        "type": "object",
                        "properties": {"text": {"type": "string"}},
                        "required": ["text"],
                    },
                },
                "sicry_to_stix": {
                    "name": "sicry_to_stix",
                    "description": "Export STIX.",
                    "inputSchema": {
                        "type": "object",
                        "properties": {"results": {"type": "array", "items": {"type": "object"}}},
                        "required": ["results"],
                    },
                },
                "sicry_to_csv": {
                    "name": "sicry_to_csv",
                    "description": "Export CSV.",
                    "inputSchema": {
                        "type": "object",
                        "properties": {"results": {"type": "array", "items": {"type": "object"}}},
                        "required": ["results"],
                    },
                },
                "sicry_watch_add": {
                    "name": "sicry_watch_add",
                    "description": "Watch add.",
                    "inputSchema": {"type": "object"},
                },
                "sicry_watch_check": {
                    "name": "sicry_watch_check",
                    "description": "Watch check.",
                    "inputSchema": {"type": "object"},
                },
                "sicry_crawl": {
                    "name": "sicry_crawl",
                    "description": "Crawl onion.",
                    "inputSchema": {"type": "object"},
                },
                "sicry_ask": {
                    "name": "sicry_ask",
                    "description": "LLM ask.",
                    "inputSchema": {"type": "object"},
                },
            }

            def call(self, tool, args):
                return {"tool": tool, "args": args}

        registry = ToolRegistry()
        count = register_onionclaw_tools(
            registry,
            config=OnionClawConfig(enabled=True, repo_path="/opt/onionclaw"),
            toolset="onionclaw.test",
            runner=_FakeRunner(),
        )

        self.assertEqual(count, 9)
        definitions = registry.get_tool_definitions(enabled_toolsets={"onionclaw.test"}, max_risk="active")
        names = {tool["function"]["name"] for tool in definitions}
        self.assertEqual(
            names,
            {
                "onionclaw_check_tor",
                "onionclaw_renew_identity",
                "onionclaw_check_engines",
                "onionclaw_search",
                "onionclaw_fetch",
                "onionclaw_analyze_nollm",
                "onionclaw_extract_keywords",
                "onionclaw_to_stix",
                "onionclaw_to_csv",
            },
        )
        self.assertNotIn("onionclaw_watch_add", names)
        self.assertNotIn("onionclaw_crawl", names)
        self.assertNotIn("onionclaw_ask", names)

    def test_onionclaw_risk_metadata_keeps_fetch_out_of_passive_scope(self):
        from ares.config.loader import OnionClawConfig
        from ares.tools.onionclaw_adapter import register_onionclaw_tools
        from ares.tools.registry import ToolRegistry

        class _FakeRunner:
            tools = {
                "sicry_search": {
                    "name": "sicry_search",
                    "description": "Search onions.",
                    "inputSchema": {"type": "object", "properties": {"query": {"type": "string"}}, "required": ["query"]},
                },
                "sicry_fetch": {
                    "name": "sicry_fetch",
                    "description": "Fetch onion.",
                    "inputSchema": {"type": "object", "properties": {"url": {"type": "string"}}, "required": ["url"]},
                },
            }

            def call(self, tool, args):
                return {"tool": tool, "args": args}

        registry = ToolRegistry()
        register_onionclaw_tools(
            registry,
            config=OnionClawConfig(enabled=True, repo_path="/opt/onionclaw"),
            toolset="onionclaw.test",
            runner=_FakeRunner(),
        )

        passive_names = {
            tool["function"]["name"]
            for tool in registry.get_tool_definitions(enabled_toolsets={"onionclaw.test"}, max_risk="passive")
        }
        active_names = {
            tool["function"]["name"]
            for tool in registry.get_tool_definitions(enabled_toolsets={"onionclaw.test"}, max_risk="active")
        }

        self.assertIn("onionclaw_search", passive_names)
        self.assertNotIn("onionclaw_fetch", passive_names)
        self.assertIn("onionclaw_fetch", active_names)


if __name__ == "__main__":
    unittest.main()

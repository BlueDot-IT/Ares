import sys
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))


class GhostMCPRunnerSchemaTests(unittest.TestCase):
    def test_inproc_runner_derives_required_schemas_from_callable_signatures(self):
        from lib.ghostmcp_runner import GhostMCPToolRunner

        runner = GhostMCPToolRunner(transport="inproc")

        whois_schema = runner.tools["whois"]["inputSchema"]
        reverse_dns_schema = runner.tools["reverse_dns"]["inputSchema"]
        tcp_port_scan_schema = runner.tools["tcp_port_scan"]["inputSchema"]

        self.assertEqual(whois_schema["type"], "object")
        self.assertEqual(whois_schema["required"], ["target"])
        self.assertEqual(whois_schema["properties"]["target"]["type"], "string")

        self.assertEqual(reverse_dns_schema["required"], ["ip"])
        self.assertEqual(reverse_dns_schema["properties"]["ip"]["type"], "string")

        self.assertEqual(tcp_port_scan_schema["required"], ["host", "ports"])
        self.assertEqual(tcp_port_scan_schema["properties"]["ports"]["type"], "array")
        self.assertEqual(tcp_port_scan_schema["properties"]["ports"]["items"]["type"], "integer")

    def test_vendored_runner_exposes_versioned_security_manifest(self):
        from lib.ghostmcp_runner import GhostMCPToolRunner

        runner = GhostMCPToolRunner(transport="inproc")
        security = runner.tools["runtime_probe"]["security"]

        self.assertEqual(security["manifest_schema"], "1.0")
        self.assertEqual(security["server_version"], "0.2.0")
        self.assertEqual(security["risk"], "passive")
        self.assertIn("discovery", security["capabilities"])
        runner.close()

    def test_external_bridge_preserves_security_manifest(self):
        from lib.ghostmcp_runner import GhostMCPToolRunner

        runner = GhostMCPToolRunner(transport="external-stdio")
        security = runner.tools["runtime_probe"]["security"]

        self.assertEqual(security["manifest_schema"], "1.0")
        self.assertEqual(security["server_version"], "0.2.0")
        runner.close()

    def test_register_ghostmcp_tools_passes_scope_policy_to_default_runner(self):
        from ares.tools.ghostmcp_adapter import register_ghostmcp_tools, reset_default_ghostmcp_runner_cache
        from ares.tools.registry import ToolRegistry

        class _FakeRunner:
            tools = {
                "split_targets": {
                    "name": "split_targets",
                    "description": "Split semicolon targets.",
                    "signature": "(targets: str)",
                    "inputSchema": {
                        "type": "object",
                        "properties": {"targets": {"type": "string"}},
                        "required": ["targets"],
                    },
                }
            }

            def call(self, tool, args):
                return {"targets": args["targets"].split(";")}

        registry = ToolRegistry()
        reset_default_ghostmcp_runner_cache()
        try:
            with patch("ares.tools.ghostmcp_adapter.GhostMCPToolRunner", return_value=_FakeRunner()) as ctor:
                register_ghostmcp_tools(registry, policy_allow_private_only=False)
        finally:
            reset_default_ghostmcp_runner_cache()

        ctor.assert_called_once_with(allow_private_only=False)
        self.assertIn("split_targets", {entry.name for entry in registry.iter_entries()})


if __name__ == "__main__":
    unittest.main()

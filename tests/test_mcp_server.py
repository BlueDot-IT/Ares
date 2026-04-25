import sys
from pathlib import Path
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))


class GhostMCPRunnerTests(unittest.TestCase):
    def test_runner_initializes_and_exposes_vendor_and_legacy_tools(self):
        # Import inside test so failing imports show clear unittest output
        from lib.ghostmcp_runner import GhostMCPToolRunner

        runner = GhostMCPToolRunner(transport="inproc")
        self.assertIsInstance(runner.tools, dict)
        self.assertGreater(len(runner.tools), 20)
        self.assertIn("toolchain_status", runner.tools)
        self.assertIn("runtime_probe", runner.tools)
        self.assertIn("server_health", runner.tools)
        self.assertIn("split_targets", runner.tools)

    def test_runner_can_use_external_stdio_bridge(self):
        from lib.ghostmcp_runner import GhostMCPToolRunner

        runner = GhostMCPToolRunner(transport="external-stdio")
        self.assertGreater(len(runner.tools), 20)
        self.assertIn("toolchain_status", runner.tools)
        result = runner.call("split_targets", {"targets": "127.0.0.1;localhost"})
        self.assertEqual(result, {"targets": ["127.0.0.1", "localhost"]})

    def test_runner_can_execute_discovered_tool(self):
        from lib.ghostmcp_runner import GhostMCPToolRunner

        runner = GhostMCPToolRunner(transport="inproc")
        result = runner.call("split_targets", {"targets": "127.0.0.1;localhost"})
        self.assertEqual(result, {"targets": ["127.0.0.1", "localhost"]})

    def test_runner_unknown_tool_raises(self):
        from lib.ghostmcp_runner import GhostMCPToolRunner

        runner = GhostMCPToolRunner(transport="inproc")
        with self.assertRaises(RuntimeError):
            runner.call("definitely_not_a_tool", {})

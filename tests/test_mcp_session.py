import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))


class MCPProcessSessionTests(unittest.TestCase):
    def test_session_initializes_lists_tools_and_calls_tool_over_stdio_mcp(self):
        from lib.mcp_session import MCPProcessSession, MCPServerParameters

        repo = Path(__file__).resolve().parents[1]
        params = MCPServerParameters(
            command=[sys.executable, "-m", "lib.mcp_server"],
            cwd=str(repo),
            env={"PYTHONPATH": str(repo / "src")},
        )

        with MCPProcessSession(params) as session:
            init = session.initialize()
            tools = session.list_tools()
            result = session.call_tool("split_targets", {"targets": "127.0.0.1;localhost"})

        self.assertIn("protocolVersion", init)
        tool_names = {tool["name"] for tool in tools}
        self.assertIn("split_targets", tool_names)
        self.assertEqual(result, {"targets": ["127.0.0.1", "localhost"]})


if __name__ == "__main__":
    unittest.main()

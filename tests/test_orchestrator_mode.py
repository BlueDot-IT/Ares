import json
import os
import sys
import tempfile
from pathlib import Path
import unittest
import types

class _DummyOpenAI:
    def __init__(self, *args, **kwargs):
        pass

sys.modules.setdefault("openai", types.SimpleNamespace(OpenAI=_DummyOpenAI))
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from lib.orchestrator import Orchestrator


class _FakeMCP:
    def __init__(self):
        self.tools = {
            "nmap_basic": {"name": "nmap_basic"},
            "msf_search": {"name": "msf_search"},
        }
        self.calls = []

    def call(self, tool, args):
        self.calls.append((tool, args))
        return {"returncode": 0, "stdout": "", "stderr": ""}


class _FakeLLM:
    def __init__(self, responses):
        self._responses = list(responses)
        self._idx = 0

    def generate_text(self, prompt, max_tokens=400):
        if self._idx >= len(self._responses):
            return json.dumps(
                {
                    "thought": "stop",
                    "action": {"tool": "terminate", "args": {}},
                    "expected_result": "done",
                }
            )
        value = self._responses[self._idx]
        self._idx += 1
        return value


class OrchestratorModeTests(unittest.TestCase):
    def test_blocks_msf_search_in_enum_mode(self):
        planner_responses = [
            json.dumps(
                {
                    "thought": "search exploits",
                    "action": {"tool": "msf_search", "args": {"query": "ssh"}},
                    "expected_result": "find modules",
                }
            ),
            json.dumps(
                {
                    "thought": "done",
                    "action": {"tool": "terminate", "args": {}},
                    "expected_result": "stop",
                }
            ),
        ]

        orchestrator = Orchestrator.__new__(Orchestrator)
        orchestrator.mcp = _FakeMCP()
        orchestrator.llm = _FakeLLM(planner_responses)

        lines = []
        old_cwd = os.getcwd()
        with tempfile.TemporaryDirectory() as tmp:
            os.chdir(tmp)
            try:
                orchestrator.run_scan(
                    {
                        "targets": "127.0.0.1",
                        "resolve_dns": False,
                        "enable_ipv6": False,
                        "mode": "enum",
                    },
                    lines.append,
                )
            finally:
                os.chdir(old_cwd)

        self.assertTrue(any("not allowed in mode 'enum'" in line for line in lines))
        self.assertFalse(any(tool == "msf_search" for tool, _ in orchestrator.mcp.calls))
        self.assertTrue(any(tool == "nmap_basic" for tool, _ in orchestrator.mcp.calls))

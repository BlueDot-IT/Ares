import json
import os
import re
import subprocess
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))


class AresCliYoloTests(unittest.TestCase):
    def _run_cli_help(self, *args: str) -> str:
        repo = Path(__file__).resolve().parents[1]
        env = dict(os.environ)
        env["PYTHONPATH"] = str(repo / "src")
        env["NO_COLOR"] = "1"
        result = subprocess.run(
            [sys.executable, "-m", "ares.cli", *args],
            cwd=repo,
            env=env,
            check=True,
            capture_output=True,
            text=True,
        )
        return re.sub(r"\x1b\[[0-9;]*m", "", result.stdout)

    def test_run_help_lists_yolo_flag(self):
        help_text = self._run_cli_help("run", "--help")
        self.assertIn("--yolo", help_text)

    def test_bare_ares_launches_tui(self):
        repo = Path(__file__).resolve().parents[1]
        env = dict(os.environ)
        env["PYTHONPATH"] = str(repo / "src")
        script = """
import json
from unittest.mock import patch
from ares.cli import app

with patch('ares.cli.launch_tui') as launch_tui:
    try:
        app(prog_name='ares')
        code = 0
    except SystemExit as exc:
        code = exc.code

print('RESULT_JSON=' + json.dumps({
    'called': launch_tui.call_args.kwargs if launch_tui.call_args else None,
    'code': code,
}))
"""
        result = subprocess.run(
            [sys.executable, "-c", script],
            cwd=repo,
            env=env,
            check=True,
            capture_output=True,
            text=True,
        )
        payload_line = next(line for line in result.stdout.splitlines() if line.startswith("RESULT_JSON="))
        payload = json.loads(payload_line.split("=", 1)[1])
        self.assertEqual(payload["code"], 0)
        self.assertEqual(payload["called"], {"refresh_interval": 0.5, "yolo_mode": False})

    def test_tui_help_lists_yolo_flag(self):
        help_text = self._run_cli_help("tui", "--help")
        self.assertIn("--yolo", help_text)


if __name__ == "__main__":
    unittest.main()

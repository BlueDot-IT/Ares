import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))


class AresCliGatewayTests(unittest.TestCase):
    def _run_cli(self, *args: str, env: dict[str, str]) -> str:
        repo = Path(__file__).resolve().parents[1]
        python_bin = repo / ".venv" / "bin" / "python"
        result = subprocess.run(
            [str(python_bin), "-m", "ares.cli", *args],
            cwd=repo,
            env=env,
            check=True,
            capture_output=True,
            text=True,
        )
        return result.stdout

    def test_gateway_command_reports_current_mode_and_persists_lan_settings(self):
        repo = Path(__file__).resolve().parents[1]
        with tempfile.TemporaryDirectory() as tmp:
            env = dict(os.environ)
            env["PYTHONPATH"] = str(repo / "src")
            env["ARES_HOME"] = tmp

            initial = self._run_cli("gateway-config", env=env)
            self.assertIn("mode: loopback", initial)
            self.assertIn("host: 127.0.0.1", initial)

            updated = self._run_cli("gateway-config", "--mode", "lan", "--port", "19991", env=env)
            self.assertIn("mode: lan", updated)
            self.assertIn("host: 0.0.0.0", updated)
            self.assertIn("port: 19991", updated)
            self.assertIn("bind: http://0.0.0.0:19991", updated)

            saved = json.loads((Path(tmp) / "config.json").read_text(encoding="utf-8"))
            self.assertEqual(saved["gateway"]["mode"], "lan")
            self.assertEqual(saved["gateway"]["host"], "0.0.0.0")
            self.assertEqual(saved["gateway"]["port"], 19991)

    def test_gateway_config_supports_exposed_mode_and_custom_host_override(self):
        repo = Path(__file__).resolve().parents[1]
        with tempfile.TemporaryDirectory() as tmp:
            env = dict(os.environ)
            env["PYTHONPATH"] = str(repo / "src")
            env["ARES_HOME"] = tmp

            updated = self._run_cli(
                "gateway-config",
                "--mode",
                "exposed",
                "--host",
                "10.10.10.5",
                env=env,
            )
            self.assertIn("mode: exposed", updated)
            self.assertIn("host: 10.10.10.5", updated)
            self.assertIn("exposure: direct", updated)

            saved = json.loads((Path(tmp) / "config.json").read_text(encoding="utf-8"))
            self.assertEqual(saved["gateway"]["mode"], "exposed")
            self.assertEqual(saved["gateway"]["host"], "10.10.10.5")


if __name__ == "__main__":
    unittest.main()

import json
import os
import subprocess
import sys
import tempfile
import threading
import unittest
import urllib.request
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))


class AresCliGatewayTests(unittest.TestCase):
    def _json_request(self, url: str, *, method: str = "GET", payload: dict | None = None, headers: dict[str, str] | None = None):
        data = None if payload is None else json.dumps(payload).encode("utf-8")
        request = urllib.request.Request(
            url,
            data=data,
            headers={"Content-Type": "application/json", **(headers or {})},
            method=method,
        )
        return urllib.request.urlopen(request, timeout=2)

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
            env["APP_HOME"] = tmp

            initial = self._run_cli("gateway-config", env=env)
            self.assertIn("mode: loopback", initial)
            self.assertIn("host: 127.0.0.1", initial)

            updated = self._run_cli("gateway-config", "--mode", "lan", "--port", "19991", env=env)
            self.assertIn("mode: lan", updated)
            self.assertIn("host: 0.0.0.0", updated)
            self.assertIn("port: 19991", updated)
            self.assertIn("bind: http://0.0.0.0:19991", updated)
            self.assertIn("exposure: lan-only", updated)

            saved = json.loads((Path(tmp) / "config.json").read_text(encoding="utf-8"))
            self.assertEqual(saved["gateway"]["mode"], "lan")
            self.assertEqual(saved["gateway"]["host"], "0.0.0.0")
            self.assertEqual(saved["gateway"]["port"], 19991)

    def test_gateway_config_supports_exposed_mode_and_custom_host_override(self):
        repo = Path(__file__).resolve().parents[1]
        with tempfile.TemporaryDirectory() as tmp:
            env = dict(os.environ)
            env["PYTHONPATH"] = str(repo / "src")
            env["APP_HOME"] = tmp

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
            self.assertIn("exposure: remote", updated)

            saved = json.loads((Path(tmp) / "config.json").read_text(encoding="utf-8"))
            self.assertEqual(saved["gateway"]["mode"], "exposed")
            self.assertEqual(saved["gateway"]["host"], "10.10.10.5")

    def test_gateway_config_persists_auth_and_allowlist_settings(self):
        repo = Path(__file__).resolve().parents[1]
        with tempfile.TemporaryDirectory() as tmp:
            env = dict(os.environ)
            env["PYTHONPATH"] = str(repo / "src")
            env["APP_HOME"] = tmp

            updated = self._run_cli(
                "gateway-config",
                "--mode",
                "exposed",
                "--auth-enabled",
                "--operator-token",
                "operator-secret",
                "--allow-cidr",
                "127.0.0.1/32",
                "--allow-cidr",
                "10.0.0.0/8",
                env=env,
            )
            self.assertIn("auth_enabled: yes", updated)
            self.assertIn("allow_cidrs: 127.0.0.1/32, 10.0.0.0/8", updated)

            saved = json.loads((Path(tmp) / "config.json").read_text(encoding="utf-8"))
            self.assertTrue(saved["gateway"]["auth_enabled"])
            self.assertEqual(saved["gateway"]["operator_token"], "operator-secret")
            self.assertEqual(saved["gateway"]["allow_cidrs"], ["127.0.0.1/32", "10.0.0.0/8"])

    def test_gateway_config_warns_when_exposed_mode_has_no_auth(self):
        repo = Path(__file__).resolve().parents[1]
        with tempfile.TemporaryDirectory() as tmp:
            env = dict(os.environ)
            env["PYTHONPATH"] = str(repo / "src")
            env["APP_HOME"] = tmp

            updated = self._run_cli("gateway-config", "--mode", "exposed", "--auth-disabled", env=env)

        self.assertIn("mode: exposed", updated)
        self.assertIn("auth_enabled: no", updated)
        self.assertIn("WARNING: exposed gateway mode is unauthenticated", updated)

    def test_gateway_pair_command_issues_code_from_running_gateway(self):
        from ares.config.loader import save_gateway_config
        from ares.gateway import AresGateway, start_gateway_server

        repo = Path(__file__).resolve().parents[1]
        with tempfile.TemporaryDirectory() as tmp:
            home = Path(tmp)
            env = dict(os.environ)
            env["PYTHONPATH"] = str(repo / "src")
            env["APP_HOME"] = tmp
            save_gateway_config(
                home=home,
                mode="exposed",
                auth_enabled=True,
                operator_token="operator-secret",
                allow_cidrs=["127.0.0.1/32"],
            )
            gateway = AresGateway(home=home)
            server = start_gateway_server(gateway, host="0.0.0.0", port=0, mode="exposed")
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            try:
                port = server.server_address[1]
                save_gateway_config(
                    home=home,
                    mode="exposed",
                    port=port,
                    auth_enabled=True,
                    operator_token="operator-secret",
                    allow_cidrs=["127.0.0.1/32"],
                )
                output = self._run_cli("gateway-pair", "--label", "browser-laptop", env=env)
                self.assertIn("label: browser-laptop", output)
                code_line = next(line for line in output.splitlines() if line.startswith("code: "))
                code = code_line.split(": ", 1)[1].strip()
                paired = json.loads(
                    self._json_request(
                        f"http://127.0.0.1:{port}/api/auth/pair",
                        method="POST",
                        payload={"code": code},
                    ).read().decode("utf-8")
                )
            finally:
                server.shutdown()
                server.server_close()
                thread.join(timeout=2)

        self.assertTrue(paired["session_token"])


if __name__ == "__main__":
    unittest.main()

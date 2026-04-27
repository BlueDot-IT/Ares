import json
import sys
import tempfile
import threading
import types
import unittest
import urllib.error
import urllib.request
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))


class GatewayAuthTests(unittest.TestCase):
    def test_auth_manager_expires_pairing_codes_and_sessions(self):
        from ares.gateway_auth import GatewayAuthManager

        auth = GatewayAuthManager(auth_enabled=True, operator_token="operator-secret", session_ttl_seconds=0.05, pairing_ttl_seconds=0.05)
        expired_code = auth.issue_pairing_code(label="old")
        import time

        time.sleep(0.06)
        self.assertIsNone(auth.exchange_pairing_code(expired_code))

        fresh_code = auth.issue_pairing_code(label="new")
        session_token = auth.exchange_pairing_code(fresh_code)
        self.assertTrue(session_token)
        self.assertTrue(auth.validate_session(session_token))
        time.sleep(0.06)
        self.assertFalse(auth.validate_session(session_token))

    def _json_request(self, url: str, *, method: str = "GET", payload: dict | None = None, headers: dict[str, str] | None = None):
        data = None if payload is None else json.dumps(payload).encode("utf-8")
        request = urllib.request.Request(
            url,
            data=data,
            headers={"Content-Type": "application/json", **(headers or {})},
            method=method,
        )
        return urllib.request.urlopen(request, timeout=2)

    def test_exposed_mode_requires_auth_and_pairing_codes_issue_bearer_sessions(self):
        from ares.config.loader import AppConfig, GatewayConfig, LLMConfig, PolicyConfig
        from ares.gateway import AresGateway, start_gateway_server

        def fake_runner(**kwargs):
            kwargs["session_started_callback"](41)
            kwargs["event_callback"]({"type": "final_response", "final_response": "ok", "message": "ok"})
            return types.SimpleNamespace(final_response="ok", stop_reason="final_response")

        with tempfile.TemporaryDirectory() as tmp:
            config = AppConfig(
                home=Path(tmp),
                llm=LLMConfig(model="unit-model"),
                policy=PolicyConfig(max_risk="passive"),
                gateway=GatewayConfig(
                    mode="exposed",
                    host="127.0.0.1",
                    port=0,
                    exposure="remote",
                    auth_enabled=True,
                    operator_token="operator-secret",
                    allow_cidrs=("127.0.0.1/32",),
                ),
            )
            gateway = AresGateway(config=config, runner=fake_runner)
            pairing_code = gateway.issue_pairing_code(label="local-console")
            server = start_gateway_server(gateway, host="127.0.0.1", port=0, mode="exposed")
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            try:
                base = f"http://127.0.0.1:{server.server_address[1]}"
                with self.assertRaises(urllib.error.HTTPError) as denied:
                    urllib.request.urlopen(base + "/health", timeout=2)
                self.assertEqual(denied.exception.code, 401)

                pair_response = json.loads(
                    self._json_request(base + "/api/auth/pair", method="POST", payload={"code": pairing_code}).read().decode("utf-8")
                )
                session_token = pair_response["session_token"]

                health = json.loads(
                    self._json_request(
                        base + "/health",
                        headers={"Authorization": f"Bearer {session_token}"},
                    ).read().decode("utf-8")
                )
                self.assertEqual(health["status"], "ok")

                with self.assertRaises(urllib.error.HTTPError) as reused:
                    self._json_request(base + "/api/auth/pair", method="POST", payload={"code": pairing_code})
                self.assertEqual(reused.exception.code, 401)

                with self.assertRaises(urllib.error.HTTPError) as unauthenticated_issue:
                    self._json_request(base + "/api/auth/pairing-codes", method="POST", payload={"label": "browser"})
                self.assertEqual(unauthenticated_issue.exception.code, 401)

                login_response = json.loads(
                    self._json_request(
                        base + "/api/auth/login",
                        method="POST",
                        payload={"operator_token": "operator-secret"},
                    ).read().decode("utf-8")
                )
                operator_session = login_response["session_token"]
                issued = json.loads(
                    self._json_request(
                        base + "/api/auth/pairing-codes",
                        method="POST",
                        payload={"label": "browser"},
                        headers={"Authorization": f"Bearer {operator_session}"},
                    ).read().decode("utf-8")
                )
                browser_session = json.loads(
                    self._json_request(base + "/api/auth/pair", method="POST", payload={"code": issued["code"]}).read().decode("utf-8")
                )["session_token"]
                paired_health = json.loads(
                    self._json_request(
                        base + "/health",
                        headers={"Authorization": f"Bearer {browser_session}"},
                    ).read().decode("utf-8")
                )
                self.assertEqual(paired_health["status"], "ok")
            finally:
                server.shutdown()
                server.server_close()
                thread.join(timeout=2)

    def test_gateway_allowlist_and_audit_log_cover_login_and_run_submission(self):
        from ares.config.loader import AppConfig, GatewayConfig, LLMConfig, PolicyConfig
        from ares.gateway import AresGateway, gateway_allowlist_allows_client, start_gateway_server

        def fake_runner(**kwargs):
            kwargs["session_started_callback"](55)
            kwargs["event_callback"]({"type": "final_response", "final_response": "done", "message": "done"})
            return types.SimpleNamespace(final_response="done", stop_reason="final_response")

        self.assertTrue(gateway_allowlist_allows_client(("127.0.0.1/32",), "127.0.0.1"))
        self.assertFalse(gateway_allowlist_allows_client(("127.0.0.1/32",), "127.0.0.2"))
        self.assertFalse(gateway_allowlist_allows_client(("10.0.0.0/8",), "8.8.8.8"))

        with tempfile.TemporaryDirectory() as tmp:
            home = Path(tmp)
            config = AppConfig(
                home=home,
                llm=LLMConfig(model="unit-model"),
                policy=PolicyConfig(max_risk="passive"),
                gateway=GatewayConfig(
                    mode="exposed",
                    host="127.0.0.1",
                    port=0,
                    exposure="remote",
                    auth_enabled=True,
                    operator_token="operator-secret",
                    allow_cidrs=("127.0.0.1/32",),
                ),
            )
            gateway = AresGateway(config=config, runner=fake_runner)
            server = start_gateway_server(gateway, host="127.0.0.1", port=0, mode="exposed")
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            try:
                base = f"http://127.0.0.1:{server.server_address[1]}"
                login = json.loads(
                    self._json_request(
                        base + "/api/auth/login",
                        method="POST",
                        payload={"operator_token": "operator-secret"},
                    ).read().decode("utf-8")
                )
                session_token = login["session_token"]
                created = json.loads(
                    self._json_request(
                        base + "/api/runs",
                        method="POST",
                        payload={"prompt": "scan target", "target": "127.0.0.1"},
                        headers={"Authorization": f"Bearer {session_token}"},
                    ).read().decode("utf-8")
                )
                gateway.wait_for_run(created["id"], timeout=2.0)
            finally:
                server.shutdown()
                server.server_close()
                thread.join(timeout=2)

            audit_path = home / "gateway-audit.jsonl"
            audit_lines = [json.loads(line) for line in audit_path.read_text(encoding="utf-8").splitlines() if line.strip()]
            audit_mode = audit_path.stat().st_mode & 0o777

        self.assertTrue(any(item["event"] == "auth_login_succeeded" for item in audit_lines))
        self.assertTrue(any(item["event"] == "run_submitted" for item in audit_lines))
        self.assertEqual(audit_mode, 0o600)


if __name__ == "__main__":
    unittest.main()

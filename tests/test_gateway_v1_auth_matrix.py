import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))


class GatewayV1AuthMatrixTests(unittest.TestCase):
    def test_auth_required_in_every_mode_when_enabled(self):
        from ares.gateway_auth import GatewayAuthManager

        enabled = GatewayAuthManager(auth_enabled=True, operator_token="unit-token")
        disabled = GatewayAuthManager(auth_enabled=False, operator_token="unit-token")

        self.assertTrue(enabled.auth_required(mode="loopback"))
        self.assertTrue(enabled.auth_required(mode="lan"))
        self.assertTrue(enabled.auth_required(mode="exposed"))
        self.assertFalse(disabled.auth_required(mode="exposed"))

    def test_operator_login_and_bearer_parsing(self):
        from ares.gateway_auth import GatewayAuthManager, extract_bearer_token

        auth = GatewayAuthManager(auth_enabled=True, operator_token="unit-token")

        self.assertIsNone(auth.login("mismatch"))
        token = auth.login("unit-token")
        self.assertIsNotNone(token)
        self.assertTrue(auth.validate_session(token))
        self.assertEqual(extract_bearer_token(f"Bearer {token}"), token)
        self.assertEqual(extract_bearer_token(f"bearer {token}"), token)
        self.assertIsNone(extract_bearer_token("Basic nope"))

    def test_pairing_codes_are_single_use(self):
        from ares.gateway_auth import GatewayAuthManager

        auth = GatewayAuthManager(auth_enabled=True, operator_token="unit-token")
        code = auth.issue_pairing_code(label="laptop")

        first_token = auth.exchange_pairing_code(code)
        second_token = auth.exchange_pairing_code(code)

        self.assertIsNotNone(first_token)
        self.assertTrue(auth.validate_session(first_token))
        self.assertIsNone(second_token)

    def test_ttl_is_enforced(self):
        from ares.gateway_auth import GatewayAuthManager

        pairing_auth = GatewayAuthManager(auth_enabled=True, operator_token="unit-token", pairing_ttl_seconds=0)
        code = pairing_auth.issue_pairing_code(label="expired")
        self.assertIsNone(pairing_auth.exchange_pairing_code(code))

        session_auth = GatewayAuthManager(auth_enabled=True, operator_token="unit-token", session_ttl_seconds=0)
        token = session_auth.login("unit-token")
        self.assertIsNotNone(token)
        self.assertFalse(session_auth.validate_session(token))

    def test_repeated_failed_logins_block_the_window(self):
        from ares.gateway_auth import GatewayAuthManager

        auth = GatewayAuthManager(
            auth_enabled=True,
            operator_token="unit-token",
            failure_window_seconds=60,
            max_failed_logins=2,
        )

        self.assertIsNone(auth.login("mismatch-1"))
        self.assertIsNone(auth.login("mismatch-2"))
        self.assertIsNone(auth.login("unit-token"))

    def test_gateway_allowlist_accepts_only_configured_cidrs(self):
        from ares.gateway import gateway_allowlist_allows_client

        allowlist = ("127.0.0.1/32", "192.168.10.0/24", "2001:db8::/32")

        self.assertTrue(gateway_allowlist_allows_client(allowlist, "127.0.0.1"))
        self.assertTrue(gateway_allowlist_allows_client(allowlist, "192.168.10.25"))
        self.assertTrue(gateway_allowlist_allows_client(allowlist, "2001:db8::42"))
        self.assertFalse(gateway_allowlist_allows_client(allowlist, "192.168.11.25"))
        self.assertFalse(gateway_allowlist_allows_client(allowlist, "8.8.8.8"))
        self.assertFalse(gateway_allowlist_allows_client(("not-a-cidr",), "127.0.0.1"))


if __name__ == "__main__":
    unittest.main()

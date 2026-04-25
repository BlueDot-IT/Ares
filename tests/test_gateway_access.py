import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))


class GatewayAccessPolicyTests(unittest.TestCase):
    def test_loopback_mode_accepts_only_loopback_clients(self):
        from ares.gateway import gateway_mode_allows_client

        self.assertTrue(gateway_mode_allows_client("loopback", "127.0.0.1"))
        self.assertTrue(gateway_mode_allows_client("loopback", "::1"))
        self.assertFalse(gateway_mode_allows_client("loopback", "192.168.1.25"))

    def test_lan_mode_accepts_local_network_clients_but_rejects_public_addresses(self):
        from ares.gateway import gateway_mode_allows_client

        self.assertTrue(gateway_mode_allows_client("lan", "127.0.0.1"))
        self.assertTrue(gateway_mode_allows_client("lan", "192.168.1.25"))
        self.assertTrue(gateway_mode_allows_client("lan", "10.0.4.12"))
        self.assertTrue(gateway_mode_allows_client("lan", "172.20.1.9"))
        self.assertTrue(gateway_mode_allows_client("lan", "169.254.10.7"))
        self.assertTrue(gateway_mode_allows_client("lan", "fd00::42"))
        self.assertFalse(gateway_mode_allows_client("lan", "8.8.8.8"))
        self.assertFalse(gateway_mode_allows_client("lan", "2001:4860:4860::8888"))

    def test_exposed_mode_allows_public_clients(self):
        from ares.gateway import gateway_mode_allows_client

        self.assertTrue(gateway_mode_allows_client("exposed", "8.8.8.8"))
        self.assertTrue(gateway_mode_allows_client("exposed", "2001:4860:4860::8888"))


if __name__ == "__main__":
    unittest.main()

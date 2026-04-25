import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))


class GatewayConfigModeTests(unittest.TestCase):
    def test_gateway_mode_presets_resolve_expected_hosts(self):
        from ares.config.loader import gateway_mode_defaults, resolve_gateway_mode

        self.assertEqual(resolve_gateway_mode("loopback"), "loopback")
        self.assertEqual(gateway_mode_defaults("loopback")["host"], "127.0.0.1")
        self.assertEqual(gateway_mode_defaults("lan")["host"], "0.0.0.0")
        self.assertEqual(gateway_mode_defaults("exposed")["host"], "0.0.0.0")
        self.assertEqual(gateway_mode_defaults("exposed")["exposure"], "direct")

    def test_save_gateway_config_persists_mode_host_and_port(self):
        from ares.config.loader import load_config, save_gateway_config

        with tempfile.TemporaryDirectory() as tmp:
            home = Path(tmp)
            save_gateway_config(home=home, mode="lan", port=18888)
            cfg = load_config(home)

        self.assertEqual(cfg.gateway.mode, "lan")
        self.assertEqual(cfg.gateway.host, "0.0.0.0")
        self.assertEqual(cfg.gateway.port, 18888)


if __name__ == "__main__":
    unittest.main()

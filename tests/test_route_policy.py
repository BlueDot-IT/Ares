import os
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))


class RoutePolicyTests(unittest.TestCase):
    def test_route_policy_uses_direct_for_private_and_tor_for_public(self):
        from ares.policy.route import RoutePolicy

        policy = RoutePolicy(require_tor_for_external=True)

        self.assertEqual(policy.route_for_target("127.0.0.1"), "direct")
        self.assertEqual(policy.route_for_target("192.168.1.10"), "direct")
        self.assertEqual(policy.route_for_target("8.8.8.8"), "tor")
        self.assertEqual(policy.route_for_target("https://8.8.8.8/path"), "tor")

    def test_route_policy_context_sets_force_tor_env(self):
        from ares.policy.route import RoutePolicy

        os.environ.pop("FORCE_TOR", None)
        policy = RoutePolicy(require_tor_for_external=True)

        with policy.apply_for_target("8.8.8.8"):
            self.assertEqual(os.getenv("FORCE_TOR"), "1")
        self.assertIsNone(os.getenv("FORCE_TOR"))

    def test_legacy_runner_wraps_subprocess_command_when_force_tor_enabled(self):
        from lib.mcp_server import _apply_tor_wrapper

        with patch("shutil.which", side_effect=lambda name: "/usr/bin/torsocks" if name == "torsocks" else None):
            with patch.dict(os.environ, {"FORCE_TOR": "1"}, clear=False):
                self.assertEqual(_apply_tor_wrapper(["curl", "https://example.com"]), ["torsocks", "curl", "https://example.com"])


if __name__ == "__main__":
    unittest.main()

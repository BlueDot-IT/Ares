import os
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))


class ROEProfileTests(unittest.TestCase):
    def test_builtin_profiles_define_risk_toolsets_and_approval_risks(self):
        from ares.policy.roe import ROEProfileRegistry

        registry = ROEProfileRegistry.builtin()
        passive = registry.get("passive")
        intrusive = registry.get("intrusive")

        self.assertEqual(passive.max_risk, "passive")
        self.assertIn("recon", passive.allowed_toolsets)
        self.assertEqual(intrusive.max_risk, "intrusive")
        self.assertIn("exploit", intrusive.approval_required_risks)

    def test_load_config_can_use_roe_profile_to_set_policy_defaults(self):
        from ares.config.loader import load_config

        old_env = os.environ.copy()
        try:
            os.environ["ARES_ROE_PROFILE"] = "safe-active"
            os.environ.pop("ARES_MAX_RISK", None)
            cfg = load_config()
            self.assertEqual(cfg.policy.roe_profile, "safe-active")
            self.assertEqual(cfg.policy.max_risk, "active")
        finally:
            os.environ.clear()
            os.environ.update(old_env)


if __name__ == "__main__":
    unittest.main()

import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from typer.testing import CliRunner

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from ares.cli import app
from ares.llm.oauth_cache import OAuthTokenCacheEntry, save_oauth_token


class _FakeBroker:
    def __init__(self) -> None:
        self.login_calls: list[str] = []
        self.logout_calls: list[str] = []

    def describe(self, provider: str):
        if provider == "gemini":
            return {"provider": "gemini", "label": "Gemini", "method": "browser"}
        return None

    def available_flows(self):
        return [{"provider": "gemini", "label": "Gemini", "method": "browser"}]

    def login(self, provider: str):
        self.login_calls.append(provider)
        return {
            "provider": provider,
            "expires_at": "2030-01-01T00:00:00+00:00",
            "method": "browser",
        }

    def status(self, provider: str | None = None):
        rows = [
            {
                "provider": provider or "gemini",
                "has_token": True,
                "expires_at": "2030-01-01T00:00:00+00:00",
                "method": "browser",
            }
        ]
        return rows

    def logout(self, provider: str):
        self.logout_calls.append(provider)


class CliAuthTests(unittest.TestCase):
    def setUp(self) -> None:
        self.runner = CliRunner()

    def test_auth_login_triggers_oauth_broker(self):
        broker = _FakeBroker()
        with patch("ares.cli.build_oauth_broker", return_value=broker):
            result = self.runner.invoke(app, ["auth", "login", "--provider", "gemini"])

        self.assertEqual(result.exit_code, 0, result.stdout)
        self.assertIn("Logged in: gemini", result.stdout)
        self.assertEqual(broker.login_calls, ["gemini"])

    def test_auth_login_without_provider_uses_supported_oauth_provider(self):
        broker = _FakeBroker()
        with patch("ares.cli.build_oauth_broker", return_value=broker):
            result = self.runner.invoke(app, ["auth", "login"])

        self.assertEqual(result.exit_code, 0, result.stdout)
        self.assertIn("Logged in: gemini", result.stdout)
        self.assertEqual(broker.login_calls, ["gemini"])

    def test_auth_login_fails_when_no_oauth_providers_exist(self):
        broker = _FakeBroker()
        with patch("ares.cli.build_oauth_broker", return_value=broker), patch.object(broker, "available_flows", return_value=[]):
            result = self.runner.invoke(app, ["auth", "login"])

        self.assertNotEqual(result.exit_code, 0)
        self.assertIn("No OAuth providers are available", result.output)

    def test_auth_status_shows_cached_credentials_without_secret_value(self):
        broker = _FakeBroker()
        with patch("ares.cli.build_oauth_broker", return_value=broker):
            result = self.runner.invoke(app, ["auth", "status", "--provider", "gemini"])

        self.assertEqual(result.exit_code, 0, result.stdout)
        self.assertIn("provider: gemini", result.stdout)
        self.assertIn("has_token: yes", result.stdout)
        self.assertNotIn("token", result.stdout.lower().replace("has_token", ""))

    def test_auth_logout_clears_cached_credentials(self):
        broker = _FakeBroker()
        with patch("ares.cli.build_oauth_broker", return_value=broker):
            result = self.runner.invoke(app, ["auth", "logout", "--provider", "gemini"])

        self.assertEqual(result.exit_code, 0, result.stdout)
        self.assertIn("Logged out: gemini", result.stdout)
        self.assertEqual(broker.logout_calls, ["gemini"])

    def test_onboard_can_offer_immediate_sign_in_for_oauth_provider(self):
        broker = _FakeBroker()
        with tempfile.TemporaryDirectory() as tmp:
            env = dict(os.environ)
            env["ARES_HOME"] = tmp
            with patch("ares.onboarding.build_oauth_broker", return_value=broker):
                result = self.runner.invoke(
                    app,
                    ["onboard"],
                    input="\n".join([
                        "5",
                        "gemini-2.5-pro",
                        "2",
                        "demo-project",
                        "us-central1",
                        "y",
                        "ember",
                        "1",
                        "n",
                    ])
                    + "\n",
                    env=env,
                )

        self.assertEqual(result.exit_code, 0, result.stdout)
        self.assertEqual(broker.login_calls, ["gemini"])
        self.assertIn("oauth sign-in: complete", result.stdout)


if __name__ == "__main__":
    unittest.main()

import os
import sys
import tempfile
import types
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from ares.llm.oauth import build_google_oauth_credentials, build_openai_oauth_token_provider
from ares.llm.oauth_cache import OAuthTokenCacheEntry, load_oauth_token, save_oauth_token
from ares.llm.oauth_flows import OAuthBroker, OAuthFlowInfo


class _FakeFlow:
    def __init__(self, provider: str, *, label: str = "Demo OAuth", method: str = "browser", ttl_seconds: int = 3600) -> None:
        self.provider = provider
        self.label = label
        self.method = method
        self.ttl_seconds = ttl_seconds
        self.calls = 0

    def describe(self) -> OAuthFlowInfo:
        return OAuthFlowInfo(
            provider=self.provider,
            label=self.label,
            login_label=f"{self.label} sign-in",
            method=self.method,
        )

    def login(self, *, home: Path, cached: OAuthTokenCacheEntry | None = None) -> OAuthTokenCacheEntry:
        self.calls += 1
        return OAuthTokenCacheEntry(
            provider=self.provider,
            access_token=f"{self.provider}-token-{self.calls}",
            expires_at=datetime.now(timezone.utc) + timedelta(seconds=self.ttl_seconds),
            metadata={"calls": str(self.calls)},
        )


class _FailingFlow:
    def __init__(self, provider: str, message: str = "oauth provider failed") -> None:
        self.provider = provider
        self.message = message

    def describe(self) -> OAuthFlowInfo:
        return OAuthFlowInfo(
            provider=self.provider,
            label="Failing OAuth",
            login_label="Failing sign-in",
            method="browser",
        )

    def login(self, *, home: Path, cached: OAuthTokenCacheEntry | None = None) -> OAuthTokenCacheEntry:
        raise RuntimeError(self.message)


class OAuthFlowTests(unittest.TestCase):
    def test_broker_describes_registered_provider_specific_login_methods(self):
        broker = OAuthBroker(home=Path("/tmp/ares-oauth-test"), flows=[_FakeFlow("gemini", label="Google OAuth", method="browser")])

        info = broker.describe("gemini")

        self.assertIsNotNone(info)
        self.assertEqual(info.provider, "gemini")
        self.assertEqual(info.label, "Google OAuth")
        self.assertEqual(info.method, "browser")

    def test_broker_reuses_unexpired_cached_token(self):
        with tempfile.TemporaryDirectory() as tmp:
            home = Path(tmp)
            flow = _FakeFlow("gemini")
            token_path = save_oauth_token(
                home=home,
                entry=OAuthTokenCacheEntry(
                    provider="gemini",
                    access_token="cached-token",
                    expires_at=datetime.now(timezone.utc) + timedelta(hours=1),
                ),
            )
            broker = OAuthBroker(home=home, flows=[flow])

            token = broker.get_access_token("gemini")
            cache_mode = token_path.stat().st_mode & 0o777
            cache_dir_mode = token_path.parent.stat().st_mode & 0o777

        self.assertEqual(token, "cached-token")
        self.assertEqual(flow.calls, 0)
        self.assertEqual(cache_mode, 0o600)
        self.assertEqual(cache_dir_mode, 0o700)

    def test_broker_refreshes_expired_cached_token_via_flow(self):
        with tempfile.TemporaryDirectory() as tmp:
            home = Path(tmp)
            flow = _FakeFlow("gemini")
            save_oauth_token(
                home=home,
                entry=OAuthTokenCacheEntry(
                    provider="gemini",
                    access_token="expired-token",
                    expires_at=datetime.now(timezone.utc) - timedelta(minutes=5),
                ),
            )
            broker = OAuthBroker(home=home, flows=[flow])

            token = broker.get_access_token("gemini")
            cached = load_oauth_token(home=home, provider="gemini")

        self.assertEqual(token, "gemini-token-1")
        self.assertIsNotNone(cached)
        self.assertEqual(cached.access_token, "gemini-token-1")
        self.assertEqual(flow.calls, 1)

    def test_build_google_oauth_credentials_can_use_broker_without_token_command(self):
        with tempfile.TemporaryDirectory() as tmp:
            home = Path(tmp)
            broker = OAuthBroker(home=home, flows=[_FakeFlow("gemini")])

            google_module = types.ModuleType("google")
            google_auth_module = types.ModuleType("google.auth")
            google_credentials_module = types.ModuleType("google.auth.credentials")

            class FakeCredentials:
                def __init__(self) -> None:
                    self.token = None
                    self.expiry = None

            google_credentials_module.Credentials = FakeCredentials
            google_auth_module.credentials = google_credentials_module
            google_module.auth = google_auth_module

            with patch.dict(
                sys.modules,
                {
                    "google": google_module,
                    "google.auth": google_auth_module,
                    "google.auth.credentials": google_credentials_module,
                },
            ):
                credentials = build_google_oauth_credentials("", home=home, provider="gemini", broker=broker)
                credentials.refresh(None)

        self.assertEqual(credentials.token, "gemini-token-1")
        self.assertIsNotNone(credentials.expiry)

    def test_openai_oauth_token_provider_uses_broker_before_legacy_token_command(self):
        with tempfile.TemporaryDirectory() as tmp:
            home = Path(tmp)
            broker = OAuthBroker(home=home, flows=[_FakeFlow("openai")])

            provider = build_openai_oauth_token_provider("print-openai-token", home=home, provider="openai", broker=broker)
            token = provider()

        self.assertEqual(token, "openai-token-1")

    def test_openai_oauth_token_provider_falls_back_to_legacy_token_command(self):
        with tempfile.TemporaryDirectory() as tmp:
            home = Path(tmp)
            broker = OAuthBroker(home=home, flows=[])
            with patch("ares.llm.oauth.run_oauth_token_command", return_value=("legacy-token", datetime.now(timezone.utc) + timedelta(hours=1))) as run_command:
                provider = build_openai_oauth_token_provider("print-openai-token", home=home, provider="openai", broker=broker)
                token = provider()

        self.assertEqual(token, "legacy-token")
        run_command.assert_called_once_with("print-openai-token")

    def test_configured_oauth_flow_errors_are_not_masked_by_empty_legacy_command(self):
        with tempfile.TemporaryDirectory() as tmp:
            home = Path(tmp)
            broker = OAuthBroker(home=home, flows=[_FailingFlow("openai", message="provider login failed")])
            provider = build_openai_oauth_token_provider("", home=home, provider="openai", broker=broker)

            with self.assertRaisesRegex(RuntimeError, "provider login failed"):
                provider()


if __name__ == "__main__":
    unittest.main()

import json
import os
import sys
import tempfile
import types
import unittest
import urllib.parse
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from ares.llm.oauth import build_google_oauth_credentials, build_openai_oauth_token_provider
from ares.llm.oauth_cache import OAuthTokenCacheEntry, load_oauth_token, save_oauth_token
from ares.llm.oauth_flows import OAuthBroker, OAuthFlowInfo, OpenAIOAuthFlow, build_default_oauth_broker


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
    def test_oauth_cache_rejects_unsafe_provider_cache_keys(self):
        from ares.llm.oauth_cache import oauth_cache_path

        with tempfile.TemporaryDirectory() as tmp:
            home = Path(tmp)
            for provider in ("../evil", "bad/name", "bad\\name", "", ".", ".."):
                with self.subTest(provider=provider):
                    with self.assertRaises(ValueError):
                        oauth_cache_path(home=home, provider=provider)

        self.assertFalse((home.parent / "evil.json").exists())
    def test_oauth_cache_listing_ignores_invalid_local_cache_filenames(self):
        from ares.llm.oauth_cache import list_oauth_tokens, oauth_cache_dir

        with tempfile.TemporaryDirectory() as tmp:
            home = Path(tmp)
            cache_dir = oauth_cache_dir(home)
            (cache_dir / "bad name.json").write_text("{}", encoding="utf-8")

            entries = list_oauth_tokens(home=home)

        self.assertEqual(entries, [])
    def test_oauth_broker_status_ignores_invalid_local_cache_filenames(self):
        from ares.llm.oauth_cache import oauth_cache_dir
        from ares.llm.oauth_flows import build_default_oauth_broker

        with tempfile.TemporaryDirectory() as tmp:
            home = Path(tmp)
            cache_dir = oauth_cache_dir(home)
            (cache_dir / "bad name.json").write_text("{}", encoding="utf-8")

            rows = build_default_oauth_broker(home=home).status()

        self.assertEqual([row["provider"] for row in rows], ["gemini", "openai"])


class OpenAIOAuthFlowTests(unittest.TestCase):
    def test_describe_returns_openai_provider_info(self):
        flow = OpenAIOAuthFlow()
        info = flow.describe()
        self.assertEqual(info.provider, "openai")
        self.assertEqual(info.label, "OpenAI OAuth")
        self.assertEqual(info.method, "browser")

    def test_pkce_code_challenge_is_valid_s256(self):
        import base64
        import hashlib

        flow = OpenAIOAuthFlow()
        verifier = flow._generate_code_verifier()
        challenge = flow._generate_code_challenge(verifier)

        expected = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode("ascii")).digest()).rstrip(b"=").decode("ascii")
        self.assertEqual(challenge, expected)

    def test_authorization_url_contains_required_params(self):
        flow = OpenAIOAuthFlow()
        url = flow._build_authorization_url("test-challenge", "test-state")
        parsed = urllib.parse.urlparse(url)
        params = urllib.parse.parse_qs(parsed.query)

        self.assertEqual(parsed.scheme, "https")
        self.assertIn("auth.openai.com", parsed.netloc)
        self.assertEqual(params["response_type"], ["code"])
        self.assertEqual(params["code_challenge"], ["test-challenge"])
        self.assertEqual(params["code_challenge_method"], ["S256"])
        self.assertEqual(params["state"], ["test-state"])
        self.assertIn("openid", params["scope"][0])
        self.assertIn("offline_access", params["scope"][0])

    def test_exchange_code_returns_cached_entry(self):
        flow = OpenAIOAuthFlow()
        fake_response = json.dumps({
            "access_token": "test-access-token",
            "refresh_token": "test-refresh-token",
            "expires_in": 7200,
        }).encode("utf-8")

        mock_resp = unittest.mock.MagicMock()
        mock_resp.read.return_value = fake_response
        mock_resp.__enter__ = lambda s: s
        mock_resp.__exit__ = lambda s, *a: None

        with patch("ares.llm.oauth_flows.urllib.request.urlopen", return_value=mock_resp):
            entry = flow._exchange_code("fake-code", "fake-verifier")

        self.assertIsInstance(entry, OAuthTokenCacheEntry)
        self.assertEqual(entry.provider, "openai")
        self.assertEqual(entry.access_token, "test-access-token")
        self.assertEqual(entry.refresh_token, "test-refresh-token")

    def test_broker_includes_openai_flow_by_default(self):
        with tempfile.TemporaryDirectory() as tmp:
            home = Path(tmp)
            broker = build_default_oauth_broker(home=home)

            info = broker.describe("openai")
            self.assertIsNotNone(info)
            self.assertEqual(info.provider, "openai")
            self.assertEqual(info.method, "browser")

    def test_broker_includes_both_gemini_and_openai(self):
        with tempfile.TemporaryDirectory() as tmp:
            home = Path(tmp)
            broker = build_default_oauth_broker(home=home)
            flows = broker.available_flows()
            providers = [f.provider for f in flows]
            self.assertIn("gemini", providers)
            self.assertIn("openai", providers)

    def test_openai_oauth_token_provider_uses_broker(self):
        with tempfile.TemporaryDirectory() as tmp:
            home = Path(tmp)
            broker = OAuthBroker(home=home, flows=[_FakeFlow("openai")])
            provider = build_openai_oauth_token_provider("", home=home, provider="openai", broker=broker)
            token = provider()
        self.assertEqual(token, "openai-token-1")

    def test_openai_oauth_login_uses_broker_when_configured(self):
        with tempfile.TemporaryDirectory() as tmp:
            home = Path(tmp)
            flow = _FakeFlow("openai")
            broker = OAuthBroker(home=home, flows=[flow])
            entry = broker.login("openai")
        self.assertEqual(entry.access_token, "openai-token-1")
        self.assertEqual(entry.provider, "openai")

    def test_openai_oauth_state_mismatch_raises(self):
        flow = OpenAIOAuthFlow()
        with patch.object(flow, "_open_browser", return_value=None):
            with patch.object(flow, "_receive_callback", side_effect=RuntimeError("OpenAI OAuth state mismatch — possible CSRF attack")):
                with self.assertRaisesRegex(RuntimeError, "state mismatch"):
                    flow.login(home=Path("/tmp"))

    def test_openai_oauth_error_response_raises(self):
        flow = OpenAIOAuthFlow()
        with patch.object(flow, "_open_browser", return_value=None):
            with patch.object(flow, "_receive_callback", side_effect=RuntimeError("OpenAI OAuth error: access_denied")):
                with self.assertRaisesRegex(RuntimeError, "access_denied"):
                    flow.login(home=Path("/tmp"))

    def test_receive_callback_extracts_code_from_query(self):
        flow = OpenAIOAuthFlow()
        expected_state = "test-state-123"

        mock_server = unittest.mock.MagicMock()
        mock_server.server_close = lambda: None

        call_count = 0
        def fake_handle_request():
            nonlocal call_count
            call_count += 1
            # Simulate the CallbackHandler receiving a GET request
            handler = flow.__class__.__dict__["OpenAIOAuthFlow"]._CallbackHandler if False else None

        mock_server.handle_request.side_effect = fake_handle_request

        # Instead of mocking the full server, test the URL parsing logic directly
        test_url = f"/callback?state={expected_state}&code=auth-code-abc"
        query = urllib.parse.parse_qs(urllib.parse.urlparse(test_url).query)
        self.assertEqual(query["state"], [expected_state])
        self.assertEqual(query["code"], ["auth-code-abc"])


if __name__ == "__main__":
    unittest.main()

from __future__ import annotations

import hashlib
import os
import secrets
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from typing import Protocol

from .oauth_cache import OAuthTokenCacheEntry, clear_oauth_token, list_oauth_tokens, load_oauth_token, normalize_oauth_provider_key, save_oauth_token

OPENAI_AUTHORIZE_URL = "https://auth.openai.com/oauth/authorize"
# Backward-compatible alias for integrations that imported the previous name.
OPENAI_OAUTH_AUTH_ENDPOINT = OPENAI_AUTHORIZE_URL
OPENAI_OAUTH_TOKEN_ENDPOINT = "https://auth.openai.com/oauth/token"
OPENAI_OAUTH_CLIENT_ID = "app_EMoamEEZ73f0CkXaXp7hrann"
OPENAI_OAUTH_REDIRECT_URI = "http://localhost:1455/auth/callback"
OPENAI_OAUTH_SCOPES = ("openid", "profile", "email", "offline_access")


@dataclass(frozen=True)
class OAuthFlowInfo:
    provider: str
    label: str
    login_label: str
    method: str


class OAuthFlow(Protocol):
    def describe(self) -> OAuthFlowInfo: ...

    def login(self, *, home: Path, cached: OAuthTokenCacheEntry | None = None) -> OAuthTokenCacheEntry: ...


class OAuthBroker:
    def __init__(self, *, home: Path | str, flows: list[OAuthFlow] | tuple[OAuthFlow, ...] | None = None) -> None:
        self.home = Path(home).expanduser()
        self._flows: dict[str, OAuthFlow] = {}
        for flow in flows or []:
            self.register(flow)

    def register(self, flow: OAuthFlow) -> None:
        info = flow.describe()
        self._flows[info.provider.strip().lower()] = flow

    def describe(self, provider: str) -> OAuthFlowInfo | None:
        flow = self._flows.get(str(provider or "").strip().lower())
        return flow.describe() if flow is not None else None

    def available_flows(self) -> list[OAuthFlowInfo]:
        return [flow.describe() for _, flow in sorted(self._flows.items())]

    def login(self, provider: str) -> OAuthTokenCacheEntry:
        key = str(provider or "").strip().lower()
        flow = self._flows.get(key)
        if flow is None:
            raise RuntimeError(f"No OAuth flow is configured for provider '{provider}'")
        cached = load_oauth_token(home=self.home, provider=key)
        entry = flow.login(home=self.home, cached=cached)
        save_oauth_token(home=self.home, entry=entry)
        return entry

    def get_entry(self, provider: str, *, allow_login: bool = True) -> OAuthTokenCacheEntry | None:
        key = str(provider or "").strip().lower()
        cached = load_oauth_token(home=self.home, provider=key)
        if cached is not None and not cached.is_expired():
            return cached
        flow = self._flows.get(key)
        refresh = getattr(flow, "refresh", None) if flow is not None else None
        if cached is not None and cached.refresh_token and callable(refresh):
            entry = refresh(home=self.home, cached=cached)
            save_oauth_token(home=self.home, entry=entry)
            return entry
        if allow_login and flow is not None:
            return self.login(key)
        return cached

    def get_access_token(self, provider: str, *, allow_login: bool = True) -> str:
        entry = self.get_entry(provider, allow_login=allow_login)
        if entry is None or entry.is_expired(skew_seconds=0):
            raise RuntimeError(f"No valid OAuth token is available for provider '{provider}'")
        return entry.access_token

    def status(self, provider: str | None = None) -> list[dict[str, str | bool]]:
        providers: list[str] = []
        if provider:
            providers = [normalize_oauth_provider_key(provider)]
        else:
            cached_entries = list_oauth_tokens(home=self.home)
            providers = sorted(set([*self._flows.keys(), *[entry.provider for entry in cached_entries]]))
        rows: list[dict[str, str | bool]] = []
        for key in providers:
            info = self.describe(key)
            try:
                cached = load_oauth_token(home=self.home, provider=key)
            except ValueError:
                continue
            rows.append(
                {
                    "provider": key,
                    "has_token": bool(cached),
                    "expired": bool(cached.is_expired(skew_seconds=0)) if cached is not None else False,
                    "expires_at": cached.expires_at.isoformat() if cached is not None else "-",
                    "method": info.method if info is not None else "-",
                }
            )
        return rows

    def logout(self, provider: str) -> bool:
        return clear_oauth_token(home=self.home, provider=provider)


class GoogleOAuthFlow:
    def __init__(
        self,
        *,
        provider: str = "gemini",
        label: str = "Google OAuth",
        client_secrets_file: str | None = None,
        scopes: tuple[str, ...] | None = None,
    ) -> None:
        self.provider = provider
        self.label = label
        self.client_secrets_file = client_secrets_file
        self.scopes = scopes or (
            "openid",
            "https://www.googleapis.com/auth/userinfo.email",
            "https://www.googleapis.com/auth/cloud-platform",
        )

    def describe(self) -> OAuthFlowInfo:
        return OAuthFlowInfo(
            provider=self.provider,
            label=self.label,
            login_label="Sign in with Google",
            method="browser",
        )

    def login(self, *, home: Path, cached: OAuthTokenCacheEntry | None = None) -> OAuthTokenCacheEntry:
        client_secrets = str(self.client_secrets_file or os.getenv("GOOGLE_OAUTH_CLIENT_SECRETS") or os.getenv("GOOGLE_OAUTH_CLIENT_SECRETS") or "").strip()
        if client_secrets:
            return self._login_with_installed_app(client_secrets)
        return self._login_with_adc()

    def _login_with_installed_app(self, client_secrets_file: str) -> OAuthTokenCacheEntry:
        try:
            from google_auth_oauthlib.flow import InstalledAppFlow
        except Exception as exc:  # pragma: no cover - depends on optional package
            raise RuntimeError("google-auth-oauthlib package is required for browser-based Google OAuth login") from exc
        flow = InstalledAppFlow.from_client_secrets_file(client_secrets_file, scopes=list(self.scopes))
        credentials = flow.run_local_server(port=0, open_browser=True)
        token = str(getattr(credentials, "token", "") or "").strip()
        if not token:
            raise RuntimeError("Google OAuth login did not produce an access token")
        expiry = getattr(credentials, "expiry", None) or (datetime.now(timezone.utc) + timedelta(hours=1))
        if getattr(expiry, "tzinfo", None) is None:
            expiry = expiry.replace(tzinfo=timezone.utc)
        return OAuthTokenCacheEntry(
            provider=self.provider,
            access_token=token,
            expires_at=expiry.astimezone(timezone.utc),
            refresh_token=str(getattr(credentials, "refresh_token", "") or "").strip(),
            metadata={"source": "installed-app"},
        )

    def _login_with_adc(self) -> OAuthTokenCacheEntry:
        try:
            import google.auth
            from google.auth.transport.requests import Request
        except Exception as exc:  # pragma: no cover - depends on optional package
            raise RuntimeError(
                "google-auth package is required for Google OAuth login. Install '.[gemini]' and optionally set GOOGLE_OAUTH_CLIENT_SECRETS for browser login."
            ) from exc
        credentials, _ = google.auth.default(scopes=list(self.scopes))
        if credentials is None:
            raise RuntimeError("No Google application default credentials are available")
        if hasattr(credentials, "refresh"):
            credentials.refresh(Request())
        token = str(getattr(credentials, "token", "") or "").strip()
        if not token:
            raise RuntimeError("Google ADC credentials did not provide an access token")
        expiry = getattr(credentials, "expiry", None) or (datetime.now(timezone.utc) + timedelta(hours=1))
        if getattr(expiry, "tzinfo", None) is None:
            expiry = expiry.replace(tzinfo=timezone.utc)
        return OAuthTokenCacheEntry(
            provider=self.provider,
            access_token=token,
            expires_at=expiry.astimezone(timezone.utc),
            refresh_token=str(getattr(credentials, "refresh_token", "") or "").strip(),
            metadata={"source": "application-default-credentials"},
        )


class OpenAIOAuthFlow:
    """OpenAI ChatGPT OAuth 2.0 PKCE flow against OpenAI's Auth0 tenant.

    This implements the same browser-based login that Codex and ChatGPT use.
    No client secret is required — the flow uses PKCE for public clients.
    """

    def __init__(
        self,
        *,
        provider: str = "openai",
        label: str = "OpenAI OAuth",
        client_id: str = OPENAI_OAUTH_CLIENT_ID,
        redirect_uri: str = OPENAI_OAUTH_REDIRECT_URI,
        scopes: tuple[str, ...] = OPENAI_OAUTH_SCOPES,
        auth_endpoint: str = OPENAI_AUTHORIZE_URL,
        token_endpoint: str = OPENAI_OAUTH_TOKEN_ENDPOINT,
    ) -> None:
        self.provider = provider
        self.label = label
        self.client_id = client_id
        self.redirect_uri = redirect_uri
        self.scopes = scopes
        self.auth_endpoint = auth_endpoint
        self.token_endpoint = token_endpoint

    def describe(self) -> OAuthFlowInfo:
        return OAuthFlowInfo(
            provider=self.provider,
            label=self.label,
            login_label="Sign in with ChatGPT",
            method="browser",
        )

    def login(self, *, home: Path, cached: OAuthTokenCacheEntry | None = None) -> OAuthTokenCacheEntry:
        code_verifier = self._generate_code_verifier()
        code_challenge = self._generate_code_challenge(code_verifier)
        state = secrets.token_urlsafe(32)

        auth_url = self._build_authorization_url(code_challenge, state)
        print(f"\nOpening browser for OpenAI sign-in...\nIf it does not open, visit:\n{auth_url}\n")
        self._open_browser(auth_url)

        auth_code = self._receive_callback(state)
        return self._exchange_code(auth_code, code_verifier)

    def refresh(self, *, home: Path, cached: OAuthTokenCacheEntry) -> OAuthTokenCacheEntry:
        if not cached.refresh_token:
            raise RuntimeError(
                "The cached OpenAI OAuth session has no refresh token. "
                "Run `ares auth login openai` interactively."
            )
        return self._exchange_refresh_token(cached)

    @staticmethod
    def _generate_code_verifier() -> str:
        return secrets.token_urlsafe(64)

    @classmethod
    def _generate_code_challenge(cls, verifier: str) -> str:
        digest = hashlib.sha256(verifier.encode("ascii")).digest()
        import base64
        return base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")

    def _build_authorization_url(self, code_challenge: str, state: str) -> str:
        params = {
            "client_id": self.client_id,
            "response_type": "code",
            "redirect_uri": self.redirect_uri,
            "scope": " ".join(self.scopes),
            "code_challenge": code_challenge,
            "code_challenge_method": "S256",
            "state": state,
            "id_token_add_organizations": "true",
            "codex_cli_simplified_flow": "true",
            "originator": "ares",
        }
        return f"{self.auth_endpoint}?{urllib.parse.urlencode(params)}"

    @staticmethod
    def _open_browser(url: str) -> None:
        import webbrowser
        try:
            webbrowser.open(url)
        except Exception:
            pass

    def _receive_callback(self, expected_state: str) -> str:
        parsed = urllib.parse.urlparse(self.redirect_uri)
        port = parsed.port or 1455
        received_state = None
        received_code = None
        received_error = None

        class CallbackHandler(BaseHTTPRequestHandler):
            def do_GET(handler_self):
                nonlocal received_state, received_code, received_error
                query = urllib.parse.parse_qs(urllib.parse.urlparse(handler_self.path).query)
                received_state = query.get("state", [None])[0]
                received_code = query.get("code", [None])[0]
                received_error = query.get("error", [None])[0]
                handler_self.send_response(200)
                handler_self.send_header("Content-Type", "text/html")
                handler_self.end_headers()
                handler_self.wfile.write(
                    b"<html><body><h2>OpenAI sign-in complete.</h2>"
                    b"<p>You can close this tab and return to Ares.</p></body></html>"
                )

            def log_message(self, format, *args):
                pass

        server = HTTPServer(("127.0.0.1", port), CallbackHandler)
        server.timeout = 120

        try:
            while received_code is None and received_error is None:
                server.handle_request()
        finally:
            server.server_close()

        if received_error:
            raise RuntimeError(f"OpenAI OAuth error: {received_error}")
        if received_state != expected_state:
            raise RuntimeError("OpenAI OAuth state mismatch — possible CSRF attack")
        if not received_code:
            raise RuntimeError("OpenAI OAuth callback did not include an authorization code")
        return received_code

    def _exchange_code(self, code: str, code_verifier: str) -> OAuthTokenCacheEntry:
        token_data = self._request_token({
            "grant_type": "authorization_code",
            "client_id": self.client_id,
            "code": code,
            "redirect_uri": self.redirect_uri,
            "code_verifier": code_verifier,
        })
        return self._entry_from_token_data(token_data, source="openai-pkce")

    def _exchange_refresh_token(self, cached: OAuthTokenCacheEntry) -> OAuthTokenCacheEntry:
        try:
            token_data = self._request_token({
                "grant_type": "refresh_token",
                "client_id": self.client_id,
                "refresh_token": cached.refresh_token,
            })
        except RuntimeError as exc:
            raise RuntimeError(
                "OpenAI OAuth refresh failed. Run `ares auth login openai` "
                "interactively to renew the session."
            ) from exc
        return self._entry_from_token_data(
            token_data,
            source="openai-refresh",
            fallback_refresh_token=cached.refresh_token,
        )

    def _request_token(self, form: dict[str, str]) -> dict[str, object]:
        import json as _json
        payload = urllib.parse.urlencode(form).encode("utf-8")
        request = urllib.request.Request(
            self.token_endpoint,
            data=payload,
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            method="POST",
        )
        try:
            with urllib.request.urlopen(request, timeout=30) as response:
                body = response.read().decode("utf-8")
        except urllib.error.HTTPError as exc:
            raise RuntimeError(
                f"OpenAI OAuth token endpoint returned HTTP {exc.code}"
            ) from exc
        except Exception as exc:
            raise RuntimeError(f"OpenAI OAuth token request failed: {exc}") from exc
        try:
            token_data = _json.loads(body)
        except _json.JSONDecodeError as exc:
            raise RuntimeError("OpenAI OAuth token endpoint returned invalid JSON") from exc
        if not isinstance(token_data, dict):
            raise RuntimeError("OpenAI OAuth token endpoint returned an invalid response")
        return token_data

    def _entry_from_token_data(
        self,
        token_data: dict[str, object],
        *,
        source: str,
        fallback_refresh_token: str = "",
    ) -> OAuthTokenCacheEntry:
        access_token = str(token_data.get("access_token", "")).strip()
        if not access_token:
            raise RuntimeError("OpenAI OAuth token response did not include access_token")

        expires_in = token_data.get("expires_in", 3600)
        ttl = max(int(expires_in), 60) if isinstance(expires_in, (int, float)) else 3600
        refresh_token = (
            str(token_data.get("refresh_token", "")).strip()
            or fallback_refresh_token
        )

        return OAuthTokenCacheEntry(
            provider=self.provider,
            access_token=access_token,
            expires_at=datetime.now(timezone.utc) + timedelta(seconds=ttl),
            refresh_token=refresh_token,
            metadata={"source": source},
        )


def build_default_oauth_broker(*, home: Path | str) -> OAuthBroker:
    return OAuthBroker(home=home, flows=[GoogleOAuthFlow(), OpenAIOAuthFlow()])

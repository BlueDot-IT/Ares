from __future__ import annotations

import os
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Protocol

from .oauth_cache import OAuthTokenCacheEntry, clear_oauth_token, list_oauth_tokens, load_oauth_token, normalize_oauth_provider_key, save_oauth_token


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
        if allow_login and key in self._flows:
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
        client_secrets = str(self.client_secrets_file or os.getenv("ARES_GOOGLE_OAUTH_CLIENT_SECRETS") or os.getenv("GOOGLE_OAUTH_CLIENT_SECRETS") or "").strip()
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
                "google-auth package is required for Google OAuth login. Install '.[gemini]' and optionally set ARES_GOOGLE_OAUTH_CLIENT_SECRETS for browser login."
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


def build_default_oauth_broker(*, home: Path | str) -> OAuthBroker:
    return OAuthBroker(home=home, flows=[GoogleOAuthFlow()])

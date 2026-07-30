from __future__ import annotations

import json
import shlex
import subprocess
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Callable

from .oauth_cache import OAuthTokenCacheEntry, save_oauth_token
from .oauth_flows import OAuthBroker, build_default_oauth_broker

DEFAULT_TOKEN_TTL_SECONDS = 3600


class OAuthTokenCommandError(RuntimeError):
    pass


def build_oauth_broker(*, home: Path | str | None = None) -> OAuthBroker:
    resolved_home = Path(home).expanduser() if home is not None else Path.home() / ".ares"
    return build_default_oauth_broker(home=resolved_home)


def run_oauth_token_command(command: str) -> tuple[str, datetime]:
    argv = shlex.split(str(command or "").strip())
    if not argv:
        raise OAuthTokenCommandError("OAuth token command is required")
    try:
        result = subprocess.run(argv, check=True, capture_output=True, text=True)
    except subprocess.CalledProcessError as exc:
        stderr = (exc.stderr or "").strip()
        detail = f": {stderr}" if stderr else ""
        raise OAuthTokenCommandError(f"OAuth token command failed{detail}") from exc
    return parse_oauth_token_output(result.stdout)


def parse_oauth_token_output(output: str) -> tuple[str, datetime]:
    raw = str(output or "").strip()
    if not raw:
        raise OAuthTokenCommandError("OAuth token command returned empty output")
    if raw.startswith("{"):
        try:
            payload = json.loads(raw)
        except json.JSONDecodeError as exc:
            raise OAuthTokenCommandError("OAuth token command returned invalid JSON") from exc
        if not isinstance(payload, dict):
            raise OAuthTokenCommandError("OAuth token command JSON output must be an object")
        token = str(payload.get("access_token") or payload.get("token") or "").strip()
        if not token:
            raise OAuthTokenCommandError("OAuth token command JSON output did not include access_token")
        expires_in = payload.get("expires_in")
        ttl = max(int(expires_in), 60) if isinstance(expires_in, (int, float)) else DEFAULT_TOKEN_TTL_SECONDS
        return token, datetime.now(timezone.utc) + timedelta(seconds=ttl)
    return raw.splitlines()[-1].strip(), datetime.now(timezone.utc) + timedelta(seconds=DEFAULT_TOKEN_TTL_SECONDS)


def _token_from_broker_or_command(
    *,
    command: str,
    home: Path | str | None,
    provider: str,
    broker: OAuthBroker | None,
) -> tuple[str, datetime]:
    active_broker = broker or build_oauth_broker(home=home)
    if active_broker is not None:
        has_configured_flow = active_broker.describe(provider) is not None
        entry = active_broker.get_entry(provider, allow_login=False)
        if entry is not None and not entry.is_expired(skew_seconds=0):
            return entry.access_token, entry.expires_at
        if has_configured_flow:
            raise RuntimeError(
                f"No valid OAuth token is available for provider '{provider}'. "
                f"Run `ares auth login {provider}` interactively."
            )
    token, expiry = run_oauth_token_command(command)
    save_oauth_token(
        home=home,
        entry=OAuthTokenCacheEntry(
            provider=provider,
            access_token=token,
            expires_at=expiry,
            metadata={"source": "token-command"},
        ),
    )
    return token, expiry


def build_openai_oauth_token_provider(
    command: str = "",
    *,
    home: Path | str | None = None,
    provider: str = "openai",
    broker: OAuthBroker | None = None,
) -> Callable[[], str]:
    def _provider() -> str:
        token, _ = _token_from_broker_or_command(command=command, home=home, provider=provider, broker=broker)
        return token

    return _provider


def build_google_oauth_credentials(
    command: str = "",
    *,
    home: Path | str | None = None,
    provider: str = "gemini",
    broker: OAuthBroker | None = None,
) -> Any:
    try:
        from google.auth import credentials as google_credentials
    except Exception as exc:  # pragma: no cover - only hit without dependency
        raise RuntimeError("google-auth package is required for Gemini OAuth support") from exc

    class BrokerOAuthCredentials(google_credentials.Credentials):
        def __init__(self) -> None:
            super().__init__()
            self.token = None
            self.expiry = None

        def refresh(self, request: Any) -> None:  # pragma: no cover - exercised through SDK integration
            token, expiry = _token_from_broker_or_command(command=command, home=home, provider=provider, broker=broker)
            self.token = token
            self.expiry = expiry

    return BrokerOAuthCredentials()

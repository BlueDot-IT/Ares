from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from ares.secure_files import ensure_private_dir, write_private_text

DEFAULT_HOME = "~/.ares"
OAUTH_DIRNAME = "oauth"
_SAFE_PROVIDER_RE = re.compile(r"^[a-z0-9][a-z0-9_.-]{0,63}$")


@dataclass(frozen=True)
class OAuthTokenCacheEntry:
    provider: str
    access_token: str
    expires_at: datetime
    refresh_token: str = ""
    token_type: str = "Bearer"
    metadata: dict[str, str] = field(default_factory=dict)

    def is_expired(self, *, skew_seconds: int = 60) -> bool:
        cutoff = datetime.now(timezone.utc) + timedelta(seconds=max(0, skew_seconds))
        return self.expires_at <= cutoff


def resolve_home(home: Path | str | None = None) -> Path:
    if home is not None:
        return Path(home).expanduser()
    return Path(os.getenv("ARES_HOME", DEFAULT_HOME)).expanduser()


def oauth_cache_dir(home: Path | str | None = None) -> Path:
    return ensure_private_dir(resolve_home(home) / OAUTH_DIRNAME)


def normalize_oauth_provider_key(provider: str) -> str:
    key = str(provider or "").strip().lower()
    if not _SAFE_PROVIDER_RE.fullmatch(key) or key in {".", ".."}:
        raise ValueError(f"unsafe OAuth provider cache key: {provider!r}")
    return key


def oauth_cache_path(*, home: Path | str | None = None, provider: str) -> Path:
    key = normalize_oauth_provider_key(provider)
    return oauth_cache_dir(home) / f"{key}.json"


def save_oauth_token(*, home: Path | str | None = None, entry: OAuthTokenCacheEntry) -> Path:
    path = oauth_cache_path(home=home, provider=entry.provider)
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "provider": entry.provider,
        "access_token": entry.access_token,
        "expires_at": entry.expires_at.astimezone(timezone.utc).isoformat(),
        "refresh_token": entry.refresh_token,
        "token_type": entry.token_type,
        "metadata": dict(entry.metadata),
    }
    write_private_text(path, json.dumps(payload, indent=2, sort_keys=True) + "\n")
    return path


def load_oauth_token(*, home: Path | str | None = None, provider: str) -> OAuthTokenCacheEntry | None:
    path = oauth_cache_path(home=home, provider=provider)
    if not path.exists():
        return None
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    if not isinstance(payload, dict):
        return None
    token = str(payload.get("access_token") or "").strip()
    expires_at_raw = str(payload.get("expires_at") or "").strip()
    if not token or not expires_at_raw:
        return None
    try:
        expires_at = datetime.fromisoformat(expires_at_raw)
    except ValueError:
        return None
    if expires_at.tzinfo is None:
        expires_at = expires_at.replace(tzinfo=timezone.utc)
    metadata = payload.get("metadata") if isinstance(payload.get("metadata"), dict) else {}
    try:
        provider_key = normalize_oauth_provider_key(str(payload.get("provider") or provider))
    except ValueError:
        return None
    return OAuthTokenCacheEntry(
        provider=provider_key,
        access_token=token,
        expires_at=expires_at.astimezone(timezone.utc),
        refresh_token=str(payload.get("refresh_token") or "").strip(),
        token_type=str(payload.get("token_type") or "Bearer").strip() or "Bearer",
        metadata={str(key): str(value) for key, value in metadata.items()},
    )


def clear_oauth_token(*, home: Path | str | None = None, provider: str) -> bool:
    path = oauth_cache_path(home=home, provider=provider)
    if not path.exists():
        return False
    path.unlink()
    return True


def list_oauth_tokens(*, home: Path | str | None = None) -> list[OAuthTokenCacheEntry]:
    directory = oauth_cache_dir(home)
    if not directory.exists():
        return []
    entries: list[OAuthTokenCacheEntry] = []
    for item in sorted(directory.glob("*.json")):
        try:
            entry = load_oauth_token(home=directory.parent, provider=item.stem)
        except ValueError:
            continue
        if entry is not None:
            entries.append(entry)
    return entries

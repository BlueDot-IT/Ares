from __future__ import annotations

import hashlib
import hmac
import secrets
import threading
import time
from dataclasses import dataclass


@dataclass(frozen=True)
class GatewaySession:
    token: str
    created_at: float
    source: str


DEFAULT_SESSION_TTL_SECONDS = 8 * 60 * 60
DEFAULT_PAIRING_TTL_SECONDS = 5 * 60
DEFAULT_FAILURE_WINDOW_SECONDS = 60
DEFAULT_MAX_FAILED_LOGINS = 5

class GatewayAuthManager:
    def __init__(
        self,
        *,
        auth_enabled: bool = False,
        operator_token: str | None = None,
        session_ttl_seconds: float = DEFAULT_SESSION_TTL_SECONDS,
        pairing_ttl_seconds: float = DEFAULT_PAIRING_TTL_SECONDS,
        failure_window_seconds: float = DEFAULT_FAILURE_WINDOW_SECONDS,
        max_failed_logins: int = DEFAULT_MAX_FAILED_LOGINS,
    ) -> None:
        self.auth_enabled = bool(auth_enabled)
        self.operator_token = str(operator_token or "").strip()
        self.session_ttl_seconds = float(session_ttl_seconds)
        self.pairing_ttl_seconds = float(pairing_ttl_seconds)
        self.failure_window_seconds = float(failure_window_seconds)
        self.max_failed_logins = int(max_failed_logins)
        self._lock = threading.Lock()
        self._sessions: dict[str, GatewaySession] = {}
        self._pairing_codes: dict[str, dict[str, str | float]] = {}
        self._failed_logins: list[float] = []

    def issue_pairing_code(self, *, label: str | None = None) -> str:
        code = secrets.token_urlsafe(12)
        with self._lock:
            self._purge_expired_locked(now=time.time())
            self._pairing_codes[code] = {
                "label": str(label or "").strip(),
                "created_at": time.time(),
            }
        return code

    def exchange_pairing_code(self, code: str) -> str | None:
        candidate = str(code or "").strip()
        if not candidate:
            return None
        with self._lock:
            now = time.time()
            self._purge_expired_locked(now=now)
            pairing = self._pairing_codes.pop(candidate, None)
            if pairing is None:
                return None
            created_at = float(pairing.get("created_at") or 0.0)
            if self._is_expired(created_at, ttl=self.pairing_ttl_seconds, now=now):
                return None
        label = str(pairing.get("label") or "paired")
        return self._issue_session(source=f"pairing:{label}")

    def login(self, operator_token: str) -> str | None:
        candidate = str(operator_token or "").strip()
        if not (self.auth_enabled and self.operator_token and candidate):
            return None
        now = time.time()
        with self._lock:
            self._purge_expired_locked(now=now)
            self._failed_logins = [item for item in self._failed_logins if not self._is_expired(item, ttl=self.failure_window_seconds, now=now)]
            if len(self._failed_logins) >= self.max_failed_logins:
                return None
        if not hmac.compare_digest(candidate, self.operator_token):
            with self._lock:
                self._failed_logins.append(now)
            return None
        with self._lock:
            self._failed_logins.clear()
        return self._issue_session(source="operator-token")

    def validate_session(self, token: str | None) -> bool:
        return self.session_provenance(token) is not None

    def session_provenance(self, token: str | None) -> dict[str, str] | None:
        candidate = str(token or "").strip()
        if not candidate:
            return None
        with self._lock:
            now = time.time()
            self._purge_expired_locked(now=now)
            session = self._sessions.get(candidate)
            if session is None:
                return None
            if self._is_expired(session.created_at, ttl=self.session_ttl_seconds, now=now):
                self._sessions.pop(candidate, None)
                return None
            return {
                "session_id": hashlib.sha256(
                    candidate.encode("utf-8")
                ).hexdigest()[:16],
                "source": session.source,
            }

    def auth_required(self, *, mode: str) -> bool:
        return self.auth_enabled

    def _issue_session(self, *, source: str) -> str:
        token = secrets.token_urlsafe(24)
        with self._lock:
            self._purge_expired_locked(now=time.time())
            self._sessions[token] = GatewaySession(token=token, created_at=time.time(), source=source)
        return token

    def _purge_expired_locked(self, *, now: float) -> None:
        self._sessions = {
            token: session
            for token, session in self._sessions.items()
            if not self._is_expired(session.created_at, ttl=self.session_ttl_seconds, now=now)
        }
        self._pairing_codes = {
            code: payload
            for code, payload in self._pairing_codes.items()
            if not self._is_expired(float(payload.get("created_at") or 0.0), ttl=self.pairing_ttl_seconds, now=now)
        }

    @staticmethod
    def _is_expired(created_at: float, *, ttl: float, now: float) -> bool:
        return ttl <= 0 or created_at <= 0 or (now - created_at) > ttl


def extract_bearer_token(header_value: str | None) -> str | None:
    raw = str(header_value or "").strip()
    if not raw:
        return None
    prefix = "bearer "
    if raw.lower().startswith(prefix):
        token = raw[len(prefix) :].strip()
        return token or None
    return None

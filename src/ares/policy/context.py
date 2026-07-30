from __future__ import annotations

import ipaddress
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from urllib.parse import urlparse, urlsplit

from .risk import risk_allows


DEFAULT_ALLOWED_CIDRS = (
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
)


@dataclass(frozen=True)
class PolicyContext:
    """Runtime policy for a single engagement/tool dispatch."""

    max_risk: str = "post-exploitation"
    allow_private_only: bool = True
    allowed_cidrs: tuple[ipaddress._BaseNetwork, ...] = field(
        default_factory=lambda: DEFAULT_ALLOWED_CIDRS
    )
    allowed_hosts: tuple[str, ...] = field(default_factory=tuple)
    allowed_paths: tuple[str, ...] = field(default_factory=tuple)
    forbidden_paths: tuple[str, ...] = field(default_factory=tuple)
    scope_bound: bool = False

    def enforce_tool_call(self, tool_name: str, tool_risk: str, args: dict[str, Any]) -> None:
        if not risk_allows(self.max_risk, tool_risk):
            raise PermissionError(
                f"risk policy violation: tool {tool_name!r} risk {tool_risk!r} exceeds max {self.max_risk!r}"
            )
        effective_args = args or {}
        self._enforce_path_args(effective_args)
        for target in self._extract_scope_targets(effective_args):
            if self.looks_like_path(target):
                self.enforce_path_scope(target)
            else:
                self.enforce_target_scope(target)

    def enforce_target_scope(self, target: str) -> None:
        host = self._target_to_host(target)
        if not host:
            return
        if self.allowed_hosts:
            if self._host_is_explicitly_allowed(host):
                return
            raise PermissionError(
                f"scope policy violation: target {host!r} is outside explicit host scope"
            )
        if self.scope_bound:
            raise PermissionError(
                f"scope policy violation: target {host!r} is outside explicit host scope"
            )
        try:
            ip = ipaddress.ip_address(host)
        except ValueError:
            if self._is_private_hostname(host):
                return
            if self.allow_private_only:
                raise PermissionError(f"scope policy violation: target {host!r} is not in allowed private scope")
            return

        if self.allowed_cidrs and any(ip in cidr for cidr in self.allowed_cidrs):
            return
        if self.allow_private_only:
            raise PermissionError(f"scope policy violation: target {host!r} is not in allowed private scope")

    def enforce_path_scope(self, path: str, *, base: Path | None = None) -> None:
        resolved = self._resolve_path(path, base=base)
        for forbidden in self.forbidden_paths:
            candidate = Path(forbidden).expanduser()
            forbidden_roots = (
                [self._resolve_path(forbidden)]
                if candidate.is_absolute() or not self.allowed_paths
                else [
                    self._resolve_path(forbidden, base=self._resolve_path(allowed))
                    for allowed in self.allowed_paths
                ]
            )
            for forbidden_path in forbidden_roots:
                if self._path_is_within(resolved, forbidden_path):
                    raise PermissionError(
                        f"scope policy violation: path {str(resolved)!r} is forbidden"
                    )
        for allowed in self.allowed_paths:
            allowed_path = self._resolve_path(allowed)
            if self._path_is_within(resolved, allowed_path):
                return
        if self.scope_bound:
            raise PermissionError(
                f"scope policy violation: path {str(resolved)!r} is outside explicit path scope"
            )

    def _enforce_path_args(self, args: dict[str, Any]) -> None:
        root_value = args.get("root")
        base = Path.cwd().resolve()
        if isinstance(root_value, str) and root_value.strip():
            self.enforce_path_scope(root_value.strip())
            base = self._resolve_path(root_value.strip())

        for key in ("path", "file", "file_path", "directory", "cwd", "wordlist"):
            value = args.get(key)
            if isinstance(value, str) and value.strip():
                self.enforce_path_scope(value.strip(), base=base)

        paths = args.get("paths")
        if isinstance(paths, list):
            for value in paths:
                if isinstance(value, str) and value.strip():
                    self.enforce_path_scope(value.strip(), base=base)
        elif isinstance(paths, str) and paths.strip():
            self.enforce_path_scope(paths.strip(), base=base)

        raw_args = args.get("args")
        if self.scope_bound and raw_args not in (None, "", [], {}):
            raise PermissionError(
                "scope policy violation: opaque raw tool arguments are disabled for bounded engagements"
            )

    def _extract_scope_targets(self, args: dict[str, Any]) -> list[str]:
        targets: list[str] = []
        for key in ("target", "host", "hostname", "domain", "ip", "url", "base_url"):
            value = args.get(key)
            if isinstance(value, str) and value.strip():
                targets.append(value.strip())
        for key in ("targets", "hosts", "hostnames", "domains", "urls"):
            value = args.get(key)
            if isinstance(value, list):
                targets.extend(str(item).strip() for item in value if str(item).strip())
            elif isinstance(value, str) and value.strip():
                targets.extend(part.strip() for part in value.replace("\n", ";").split(";") if part.strip())
        return targets

    @staticmethod
    def looks_like_path(target: str) -> bool:
        value = str(target or "").strip()
        if not value:
            return False
        if len(value) >= 3 and value[1] == ":" and value[2] in {"/", "\\"}:
            return True
        parsed = urlparse(value)
        if parsed.scheme:
            return parsed.scheme == "file"
        if value.startswith(("/", "./", "../", "~", "\\")):
            return True
        if Path(value).expanduser().exists():
            return True
        if "/" in value or "\\" in value:
            first_component = value.replace("\\", "/").split("/", 1)[0]
            return "." not in first_component
        return False

    @staticmethod
    def _resolve_path(path: str, *, base: Path | None = None) -> Path:
        candidate = Path(str(path).strip()).expanduser()
        if not candidate.is_absolute():
            candidate = (base or Path.cwd()) / candidate
        return candidate.resolve(strict=False)

    @staticmethod
    def _path_is_within(path: Path, root: Path) -> bool:
        try:
            path.relative_to(root)
        except ValueError:
            return False
        return True

    @staticmethod
    def _target_to_host(target: str) -> str:
        parsed = urlparse(target)
        if parsed.scheme and parsed.hostname:
            return parsed.hostname
        stripped = target.strip().strip("[]")
        if ":" in stripped and not stripped.startswith(("http://", "https://", "tcp://", "ssh://")):
            return urlsplit(f"//{stripped}").hostname or stripped
        return stripped

    @staticmethod
    def _is_private_hostname(host: str) -> bool:
        normalized = host.strip().strip(".").lower()
        if not normalized:
            return True
        if ":" in normalized:
            normalized = normalized.rsplit(":", 1)[0]
        return normalized in {"localhost", "localhost.localdomain"} or normalized.endswith(".local")

    def _host_is_explicitly_allowed(self, host: str) -> bool:
        normalized = host.strip().strip("[]").lower().rstrip(".")
        try:
            address = ipaddress.ip_address(normalized)
        except ValueError:
            for allowed in self.allowed_hosts:
                candidate = self._target_to_host(str(allowed)).lower().rstrip(".")
                if normalized == candidate:
                    return True
            return False
        for allowed in self.allowed_hosts:
            candidate = self._target_to_host(str(allowed))
            try:
                if address in ipaddress.ip_network(candidate, strict=False):
                    return True
            except ValueError:
                continue
        return False

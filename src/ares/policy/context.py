from __future__ import annotations

import ipaddress
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Sequence
from urllib.parse import urlparse, urlsplit

from .risk import risk_allows


DEFAULT_ALLOWED_CIDRS = (
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
)


def _network_bounds(
    target: str,
) -> tuple[ipaddress._BaseAddress, ipaddress._BaseAddress] | None:
    """Return bounds for one bare IP, CIDR, or explicit address range."""
    candidate = str(target or "").strip()
    if not candidate or "://" in candidate or any(
        char.isspace() for char in candidate
    ):
        return None
    try:
        network = ipaddress.ip_network(candidate, strict=False)
    except ValueError:
        if candidate.count("-") != 1:
            return None
        start_raw, end_raw = candidate.split("-", 1)
        try:
            start = ipaddress.ip_address(start_raw)
            end = ipaddress.ip_address(end_raw)
        except ValueError:
            return None
        if start.version != end.version or int(start) > int(end):
            return None
        return start, end
    return network.network_address, network.broadcast_address


def target_to_scope_host(target: str) -> str:
    """Return one stable host/network identity without dropping suffixes."""
    candidate = str(target or "").strip()
    if not candidate:
        return ""

    try:
        parsed = urlparse(candidate)
        parsed_hostname = parsed.hostname
    except ValueError:
        return candidate.lower().rstrip(".")
    if "://" in candidate and parsed.scheme:
        return (parsed_hostname or candidate).lower().rstrip(".")

    unbracketed = candidate.removeprefix("[").removesuffix("]")
    try:
        return str(ipaddress.ip_address(unbracketed)).lower()
    except ValueError:
        pass
    try:
        return ipaddress.ip_network(candidate, strict=False).with_prefixlen
    except ValueError:
        pass

    # A slash in a scheme-less value is ambiguous network/path syntax. Keep
    # it intact so it cannot be reduced to an otherwise-authorized host.
    if "/" in candidate or "\\" in candidate:
        return candidate.lower().rstrip(".")

    if candidate.startswith("[") or candidate.count(":") == 1:
        try:
            authority = urlsplit(f"//{candidate}")
            port = authority.port
        except ValueError:
            return candidate.lower().rstrip(".")
        if (
            authority.hostname
            and authority.username is None
            and authority.password is None
            and port is not None
            and not authority.path
            and not authority.query
            and not authority.fragment
        ):
            return authority.hostname.lower().rstrip(".")
    return candidate.lower().rstrip(".")


def target_is_within_allowed_hosts(
    target: str,
    allowed_hosts: Sequence[str],
) -> bool:
    """Require the entire requested target to fit one allowed host/network."""
    requested_bounds = _network_bounds(target)
    if requested_bounds is not None:
        requested_start, requested_end = requested_bounds
        for allowed in allowed_hosts:
            allowed_bounds = _network_bounds(str(allowed))
            if allowed_bounds is None:
                allowed_host = target_to_scope_host(str(allowed))
                try:
                    address = ipaddress.ip_address(allowed_host)
                except ValueError:
                    continue
                allowed_bounds = address, address
            allowed_start, allowed_end = allowed_bounds
            if (
                requested_start.version == allowed_start.version
                and requested_start >= allowed_start
                and requested_end <= allowed_end
            ):
                return True
        return False

    host = target_to_scope_host(target)
    if not host:
        return False
    try:
        address = ipaddress.ip_address(host.strip("[]"))
    except ValueError:
        normalized = host.lower().rstrip(".")
        return any(
            normalized == target_to_scope_host(str(allowed)).lower().rstrip(".")
            for allowed in allowed_hosts
        )

    for allowed in allowed_hosts:
        allowed_bounds = _network_bounds(str(allowed))
        if allowed_bounds is None:
            allowed_host = target_to_scope_host(str(allowed))
            try:
                allowed_address = ipaddress.ip_address(allowed_host)
            except ValueError:
                continue
            allowed_bounds = allowed_address, allowed_address
        allowed_start, allowed_end = allowed_bounds
        if (
            address.version == allowed_start.version
            and allowed_start <= address <= allowed_end
        ):
            return True
    return False


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
    paths_are_bound: bool = False

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
            if target_is_within_allowed_hosts(target, self.allowed_hosts):
                return
            raise PermissionError(
                f"scope policy violation: target {host!r} is outside explicit host scope"
            )
        if self.scope_bound:
            raise PermissionError(
                f"scope policy violation: target {host!r} is outside explicit host scope"
            )
        requested_bounds = _network_bounds(target)
        if requested_bounds is not None:
            start, end = requested_bounds
            if self.allowed_cidrs and any(
                start.version == cidr.version
                and start in cidr
                and end in cidr
                for cidr in self.allowed_cidrs
            ):
                return
            if self.allow_private_only:
                raise PermissionError(
                    f"scope policy violation: target {target!r} is not in allowed private scope"
                )
            return
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
            candidate = Path(forbidden)
            if self.paths_are_bound:
                if not candidate.is_absolute():
                    raise PermissionError(
                        "scope policy violation: bound scope paths must be absolute"
                    )
                forbidden_roots = [candidate]
            else:
                candidate = candidate.expanduser()
                forbidden_roots = (
                    [self._resolve_path(forbidden)]
                    if candidate.is_absolute() or not self.allowed_paths
                    else [
                        self._resolve_path(
                            forbidden,
                            base=self._resolve_path(allowed),
                        )
                        for allowed in self.allowed_paths
                    ]
                )
            for forbidden_path in forbidden_roots:
                if self._path_is_within(resolved, forbidden_path):
                    raise PermissionError(
                        f"scope policy violation: path {str(resolved)!r} is forbidden"
                    )
        for allowed in self.allowed_paths:
            allowed_path = (
                Path(allowed)
                if self.paths_are_bound
                else self._resolve_path(allowed)
            )
            if self.paths_are_bound and not allowed_path.is_absolute():
                raise PermissionError(
                    "scope policy violation: bound scope paths must be absolute"
                )
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
                normalized = value.replace("\n", ";")
                if key != "urls":
                    normalized = normalized.replace(",", ";")
                targets.extend(
                    part.strip()
                    for part in normalized.split(";")
                    if part.strip()
                )
        return targets

    @staticmethod
    def looks_like_path(target: str) -> bool:
        value = str(target or "").strip()
        if not value:
            return False
        if _network_bounds(value) is not None:
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
        return target_to_scope_host(target)

    @staticmethod
    def _is_private_hostname(host: str) -> bool:
        normalized = host.strip().strip(".").lower()
        if not normalized:
            return True
        if ":" in normalized:
            normalized = normalized.rsplit(":", 1)[0]
        return normalized in {"localhost", "localhost.localdomain"} or normalized.endswith(".local")

    def _host_is_explicitly_allowed(self, host: str) -> bool:
        return target_is_within_allowed_hosts(host, self.allowed_hosts)

from __future__ import annotations

import ipaddress
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlparse

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

    def enforce_tool_call(self, tool_name: str, tool_risk: str, args: dict[str, Any]) -> None:
        if not risk_allows(self.max_risk, tool_risk):
            raise PermissionError(
                f"risk policy violation: tool {tool_name!r} risk {tool_risk!r} exceeds max {self.max_risk!r}"
            )
        for target in self._extract_scope_targets(args or {}):
            self.enforce_target_scope(target)

    def enforce_target_scope(self, target: str) -> None:
        host = self._target_to_host(target)
        if not host:
            return
        try:
            ip = ipaddress.ip_address(host)
        except ValueError:
            # Hostname/domain validation will be added with ROE domain allowlists.
            return

        if self.allowed_cidrs and any(ip in cidr for cidr in self.allowed_cidrs):
            return
        if self.allow_private_only:
            raise PermissionError(f"scope policy violation: target {host!r} is not in allowed private scope")

    def _extract_scope_targets(self, args: dict[str, Any]) -> list[str]:
        targets: list[str] = []
        for key in ("target", "host", "ip", "url", "base_url"):
            value = args.get(key)
            if isinstance(value, str) and value.strip():
                targets.append(value.strip())
        for key in ("targets", "hosts", "urls"):
            value = args.get(key)
            if isinstance(value, list):
                targets.extend(str(item).strip() for item in value if str(item).strip())
            elif isinstance(value, str) and value.strip():
                targets.extend(part.strip() for part in value.replace("\n", ";").split(";") if part.strip())
        return targets

    @staticmethod
    def _target_to_host(target: str) -> str:
        parsed = urlparse(target)
        if parsed.scheme and parsed.hostname:
            return parsed.hostname
        return target.strip().strip("[]")

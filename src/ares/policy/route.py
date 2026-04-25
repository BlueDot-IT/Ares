from __future__ import annotations

import ipaddress
import os
from contextlib import contextmanager
from dataclasses import dataclass, field
from typing import Iterator
from urllib.parse import urlparse


DEFAULT_DIRECT_CIDRS = (
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
)


@dataclass(frozen=True)
class RoutePolicy:
    require_tor_for_external: bool = True
    direct_allowed_cidrs: tuple[ipaddress._BaseNetwork, ...] = field(default_factory=lambda: DEFAULT_DIRECT_CIDRS)

    def route_for_target(self, target: str | None) -> str:
        if not target or not self.require_tor_for_external:
            return "direct"
        host = self._target_to_host(target)
        try:
            ip = ipaddress.ip_address(host)
        except ValueError:
            return "tor"
        if any(ip in cidr for cidr in self.direct_allowed_cidrs):
            return "direct"
        return "tor"

    @contextmanager
    def apply_for_target(self, target: str | None) -> Iterator[str]:
        route = self.route_for_target(target)
        old_force = os.environ.get("ARES_FORCE_TOR")
        try:
            if route == "tor":
                os.environ["ARES_FORCE_TOR"] = "1"
            yield route
        finally:
            if old_force is None:
                os.environ.pop("ARES_FORCE_TOR", None)
            else:
                os.environ["ARES_FORCE_TOR"] = old_force

    @staticmethod
    def _target_to_host(target: str) -> str:
        parsed = urlparse(target)
        if parsed.scheme and parsed.hostname:
            return parsed.hostname
        return target.strip().strip("[]")

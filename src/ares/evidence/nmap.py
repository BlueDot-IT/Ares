from __future__ import annotations

import re

from ares.state.db import StateDB

_HOST_RE = re.compile(r"^Nmap scan report for\s+(?P<host>\S+)", re.MULTILINE)
_SERVICE_RE = re.compile(
    r"^(?P<port>\d+)/(?:\s*)?(?P<proto>tcp|udp)\s+open\s+(?P<service>\S+)(?:\s+(?P<product>.*))?$",
    re.MULTILINE,
)


def parse_nmap_stdout_into_state(db: StateDB, *, session_id: int, stdout: str) -> None:
    current_host = _extract_host(stdout)
    if not current_host:
        return
    db.upsert_host(session_id=session_id, address=current_host)
    for match in _SERVICE_RE.finditer(stdout or ""):
        db.upsert_service(
            session_id=session_id,
            host_address=current_host,
            port=int(match.group("port")),
            proto=match.group("proto"),
            service=match.group("service"),
            product=(match.group("product") or "").strip() or None,
        )


def _extract_host(stdout: str) -> str | None:
    match = _HOST_RE.search(stdout or "")
    if not match:
        return None
    line = (stdout or "")[match.start() : (stdout or "").find("\n", match.start())]
    paren = re.search(r"\(([^)]+)\)", line)
    return paren.group(1) if paren else match.group("host")

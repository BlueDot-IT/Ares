from __future__ import annotations

import json
from typing import Any

from ares.state.db import StateDB


def _session_by_id(db: StateDB, session_id: int) -> dict[str, Any]:
    for session in db.list_sessions():
        if int(session["id"]) == int(session_id):
            return session
    raise KeyError(f"unknown session: {session_id}")


def _result_preview(result_json: str | None, error: str | None) -> str:
    if error:
        return error
    if not result_json:
        return ""
    try:
        data = json.loads(result_json)
    except json.JSONDecodeError:
        return result_json[:500]
    if isinstance(data, dict):
        for key in ("summary", "stdout", "result"):
            value = data.get(key)
            if isinstance(value, str):
                return value[:500]
        return json.dumps(data, sort_keys=True)[:500]
    return str(data)[:500]


def render_session_report(db: StateDB, session_id: int) -> str:
    session = _session_by_id(db, session_id)
    lines = [
        "# Ares Session Report",
        "",
        f"Session: {session_id}",
        f"Target: {session.get('target') or 'unspecified'}",
        f"Agent: {session.get('agent') or 'default'}",
        f"Status: {session.get('status') or 'unknown'}",
        f"Mode: {session.get('mode') or 'unspecified'}",
        "",
        "## Evidence",
    ]

    hosts = db.list_hosts(session_id)
    services = db.list_services(session_id)
    if not hosts and not services:
        lines.append("No normalized evidence recorded.")
    else:
        if hosts:
            lines.extend(["", "### Hosts"])
            for host in hosts:
                suffix = f" ({host['hostname']})" if host.get("hostname") else ""
                lines.append(f"- {host['address']}{suffix}")
        if services:
            lines.extend(["", "### Services"])
            for service in services:
                name = service.get("service") or "unknown"
                product = f" - {service['product']}" if service.get("product") else ""
                lines.append(
                    f"- {service['host_address']}:{service['port']}/{service['proto']} {name}{product}"
                )

    lines.extend(["", "## Tool Calls"])
    calls = db.list_tool_calls(session_id)
    if not calls:
        lines.append("No tool calls recorded.")
    for call in calls:
        preview = _result_preview(call.get("result_json"), call.get("error"))
        lines.append(f"- {call['tool']} [{call['status']}] {call.get('duration_ms', 0)}ms")
        if preview:
            lines.append(f"  - {preview}")

    return "\n".join(lines).rstrip() + "\n"

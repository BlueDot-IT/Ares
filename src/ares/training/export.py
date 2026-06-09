from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

from ares.agent.tool_result_indexer import redact_secrets
from ares.state.db import StateDB


SECRET_PATTERNS = [
    r"(?i)(api[_-]?key|token|secret|password)\s*[:=]\s*['\"]?[^'\"\s]+",
    r"(?i)authorization:\s*bearer\s+[a-z0-9._~+/=-]+",
    r"sk-[A-Za-z0-9_-]{20,}",
]

_SECRET_RE = [re.compile(p) for p in SECRET_PATTERNS]


def _has_policy_violation(db: StateDB, session_id: int) -> bool:
    """Check if session has any policy violations recorded."""
    with db._connection() as conn:
        row = conn.execute(
            "SELECT 1 FROM tool_calls WHERE session_id = ? AND status = 'error' AND error LIKE '%policy%' LIMIT 1",
            (session_id,),
        ).fetchone()
        return row is not None


def _has_unapproved_dangerous(db: StateDB, session_id: int) -> bool:
    """Check if session has dangerous tool calls without approval."""
    with db._connection() as conn:
        row = conn.execute(
            """
            SELECT 1 FROM tool_calls
            WHERE session_id = ? AND status = 'error'
            AND (tool LIKE '%exploit%' OR tool LIKE '%poc%' OR tool LIKE '%cve%')
            LIMIT 1
            """,
            (session_id,),
        ).fetchone()
        return row is not None


def _get_final_response(db: StateDB, session_id: int) -> str | None:
    """Get the final assistant response for a session."""
    with db._connection() as conn:
        rows = conn.execute(
            "SELECT content FROM messages WHERE session_id = ? AND role = 'assistant' ORDER BY id DESC LIMIT 1",
            (session_id,),
        ).fetchall()
        if rows:
            return rows[0]["content"]
    return None


def _get_session_metadata(db: StateDB, session_id: int) -> dict[str, Any]:
    with db._connection() as conn:
        row = conn.execute("SELECT * FROM sessions WHERE id = ?", (session_id,)).fetchone()
        if not row:
            return {}
        return dict(row)


def _get_tool_calls_summary(db: StateDB, session_id: int) -> list[dict[str, Any]]:
    """Get compact tool call history for training context."""
    calls = db.list_tool_calls(session_id)
    summary = []
    for call in calls:
        try:
            args = json.loads(call.get("args_json", "{}")) if call.get("args_json") else {}
        except Exception:
            args = {}
        summary.append(
            {
                "tool": call.get("tool"),
                "status": call.get("status"),
                "args_keys": list(args.keys())[:10],
            }
        )
    return summary


def build_training_example(db: StateDB, session_id: int) -> dict[str, Any] | None:
    """Build a single training example from a completed session."""
    session = _get_session_metadata(db, session_id)
    if not session:
        return None

    # Only export completed sessions
    if session.get("status") not in ("completed", "final_response"):
        return None

    # Skip sessions with policy violations
    if _has_policy_violation(db, session_id):
        return None

    # Skip sessions with unapproved dangerous actions
    if _has_unapproved_dangerous(db, session_id):
        return None

    # Must have a final response
    final_response = _get_final_response(db, session_id)
    if not final_response:
        return None

    prompt = session.get("prompt", "")
    target = session.get("target")
    agent = session.get("agent", "default")

    instruction = "You are Ares, an autonomous penetration testing agent for authorized engagements. Follow the operator's task prompt, use tools through the registry, and respect policy constraints."
    if target:
        input_text = f"Target: {target}\n\nTask: {prompt}"
    else:
        input_text = f"Task: {prompt}"

    output_text = redact_secrets(final_response)
    prompt_redacted = redact_secrets(prompt)

    return {
        "instruction": redact_secrets(instruction),
        "input": input_text.replace(prompt, prompt_redacted) if target else redact_secrets(input_text),
        "output": output_text,
        "metadata": {
            "session_id": session_id,
            "target": target,
            "agent": agent,
            "model": session.get("model"),
            "mode": session.get("mode"),
            "approved": True,
            "tool_calls": _get_tool_calls_summary(db, session_id),
        },
    }


def export_training_data(
    state_db: StateDB,
    output_path: Path | str,
    *,
    min_status: str = "final_response",
) -> int:
    """Export training data from completed sessions to JSONL."""
    output_path = Path(output_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    sessions = state_db.list_sessions()
    exported = 0

    with output_path.open("w", encoding="utf-8") as f:
        for session in sessions:
            if session.get("status") != min_status:
                continue
            example = build_training_example(state_db, session["id"])
            if example:
                f.write(json.dumps(example, ensure_ascii=False) + "\n")
                exported += 1

    return exported

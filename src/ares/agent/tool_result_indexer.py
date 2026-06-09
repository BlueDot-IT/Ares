from __future__ import annotations

import re
from typing import Any

SECRET_PATTERNS = [
    r"(?i)(api[_-]?key|token|secret|password)\s*[:=]\s*['\"]?[^'\"\s]+",
    r"(?i)authorization:\s*bearer\s+[a-z0-9._~+/=-]+",
    r"sk-[A-Za-z0-9_-]{20,}",
]

_SECRET_RE = [re.compile(p) for p in SECRET_PATTERNS]


def redact_secrets(text: str) -> str:
    result = text
    for pattern in _SECRET_RE:
        result = pattern.sub("[REDACTED]", result)
    return result


def _compact_for_memory(data: Any, max_chars: int = 8000) -> str:
    """Create a compact, searchable summary of a tool result for memory storage."""
    if data is None:
        return "no result"
    if isinstance(data, str):
        return redact_secrets(data[:max_chars])
    if isinstance(data, (int, float, bool)):
        return str(data)
    if isinstance(data, list):
        items = [_compact_for_memory(item, max_chars // max(1, len(data))) for item in data[:20]]
        result = "[" + ", ".join(items) + "]"
        return result[:max_chars]
    if isinstance(data, dict):
        # Extract key fields of interest
        parts = []
        for key in ("summary", "targets", "findings", "vulnerabilities", "hosts", "services", "ports", "error"):
            if key in data:
                value = data[key]
                if isinstance(value, (list, dict)):
                    parts.append(f"{key}: {_compact_for_memory(value, 2000)}")
                else:
                    parts.append(f"{key}: {value}")
        # Also include other keys but skip large ones
        for key, value in data.items():
            if key in {"stdout", "stderr", "raw", "content", "html", "response"}:
                continue
            if key not in ("summary", "targets", "findings", "vulnerabilities", "hosts", "services", "ports", "error"):
                if isinstance(value, (list, dict)):
                    parts.append(f"{key}: {_compact_for_memory(value, 1000)}")
                else:
                    parts.append(f"{key}: {value}")
        result = "; ".join(parts)
        return redact_secrets(result[:max_chars])
    return redact_secrets(str(data)[:max_chars])


def tool_result_to_memory_text(
    tool_name: str,
    status: str,
    args: dict[str, Any],
    result: Any,
    error: str | None = None,
) -> str:
    """Convert a tool call result into a compact memory chunk."""
    parts = [f"tool: {tool_name}", f"status: {status}"]

    # Extract target from args
    target = None
    for key in ("target", "host", "ip", "url", "base_url"):
        value = args.get(key)
        if isinstance(value, str) and value.strip():
            target = value.strip()
            break
    if not target:
        for key in ("targets", "hosts", "urls"):
            value = args.get(key)
            if isinstance(value, list) and value:
                target = str(value[0])
                break
            if isinstance(value, str) and value.strip():
                target = value.replace("\n", ";").split(";")[0].strip()
                break
    if target:
        parts.append(f"target: {target}")

    # Command summary for shell-like tools
    if "command" in args and isinstance(args["command"], str):
        parts.append(f"command: {args['command'][:500]}")

    # Result summary
    if status == "ok":
        summary = _compact_for_memory(result)
        if summary and summary != "no result":
            parts.append(f"result: {summary}")
    else:
        err_text = error or (result if isinstance(result, str) else "unknown error")
        parts.append(f"error: {redact_secrets(str(err_text)[:2000])}")

    return redact_secrets(" | ".join(parts))


def should_index_tool_result(tool_name: str, status: str, result: Any) -> bool:
    """Decide whether a tool result should be indexed into memory."""
    # Don't index failed calls with no useful error info
    if status != "ok":
        return True  # Index errors for debugging
    # Skip purely informational tools that don't produce evidence
    skip_tools = {
        "help",
        "version",
        "echo",
        "sleep",
        "wait",
    }
    if tool_name in skip_tools:
        return False
    # Skip if result is empty or trivial
    if result is None:
        return False
    if isinstance(result, str) and not result.strip():
        return False
    if isinstance(result, (list, dict)) and not result:
        return False
    return True

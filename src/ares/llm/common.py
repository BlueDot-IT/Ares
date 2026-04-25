from __future__ import annotations

import json
from collections.abc import Mapping
from typing import Any


def get_field(value: Any, *names: str) -> Any:
    for name in names:
        if isinstance(value, Mapping) and name in value:
            return value[name]
        if hasattr(value, name):
            return getattr(value, name)
    return None


def to_text(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, str):
        return value
    return json.dumps(value, sort_keys=True)


def parse_json_object(value: Any, *, default: dict[str, Any] | None = None) -> dict[str, Any]:
    default = {} if default is None else dict(default)
    if value is None:
        return default
    if isinstance(value, Mapping):
        return dict(value)
    if isinstance(value, str):
        try:
            parsed = json.loads(value)
        except json.JSONDecodeError:
            return default
        return dict(parsed) if isinstance(parsed, Mapping) else default
    try:
        return dict(value)
    except Exception:
        return default


def emit_text_stream(
    *,
    provider: str,
    text: str | None,
    event_callback: Any,
    chunk_size: int = 32,
) -> None:
    clean = to_text(text).strip()
    if not clean or event_callback is None:
        return
    for index in range(0, len(clean), max(1, chunk_size)):
        event_callback(
            {
                "type": "assistant_delta",
                "provider": provider,
                "text": clean[index : index + max(1, chunk_size)],
            }
        )

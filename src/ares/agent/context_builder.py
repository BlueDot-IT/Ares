from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from ares.engagement_memory import build_engagement_memory_context
from ares.state.db import StateDB


class ContextBuilder:
    """Build compact model-facing state summaries from persisted session data."""

    def __init__(self, db: StateDB, *, home: Path | str | None = None) -> None:
        self.db = db
        self.home = Path(home).expanduser() if home is not None else None

    def build_session_context(self, session_id: int, *, target: str | None = None, memory_tags: tuple[str, ...] = ()) -> str:
        calls = self.db.list_tool_calls(session_id)
        lines = ["Current engagement state:"]
        if not calls:
            lines.append("Known prior tool calls: none in this session.")
        else:
            lines.append("Known prior tool calls:")
            for call in calls[-20:]:
                summary = self._summarize_call(call)
                lines.append(f"- {call['tool']} [{call['status']}]: {summary}")
        if self.home is not None:
            memory_context = build_engagement_memory_context(self.home, target=target, memory_tags=memory_tags)
            if memory_context:
                lines.extend(["", memory_context])
        return "\n".join(lines)

    def _summarize_call(self, call: dict[str, Any]) -> str:
        if call.get("error"):
            return str(call["error"])[:500]
        raw = call.get("result_json")
        if not raw:
            return "no result"
        try:
            data = json.loads(raw)
        except Exception:
            return str(raw)[:500]
        compact = self._compact_result(data)
        return json.dumps(compact, sort_keys=True)[:700]

    def _compact_result(self, data: Any) -> Any:
        if isinstance(data, dict):
            if "summary" in data:
                return {"summary": data["summary"]}
            if "targets" in data:
                return {"targets": data["targets"]}
            compact = {}
            for key, value in data.items():
                if key in {"stdout", "stderr", "raw", "content"}:
                    continue
                compact[key] = value
                if len(compact) >= 6:
                    break
            return compact or {"keys": sorted(data.keys())[:10]}
        if isinstance(data, list):
            return data[:10]
        return data

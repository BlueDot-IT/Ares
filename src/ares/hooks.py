from __future__ import annotations

import importlib.util
import traceback
from dataclasses import dataclass
from pathlib import Path
from types import ModuleType
from typing import Any

from ares.engagement_memory import write_engagement_memory
from ares.reporting.markdown import render_session_report
from ares.secure_files import write_private_text
from ares.state.db import StateDB


@dataclass(frozen=True)
class HookInvocationResult:
    name: str
    status: str
    result: Any = None
    error: str = ""


class HookManager:
    def __init__(self, *, home: Path | str, auto_report_on_finish: bool = False) -> None:
        self.home = Path(home)
        self.auto_report_on_finish = auto_report_on_finish
        self._hooks = self._load_hooks()

    def emit(self, event: dict[str, Any], *, state_db: StateDB | None = None) -> list[HookInvocationResult]:
        payload = dict(event)
        payload.setdefault("home", str(self.home))
        if self.auto_report_on_finish and payload.get("type") == "session_finished" and state_db is not None:
            session_id = payload.get("session_id")
            if session_id is not None:
                reports_dir = self.home / "reports"
                reports_dir.mkdir(parents=True, exist_ok=True)
                report_path = reports_dir / f"session-{int(session_id)}.md"
                write_private_text(
                    report_path,
                    render_session_report(state_db, int(session_id)),
                )
                payload["report_path"] = str(report_path)
        if payload.get("type") in {"session_finished", "session_failed"} and payload.get("session_id") is not None:
            payload["engagement_memory_path"] = str(write_engagement_memory(self.home, payload))
        results: list[HookInvocationResult] = []
        for name, module in self._hooks:
            handled_events = getattr(module, "HANDLED_EVENTS", ())
            if handled_events and payload.get("type") not in set(handled_events):
                continue
            handler = getattr(module, "handle_event", None)
            if not callable(handler):
                continue
            try:
                results.append(HookInvocationResult(name=name, status="ok", result=handler(dict(payload))))
            except Exception as exc:
                results.append(HookInvocationResult(name=name, status="error", error=f"{exc}\n{traceback.format_exc()}"))
        return results

    def _load_hooks(self) -> list[tuple[str, ModuleType]]:
        hooks_dir = self.home / "hooks"
        if not hooks_dir.exists():
            return []
        loaded: list[tuple[str, ModuleType]] = []
        for path in sorted(hooks_dir.glob("*.py")):
            spec = importlib.util.spec_from_file_location(f"ares_hook_{path.stem}", path)
            if spec is None or spec.loader is None:
                continue
            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)
            loaded.append((path.stem, module))
        return loaded

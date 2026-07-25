from __future__ import annotations

import curses
import json
import os
import shutil
import textwrap
import threading
import time
from dataclasses import dataclass, field
from typing import Any, Callable

from prompt_toolkit.clipboard.base import ClipboardData
from prompt_toolkit.mouse_events import MouseEventType

from ares import APP_NAME
from ares.config.loader import (
    AppConfig,
    apply_llm_profile,
    available_llm_profiles,
    load_config,
    reset_llm_config,
    save_llm_config,
    save_policy_config,
    save_ui_config,
)
from ares.run import (
    build_doctor_snapshot,
    build_model_snapshot,
    build_registry,
    format_model_snapshot,
    list_registered_tools,
    list_session_summaries,
    run_once,
    write_session_report,
)
from ares.state.db import StateDB
from ares.themes import DEFAULT_THEME, build_theme_preview_text, get_theme, list_theme_names
from ares.tools.registry import ToolRegistry


@dataclass
class BackgroundRunJob:
    prompt: str
    target: str | None = None
    approve_dangerous: bool = False
    policy_allow_private_only: bool | None = None
    status: str = "queued"
    session_id: int | None = None
    final_response: str = ""
    error: str = ""
    events: list[dict[str, Any]] = field(default_factory=list)
    started_at: float = 0.0
    finished_at: float = 0.0
    thread: threading.Thread | None = None


@dataclass
class AresTUIState:
    status_message: str = "ready"
    selected_session_id: int | None = None
    last_refresh_ts: float = 0.0
    input_buffer: str = ""
    current_target: str | None = None
    approve_dangerous: bool = False
    transcript: list[dict[str, str]] = field(default_factory=list)
    tracked_job_token: int | None = None
    processed_event_count: int = 0
    active_stream_index: int | None = None
    active_stream_provider: str | None = None
    scrollback_offset: int = 0
    scrollback_follow_latest: bool = True
    scrollback_anchor_total_lines: int = 0
    screen_paused: bool = False
    should_exit: bool = False


def _truncate(text: str, limit: int = 96) -> str:
    clean = str(text).replace("\n", " ").strip()
    if len(clean) <= limit:
        return clean
    return clean[: max(0, limit - 3)] + "..."


def _fit_width(width: int, *, minimum: int = 72, maximum: int = 120) -> int:
    return max(minimum, min(maximum, width))


def _center_line(text: str, width: int) -> str:
    return _truncate(text, width).center(width)


_SCROLL_WHEEL_STEP = 3

_PROMPT_TOOLKIT_COLOR_MAP = {
    "default": "",
    "black": "ansiblack",
    "red": "ansired",
    "green": "ansigreen",
    "yellow": "ansiyellow",
    "blue": "ansiblue",
    "magenta": "ansimagenta",
    "cyan": "ansicyan",
    "white": "ansiwhite",
}


def _prompt_toolkit_tone_style(tone: Any) -> str:
    parts: list[str] = []
    fg = _PROMPT_TOOLKIT_COLOR_MAP.get(getattr(tone, "fg", "default"), "")
    if fg:
        parts.append(fg)
    bg = _PROMPT_TOOLKIT_COLOR_MAP.get(getattr(tone, "bg", "default"), "")
    if bg:
        parts.append(f"bg:{bg}")
    parts.extend(str(item) for item in getattr(tone, "attrs", ()) if item)
    return " ".join(parts)


STARTUP_BANNER_LINES = [
    "        ##                                                 ##",
    "     /####                                              /####",
    "    /  ###                                             /  ###                                          #",
    "       /##                                                /##                                         ##",
    "      /  ##                                              /  ##                                        ##",
    "      /  ##     ###  /###     /##       /###             /  ##         /###      /##  ###  /###     ########",
    "     /    ##     ###/ #### / / ###     / #### /         /    ##       /  ###  / / ###  ###/ #### / ########",
    "     /    ##      ##   ###/ /   ###   ##  ###/          /    ##      /    ###/ /   ###  ##   ###/     ##",
    "    /      ##     ##       ##    ### ####              /      ##    ##     ## ##    ### ##    ##      ##",
    "    /########     ##       ########    ###             /########    ##     ## ########  ##    ##      ##",
    "   /        ##    ##       #######       ###          /        ##   ##     ## #######   ##    ##      ##",
    "   #        ##    ##       ##              ###        #        ##   ##     ## ##        ##    ##      ##",
    "  /####      ##   ##       ####    /  /###  ##       /####      ##  ##     ## ####    / ##    ##      ##",
    " /   ####    ## / ###       ######/  / #### /       /   ####    ## / ########  ######/  ###   ###     ##",
    "/     ##      #/   ###       #####      ###/       /     ##      #/    ### ###  #####    ###   ###     ##",
    "#                                                  #                        ###",
    " ##                                                 ##                ####   ###",
    "                                                                    /######  /#",
    "                                                                   /     ###/",
]


def _center_block(lines: list[str], width: int) -> list[str]:
    block_width = max((len(line) for line in lines), default=0)
    pad = max(0, (width - block_width) // 2)
    return [(" " * pad) + line for line in lines]


def _result_preview(result_json: str | None, error: str | None) -> str:
    if error:
        return _truncate(error)
    if not result_json:
        return ""
    try:
        data = json.loads(result_json)
    except json.JSONDecodeError:
        return _truncate(result_json)
    if isinstance(data, dict):
        for key in ("summary", "stdout", "result"):
            value = data.get(key)
            if isinstance(value, str):
                return _truncate(value)
        return _truncate(json.dumps(data, sort_keys=True))
    return _truncate(str(data))


def _aggregate_state_counts(state_db: StateDB) -> dict[str, int]:
    sessions = state_db.list_sessions()
    hosts = 0
    services = 0
    messages = 0
    tool_calls = 0
    for session in sessions:
        session_id = int(session["id"])
        hosts += len(state_db.list_hosts(session_id))
        services += len(state_db.list_services(session_id))
        messages += len(state_db.list_messages(session_id))
        tool_calls += len(state_db.list_tool_calls(session_id))
    return {
        "sessions": len(sessions),
        "hosts": hosts,
        "services": services,
        "messages": messages,
        "tool_calls": tool_calls,
    }


def select_neighbor_session_id(session_ids: list[int], current: int | None, direction: int) -> int | None:
    if not session_ids:
        return None
    if current not in session_ids:
        return session_ids[-1]
    index = session_ids.index(current)
    next_index = max(0, min(len(session_ids) - 1, index + direction))
    return session_ids[next_index]


def _session_lookup(state_db: StateDB, session_id: int) -> dict[str, Any]:
    for session in state_db.list_sessions():
        if int(session["id"]) == int(session_id):
            return session
    raise KeyError(f"unknown session: {session_id}")


def build_startup_hero(*, width: int = 84) -> str:
    width = _fit_width(width, minimum=60)
    lines = [""]
    lines.extend(_center_block(STARTUP_BANNER_LINES, width))
    lines.append("")
    lines.extend(
        [
            "",
            _center_line("AUTONOMOUS PENTEST OPERATIONS", width),
            _center_line("CYBERSECURITY OPERATOR SHELL", width),
            "",
            _center_line("Type /help or describe the task to begin.", width),
            "",
        ]
    )
    return "\n".join(lines).rstrip()


def build_help_text() -> str:
    return "\n".join(
        [
            "Slash Commands",
            "===============",
            "Session Control",
            "- /help, /commands, /clear, /quit",
            "- /sessions, /inspect [id], /messages [id], /live",
            "Config",
            "- /doctor, /model, /theme, /target <target>, /scope [mode], /report [id]",
            "Tools",
            "- /tools, /copy [mode], /paste",
            "Navigation",
            "- PageUp/PageDown scroll history",
            "- Home jumps to oldest, End returns to latest",
            "- mouse wheel scrolls history",
            "- Ctrl+Y or Shift+Insert / Ctrl+V paste",
        ]
    )


def _wrap_prefixed(prefix: str, text: str, width: int) -> list[str]:
    available = max(12, width - len(prefix))
    lines: list[str] = []
    raw_lines = str(text).splitlines() or [""]
    for raw_line in raw_lines:
        wrapped = textwrap.wrap(raw_line, width=available) or [""]
        for index, chunk in enumerate(wrapped):
            lines.append((prefix if index == 0 else " " * len(prefix)) + chunk)
    return lines


def build_chat_transcript_text(transcript: list[dict[str, str]], *, width: int = 100) -> str:
    width = _fit_width(width)
    if not transcript:
        return "ares     > Awaiting operator tasking."

    prefix_map = {
        "user": "operator > ",
        "assistant": "ares     > ",
        "assistant_stream": "stream   > ",
        "tool_call": "tool     > ",
        "tool_result": "result   > ",
        "system": "status   > ",
    }
    lines: list[str] = []
    for entry in transcript:
        prefix = prefix_map.get(entry.get("kind", "assistant"), "ares     > ")
        lines.extend(_wrap_prefixed(prefix, entry.get("text", ""), width))
    return "\n".join(lines)


def build_operator_shell_text(
    *,
    transcript: list[dict[str, str]],
    input_buffer: str,
    status_message: str,
    target: str | None,
    selected_session_id: int | None,
    background_job: BackgroundRunJob | None,
    width: int = 100,
    yolo_mode: bool = False,
    screen_paused: bool = False,
    scrollback_follow_latest: bool = True,
    theme_name: str = DEFAULT_THEME,
    allow_private_only: bool = True,
) -> str:
    width = _fit_width(width)
    session_label = str(selected_session_id) if selected_session_id is not None else "-"
    job_status = background_job.status if background_job is not None else "idle"
    yolo_label = "ON" if yolo_mode else "off"
    view_label = "live" if scrollback_follow_latest else "history"
    scope_label = "private" if allow_private_only else "public"
    theme = get_theme(theme_name)
    transcript_text = build_chat_transcript_text(transcript, width=width)
    separator = theme.separator * width
    lines = [
        build_startup_hero(width=width),
        f"target: {target or '-'} | scope: {scope_label} | theme: {theme.name} | session: {session_label} | job: {job_status} | yolo: {yolo_label} | view: {view_label}",
        f"status: {status_message}",
        "commands: type /commands for a list",
        separator,
        transcript_text,
        separator,
        f"operator > {input_buffer}" if input_buffer else "operator >",
    ]
    return "\n".join(lines)


def build_dashboard_text(
    *,
    config: AppConfig,
    registry: ToolRegistry,
    state_db: StateDB,
    status_message: str = "ready",
    active_view: str = "chat",
    background_job: BackgroundRunJob | None = None,
) -> str:
    snapshot = build_doctor_snapshot(config=config, registry=registry)
    counts = _aggregate_state_counts(state_db)
    sessions = list_session_summaries(state_db)
    latest = sessions[-1] if sessions else {}
    return "\n".join(
        [
            f"{APP_NAME} status",
            f"status: {status_message}",
            f"active_view: {active_view}",
            f"background_job: {(background_job.status if background_job is not None else 'idle')}",
            f"llm_model: {snapshot['llm_model']}",
            f"roe_profile: {snapshot['roe_profile']}",
            f"registered_tools: {snapshot['registered_tools']}",
            f"sessions: {counts['sessions']}",
            f"hosts: {counts['hosts']}",
            f"services: {counts['services']}",
            f"messages: {counts['messages']}",
            f"tool_calls: {counts['tool_calls']}",
            f"latest_target: {latest.get('target') or '-'}",
            f"latest_status: {latest.get('status') or '-'}",
        ]
    )


def _build_clipboard_backend() -> Any:
    try:
        from prompt_toolkit.clipboard.pyperclip import PyperclipClipboard

        return PyperclipClipboard()
    except Exception:  # pragma: no cover - clipboard backend fallback
        from prompt_toolkit.clipboard.in_memory import InMemoryClipboard

        return InMemoryClipboard()


def build_screen_frame(
    *,
    body: str,
    active_view: str,
    status_message: str,
    selected_session_id: int | None,
    background_job: BackgroundRunJob | None,
    last_refresh_ts: float,
    width: int = 108,
    theme_name: str = DEFAULT_THEME,
) -> str:
    del active_view, last_refresh_ts
    return build_operator_shell_text(
        transcript=[{"kind": "assistant", "text": body}],
        input_buffer="",
        status_message=status_message,
        target=background_job.target if background_job is not None else None,
        selected_session_id=selected_session_id,
        background_job=background_job,
        width=width,
        yolo_mode=bool(background_job.approve_dangerous) if background_job is not None else False,
        theme_name=theme_name,
    )


def build_session_detail_text(state_db: StateDB, session_id: int) -> str:
    session = _session_lookup(state_db, session_id)
    hosts = state_db.list_hosts(session_id)
    services = state_db.list_services(session_id)
    tool_calls = state_db.list_tool_calls(session_id)
    messages = state_db.list_messages(session_id)

    lines = [
        "Session Detail",
        "==============",
        f"session_id: {session_id}",
        f"target: {session.get('target') or '-'}",
        f"status: {session.get('status') or 'unknown'}",
        f"mode: {session.get('mode') or 'unknown'}",
        f"model: {session.get('model') or 'unknown'}",
        f"prompt: {_truncate(session.get('prompt') or '', 120)}",
        f"hosts: {len(hosts)}",
        f"services: {len(services)}",
        f"tool_calls: {len(tool_calls)}",
        f"messages: {len(messages)}",
        "",
        "Hosts",
        "-----",
    ]
    if hosts:
        for host in hosts[:10]:
            suffix = f" ({host['hostname']})" if host.get("hostname") else ""
            lines.append(f"- {host['address']}{suffix}")
    else:
        lines.append("- none")

    lines.extend(["", "Services", "--------"])
    if services:
        for service in services[:15]:
            name = service.get("service") or "unknown"
            product = f" - {service['product']}" if service.get("product") else ""
            lines.append(f"- {service['port']}/{service['proto']} {name}{product}")
    else:
        lines.append("- none")

    lines.extend(["", "Recent Tool Calls", "-----------------"])
    if tool_calls:
        for call in tool_calls[-8:]:
            lines.append(f"- {call['tool']} [{call['status']}] {call.get('duration_ms', 0)}ms")
            preview = _result_preview(call.get("result_json"), call.get("error"))
            if preview:
                lines.append(f"  {preview}")
    else:
        lines.append("- none")

    lines.extend(["", "Recent Messages", "---------------"])
    if messages:
        for message in messages[-6:]:
            lines.append(f"- [{message['role']}] {_truncate(message['content'], 100)}")
    else:
        lines.append("- none")
    return "\n".join(lines)


def build_message_trace_text(state_db: StateDB, session_id: int) -> str:
    session = _session_lookup(state_db, session_id)
    messages = state_db.list_messages(session_id)
    tool_calls = state_db.list_tool_calls(session_id)
    lines = [
        "Message Trace",
        "============",
        f"session_id: {session_id}",
        f"target: {session.get('target') or '-'}",
        f"prompt: {_truncate(session.get('prompt') or '', 120)}",
        "",
        "Conversation",
        "------------",
    ]
    if messages:
        for message in messages[-12:]:
            lines.append(f"[{message['role']}] {_truncate(message['content'], 120)}")
    else:
        lines.append("No recorded messages.")

    lines.extend(["", "Tool Results", "------------"])
    if tool_calls:
        for call in tool_calls[-10:]:
            lines.append(f"{call['tool']} [{call['status']}] {call.get('duration_ms', 0)}ms")
            preview = _result_preview(call.get("result_json"), call.get("error"))
            if preview:
                lines.append(f"  {preview}")
    else:
        lines.append("No recorded tool calls.")
    return "\n".join(lines)


def build_live_activity_text(job: BackgroundRunJob | None) -> str:
    lines = ["Live Activity", "============="]
    if job is None:
        lines.append("No background job running.")
        return "\n".join(lines)

    lines.extend(
        [
            f"status: {job.status}",
            f"session_id: {job.session_id if job.session_id is not None else '-'}",
            f"target: {job.target or '-'}",
            f"prompt: {_truncate(job.prompt, 120)}",
            f"events: {len(job.events)}",
        ]
    )
    if job.final_response:
        lines.append(f"final_response: {_truncate(job.final_response, 120)}")
    if job.error:
        lines.append(f"error: {_truncate(job.error, 120)}")
    lines.extend(["", "Recent Events", "-------------"])
    if job.events:
        for event in job.events[-12:]:
            message = event.get("message") or event.get("type") or "event"
            lines.append(f"- [{event.get('type', 'event')}] {_truncate(message, 120)}")
    else:
        lines.append("- none")
    return "\n".join(lines)


def _build_sessions_text(state_db: StateDB, selected_session_id: int | None) -> str:
    sessions = list_session_summaries(state_db)
    lines = ["Sessions", "========"]
    if not sessions:
        lines.append("No sessions recorded yet.")
        return "\n".join(lines)

    selected_id = selected_session_id or int(sessions[-1]["id"])
    for item in sessions:
        marker = ">" if int(item["id"]) == selected_id else " "
        lines.append(
            f"{marker} {item['id']}: status={item.get('status') or 'unknown'} mode={item.get('mode') or 'unknown'} target={item.get('target') or '-'}"
        )

    lines.extend(["", "Selected session summary", "------------------------"])
    lines.append(build_session_detail_text(state_db, selected_id))
    return "\n".join(lines)


def _build_tools_text(registry: ToolRegistry) -> str:
    tools = list_registered_tools(registry)
    lines = ["Tools", "====="]
    if not tools:
        lines.append("No tools registered.")
        return "\n".join(lines)

    risk_counts: dict[str, int] = {}
    toolset_counts: dict[str, int] = {}
    for item in tools:
        risk_counts[item["risk"]] = risk_counts.get(item["risk"], 0) + 1
        toolset_counts[item["toolset"]] = toolset_counts.get(item["toolset"], 0) + 1

    lines.append("Risk buckets:")
    for risk, count in sorted(risk_counts.items()):
        lines.append(f"- {risk}: {count}")
    lines.append("")
    lines.append("Toolsets:")
    for toolset, count in sorted(toolset_counts.items()):
        lines.append(f"- {toolset}: {count}")
    lines.extend(["", "Registered tools", "----------------"])
    for item in tools:
        availability = "up" if item["available"] else "down"
        lines.append(f"- {item['name']} [{item['risk']}] {item['toolset']} {availability}")
    return "\n".join(lines)


def _build_doctor_text(config: AppConfig, registry: ToolRegistry) -> str:
    snapshot = build_doctor_snapshot(config=config, registry=registry)
    lines = ["Doctor", "======"]
    for key, value in snapshot.items():
        lines.append(f"{key}: {value}")
    return "\n".join(lines)


class BackgroundRunController:
    def __init__(self, run_callable: Callable[..., Any] = run_once, on_change: Callable[[], None] | None = None) -> None:
        self.run_callable = run_callable
        self.on_change = on_change
        self.current_job: BackgroundRunJob | None = None
        self.jobs: list[BackgroundRunJob] = []
        self._lock = threading.Lock()

    def start_job(
        self,
        *,
        prompt: str,
        target: str | None = None,
        approve_dangerous: bool = False,
        policy_allow_private_only: bool | None = None,
    ) -> BackgroundRunJob:
        job = BackgroundRunJob(
            prompt=prompt,
            target=target,
            approve_dangerous=approve_dangerous,
            policy_allow_private_only=policy_allow_private_only,
        )
        with self._lock:
            self.current_job = job
            self.jobs.append(job)
        thread = threading.Thread(target=self._run_job, args=(job,), daemon=True)
        job.thread = thread
        thread.start()
        return job

    def _run_job(self, job: BackgroundRunJob) -> None:
        job.status = "running"
        job.started_at = time.time()

        def on_session_started(session_id: int) -> None:
            job.session_id = session_id
            if self.on_change is not None:
                self.on_change()

        def on_event(event: dict[str, Any]) -> None:
            job.events.append(dict(event))
            if event.get("type") == "session_started" and event.get("session_id") is not None:
                job.session_id = int(event["session_id"])
            if event.get("type") == "final_response":
                job.final_response = str(event.get("final_response") or "")
            if self.on_change is not None:
                self.on_change()

        try:
            result = self.run_callable(
                prompt=job.prompt,
                target=job.target,
                approve_dangerous=job.approve_dangerous,
                policy_allow_private_only=job.policy_allow_private_only,
                event_callback=on_event,
                session_started_callback=on_session_started,
            )
            job.final_response = getattr(result, "final_response", "") or job.final_response
            job.status = "completed"
        except Exception as exc:
            job.error = str(exc)
            job.status = "failed"
            job.events.append({"type": "session_failed", "message": str(exc), "error": str(exc)})
        finally:
            job.finished_at = time.time()
            if not job.events or job.events[-1].get("type") != "session_finished":
                job.events.append(
                    {
                        "type": "session_finished",
                        "session_id": job.session_id,
                        "message": job.final_response or job.error or job.status,
                    }
                )


class AresTUI:
    def __init__(self, *, refresh_interval: float = 0.5, yolo_mode: bool = False) -> None:
        self.refresh_interval = refresh_interval
        self.config = load_config()
        self.registry = build_registry()
        self.state_db = StateDB(self.config.home / "state.db")
        self.state = AresTUIState(approve_dangerous=yolo_mode)
        self.background_runs = BackgroundRunController(run_callable=run_once, on_change=self._notify_background_change)
        self._color_roles: dict[str, int] = {}
        self._active_palette_theme: str | None = None
        self._prompt_toolkit_app: Any | None = None
        self._prompt_toolkit_input: Any | None = None
        self._suspend_redraw: bool = False

    def _request_redraw(self) -> None:
        if self._suspend_redraw:
            return
        app = self._prompt_toolkit_app
        if app is not None:
            try:
                app.invalidate()
            except Exception:
                pass

    def _notify_background_change(self) -> None:
        if not self.state.screen_paused:
            self._request_redraw()

    def _enter_history_view(self, *, total_lines: int | None = None) -> None:
        self.state.scrollback_follow_latest = False
        if total_lines is not None:
            self.state.scrollback_anchor_total_lines = max(0, int(total_lines))

    def _follow_latest_view(self, *, total_lines: int | None = None) -> None:
        self.state.scrollback_follow_latest = True
        self.state.scrollback_offset = 0
        if total_lines is not None:
            self.state.scrollback_anchor_total_lines = max(0, int(total_lines))

    def _set_input_buffer_text(self, text: str) -> None:
        clean = str(text)
        self.state.input_buffer = clean
        input_widget = self._prompt_toolkit_input
        if input_widget is not None:
            try:
                input_widget.text = clean
            except Exception:
                pass
        self._request_redraw()

    def _copy_clipboard_text_to_input(self, *, append: bool = False) -> bool:
        try:
            clipboard = _build_clipboard_backend()
            text = clipboard.get_data().text
        except Exception:
            return False
        if append and self.state.input_buffer:
            self._set_input_buffer_text(f"{self.state.input_buffer}{text}")
        else:
            self._set_input_buffer_text(text)
        return True

    def _pause_screen(self) -> None:
        self.state.screen_paused = True
        self.state.status_message = "screen paused"
        self._request_redraw()

    def _resume_screen(self) -> None:
        self.state.screen_paused = False
        self.state.status_message = "screen resumed"
        self._request_redraw()

    def _append_transcript(self, kind: str, text: str) -> None:
        clean = str(text).strip()
        if not clean:
            return
        if self.state.transcript:
            last = self.state.transcript[-1]
            if last.get("kind") == kind and last.get("text") == clean and kind in {"assistant", "system"}:
                return
        self.state.transcript.append({"kind": kind, "text": clean})
        if len(self.state.transcript) > 160:
            self.state.transcript = self.state.transcript[-120:]
        self._request_redraw()

    def _finalize_active_stream(self, final_text: str | None = None) -> None:
        index = self.state.active_stream_index
        if index is None:
            return
        if 0 <= index < len(self.state.transcript):
            replacement = str(final_text).strip() if final_text is not None else self.state.transcript[index].get("text", "")
            if replacement:
                self.state.transcript[index] = {"kind": "assistant", "text": replacement}
        self.state.active_stream_index = None
        self.state.active_stream_provider = None
        self._request_redraw()

    def _append_stream_delta(self, provider: str, text: str) -> None:
        chunk = str(text)
        if not chunk.strip():
            return
        provider_name = str(provider or self.config.llm.provider or "assistant").strip().lower()
        index = self.state.active_stream_index
        if index is not None and 0 <= index < len(self.state.transcript):
            entry = self.state.transcript[index]
            if entry.get("kind") == "assistant_stream" and self.state.active_stream_provider == provider_name:
                entry["text"] = f"{entry.get('text', '')}{chunk}"
                self.state.status_message = f"streaming {provider_name}"
                self._request_redraw()
                return
        self.state.transcript.append({"kind": "assistant_stream", "text": f"[{provider_name}] {chunk}"})
        self.state.active_stream_index = len(self.state.transcript) - 1
        self.state.active_stream_provider = provider_name
        self.state.status_message = f"streaming {provider_name}"
        if len(self.state.transcript) > 160:
            self.state.transcript = self.state.transcript[-120:]
            self.state.active_stream_index = len(self.state.transcript) - 1
        self._request_redraw()

    def _refresh_handles(self) -> None:
        if self.state.screen_paused:
            self.state.last_refresh_ts = time.time()
            return
        self.config = load_config()
        self.registry = build_registry()
        self.state_db = StateDB(self.config.home / "state.db")
        self._ensure_selected_session()
        self._ingest_background_events()
        self.state.last_refresh_ts = time.time()

    def _session_ids(self) -> list[int]:
        return [int(item["id"]) for item in list_session_summaries(self.state_db)]

    def _ensure_selected_session(self) -> None:
        session_ids = self._session_ids()
        if not session_ids:
            self.state.selected_session_id = None
            return
        if self.state.selected_session_id not in session_ids:
            self.state.selected_session_id = session_ids[-1]

    def _move_selection(self, direction: int) -> None:
        self.state.selected_session_id = select_neighbor_session_id(
            self._session_ids(),
            self.state.selected_session_id,
            direction,
        )
        self._request_redraw()

    def _ingest_background_events(self) -> None:
        if self.state.screen_paused:
            return
        job = self.background_runs.current_job
        if job is None:
            self.state.tracked_job_token = None
            self.state.processed_event_count = 0
            return

        token = id(job)
        if self.state.tracked_job_token != token:
            self.state.tracked_job_token = token
            self.state.processed_event_count = 0

        new_events = job.events[self.state.processed_event_count :]
        if not new_events:
            return
        self._suspend_redraw = True
        try:
            for event in new_events:
                self._handle_runtime_event(event)
        finally:
            self._suspend_redraw = False
        self.state.processed_event_count = len(job.events)

    def _handle_runtime_event(self, event: dict[str, Any]) -> None:
        event_type = event.get("type")
        if event_type == "session_started":
            self._finalize_active_stream()
            session_id = event.get("session_id")
            if session_id is not None:
                self.state.selected_session_id = int(session_id)
            target = event.get("target") or self.state.current_target or "-"
            self.state.status_message = f"session {session_id} active"
            self._append_transcript("system", f"session {session_id} started against {target}")
            return
        if event_type == "assistant_delta":
            self._append_stream_delta(str(event.get("provider") or self.config.llm.provider), str(event.get("text") or ""))
            return
        if event_type == "tool_call":
            self._finalize_active_stream()
            self._append_transcript("tool_call", event.get("message") or event.get("tool") or "tool call")
            return
        if event_type == "tool_result":
            self._finalize_active_stream()
            tool = event.get("tool") or "tool"
            message = event.get("message") or event.get("error") or event.get("status") or "completed"
            self._append_transcript("tool_result", f"{tool}: {message}")
            return
        if event_type == "model_fallback":
            self._finalize_active_stream()
            self.state.status_message = f"fallback -> {event.get('provider')}/{event.get('model')}"
            self._append_transcript("system", event.get("message") or "model fallback engaged")
            return
        if event_type == "final_response":
            final_text = event.get("final_response") or event.get("message") or ""
            self._finalize_active_stream(str(final_text))
            self.state.status_message = "received final response"
            if self.state.active_stream_index is None:
                if not self.state.transcript or self.state.transcript[-1].get("text") != str(final_text).strip():
                    self._append_transcript("assistant", final_text)
            return
        if event_type == "session_failed":
            self._finalize_active_stream()
            self.state.status_message = "run failed"
            self._append_transcript("system", f"session failed: {event.get('error') or event.get('message') or 'unknown error'}")
            return
        if event_type == "session_finished":
            self._finalize_active_stream()
            self.state.status_message = "run finished"

    def _frame_text(self, width: int = 100) -> str:
        return build_operator_shell_text(
            transcript=self.state.transcript,
            input_buffer=self.state.input_buffer,
            status_message=self.state.status_message,
            target=self.state.current_target,
            selected_session_id=self.state.selected_session_id,
            background_job=self.background_runs.current_job,
            width=width,
            yolo_mode=self.state.approve_dangerous,
            screen_paused=self.state.screen_paused,
            scrollback_follow_latest=self.state.scrollback_follow_latest,
            theme_name=self.config.ui.theme,
            allow_private_only=self.config.policy.allow_private_only,
        )

    def _start_background_run(self, prompt: str) -> None:
        job = self.background_runs.start_job(
            prompt=prompt,
            target=self.state.current_target,
            approve_dangerous=self.state.approve_dangerous,
            policy_allow_private_only=self.config.policy.allow_private_only,
        )
        self.state.tracked_job_token = id(job)
        self.state.processed_event_count = 0
        self.state.status_message = f"running: {_truncate(prompt, 72)}"
        self._request_redraw()

    def _resolve_session_id(self, raw: str | None = None) -> int | None:
        if raw and raw.strip():
            try:
                return int(raw.strip())
            except ValueError:
                self._append_transcript("system", f"invalid session id: {raw}")
                return None
        session_ids = self._session_ids()
        if not session_ids:
            self._append_transcript("system", "no sessions recorded yet")
            return None
        return self.state.selected_session_id or session_ids[-1]

    def _handle_report_command(self, arg: str) -> None:
        session_id = self._resolve_session_id(arg)
        if session_id is None:
            return
        try:
            path = write_session_report(self.state_db, session_id, self.config.home / "reports")
        except Exception as exc:
            self.state.status_message = "report failed"
            self._append_transcript("system", f"report failed: {exc}")
            return
        self.state.status_message = f"report written: {path}"
        self._append_transcript("system", f"report written: {path}")

    def _handle_model_command(self, arg: str) -> None:
        command_line = arg.strip()
        if not command_line:
            self._append_transcript("assistant", format_model_snapshot(build_model_snapshot(config=load_config(self.config.home))))
            return
        parts = command_line.split(maxsplit=1)
        subcommand = parts[0].lower()
        value = parts[1].strip() if len(parts) > 1 else ""
        if subcommand in {"profiles", "presets", "list"}:
            profiles = available_llm_profiles()
            lines = ["Profiles", "========"]
            for name, profile in profiles.items():
                lines.append(f"- {name}: provider={profile['provider']} model={profile['model']}")
            self._append_transcript("assistant", "\n".join(lines))
            return
        if subcommand == "profile":
            if not value:
                self._append_transcript("system", "usage: /model profile <name>")
                return
            try:
                apply_llm_profile(home=self.config.home, profile=value)
            except ValueError as exc:
                self._append_transcript("system", str(exc))
                return
            self.config = load_config(self.config.home)
            snapshot = build_model_snapshot(config=self.config)
            self.state.status_message = f"profile applied: {snapshot['profile']}"
            self._append_transcript("system", f"profile applied: {snapshot['profile']}")
            return
        if subcommand == "set":
            if not value:
                self._append_transcript("system", "usage: /model set <name>")
                return
            save_llm_config(home=self.config.home, model=value)
            self.config = load_config(self.config.home)
            self.state.status_message = f"model set: {self.config.llm.model}"
            self._append_transcript("system", f"model set: {self.config.llm.model}")
            return
        if subcommand == "provider":
            if not value:
                self._append_transcript("system", "usage: /model provider <name>")
                return
            save_llm_config(home=self.config.home, provider=value)
            self.config = load_config(self.config.home)
            self.state.status_message = f"provider set: {self.config.llm.provider}"
            self._append_transcript("system", f"provider set: {self.config.llm.provider}")
            return
        if subcommand in {"base-url", "base_url", "url"}:
            if not value:
                self._append_transcript("system", "usage: /model base-url <url>")
                return
            save_llm_config(home=self.config.home, openai_base_url=value)
            self.config = load_config(self.config.home)
            self.state.status_message = f"base_url set: {self.config.llm.openai_base_url}"
            self._append_transcript("system", f"base_url set: {self.config.llm.openai_base_url}")
            return
        if subcommand in {"fallback", "fallbacks"}:
            if not value:
                snapshot = build_model_snapshot(config=self.config)
                self._append_transcript("assistant", format_model_snapshot(snapshot))
                return
            action, _, remainder = value.partition(" ")
            action = action.strip().lower()
            remainder = remainder.strip()
            if action == "clear":
                save_llm_config(home=self.config.home, fallbacks=[])
                self.config = load_config(self.config.home)
                self.state.status_message = "fallback chain cleared"
                self._append_transcript("system", "fallback chain cleared")
                return
            if action == "add" and remainder:
                merged = [*self.config.llm.fallbacks, remainder]
                save_llm_config(home=self.config.home, fallbacks=merged)
                self.config = load_config(self.config.home)
                self.state.status_message = f"fallback added: {remainder}"
                self._append_transcript("system", f"fallback added: {remainder}")
                return
            self._append_transcript("system", "usage: /model fallback [add <provider/model>|clear]")
            return
        if subcommand == "reset":
            reset_llm_config(home=self.config.home)
            self.config = load_config(self.config.home)
            self.state.status_message = "model settings reset"
            self._append_transcript("system", "model settings reset")
            return
        self._append_transcript(
            "system",
            "usage: /model [profile <name>|profiles|set <name>|provider <name>|base-url <url>|fallback [add <provider/model>|clear]|reset]",
        )

    def _handle_theme_command(self, arg: str) -> None:
        command_line = arg.strip()
        if not command_line or command_line.lower() in {"list", "show"}:
            lines = ["Themes", "======", f"current: {self.config.ui.theme}"]
            lines.extend(f"- {name}" for name in list_theme_names())
            self._append_transcript("assistant", "\n".join(lines))
            return
        parts = command_line.split(maxsplit=1)
        subcommand = parts[0].lower()
        value = parts[1].strip() if len(parts) > 1 else ""
        if subcommand == "preview":
            theme_name = value or self.config.ui.theme
            self._append_transcript("assistant", build_theme_preview_text(theme_name))
            self.state.status_message = f"previewing theme: {get_theme(theme_name).name}"
            return
        if subcommand == "set":
            theme_name = value or subcommand
            if not theme_name:
                self._append_transcript("system", "usage: /theme set <name>")
                return
            save_ui_config(home=self.config.home, theme=theme_name)
            self.config = load_config(self.config.home)
            self.state.status_message = f"theme set: {self.config.ui.theme}"
            self._append_transcript("system", f"theme set: {self.config.ui.theme}")
            return
        save_ui_config(home=self.config.home, theme=command_line)
        self.config = load_config(self.config.home)
        self.state.status_message = f"theme set: {self.config.ui.theme}"
        self._append_transcript("system", f"theme set: {self.config.ui.theme}")

    def _handle_scope_command(self, arg: str) -> None:
        requested = arg.strip().lower()
        current_private_only = bool(self.config.policy.allow_private_only)
        if requested in {"public", "remote", "off", "false", "no"}:
            private_only = False
        elif requested in {"private", "private-only", "on", "true", "yes"}:
            private_only = True
        elif not requested:
            private_only = not current_private_only
        else:
            self._append_transcript("system", "usage: /scope [public|private]")
            return
        os.environ["ALLOW_PRIVATE_ONLY"] = "true" if private_only else "false"
        save_policy_config(home=self.config.home, allow_private_only=private_only)
        self.config = load_config(self.config.home)
        if private_only:
            self.state.status_message = "scope: private-only"
            self._append_transcript("system", "scope policy: private-only targets only")
        else:
            self.state.status_message = "scope: public targets allowed"
            self._append_transcript("system", "scope policy: public targets allowed for authorized engagements")

    def _handle_slash_command(self, text: str) -> None:
        command_line = text[1:].strip()
        if not command_line:
            self._append_transcript("assistant", build_help_text())
            return
        parts = command_line.split(maxsplit=1)
        command = parts[0].lower()
        arg = parts[1] if len(parts) > 1 else ""

        if command in {"quit", "exit", "q"}:
            self.state.should_exit = True
            return
        if command in {"help", "commands"}:
            self._append_transcript("assistant", build_help_text())
            return
        if command == "copy":
            mode = arg.strip().lower()
            if mode in {"", "transcript", "chat", "log"}:
                text = self._copy_transcript_text()
                label = "transcript"
            elif mode in {"screen", "frame", "view"}:
                text = self._copy_screen_text()
                label = "screen"
            else:
                self._append_transcript("system", "usage: /copy [transcript|screen]")
                return
            self.state.status_message = f"{label} copied to clipboard" if self._copy_to_clipboard(text) else "copy failed"
            self._request_redraw()
            return
        if command == "paste":
            mode = arg.strip().lower()
            if mode in {"", "replace", "insert"}:
                append = False
            elif mode in {"append", "add"}:
                append = True
            else:
                self._append_transcript("system", "usage: /paste [replace|append]")
                return
            if self._copy_clipboard_text_to_input(append=append):
                self.state.status_message = "clipboard pasted into prompt"
            else:
                self.state.status_message = "paste failed"
            self._request_redraw()
            return
        if command in {"pause", "freeze"}:
            self._pause_screen()
            return
        if command in {"resume", "unpause"}:
            self._resume_screen()
            return
        if command in {"clear", "new", "reset"}:
            self.state.transcript.clear()
            self.state.status_message = "transcript cleared"
            self._request_redraw()
            return
        if command == "tools":
            self._append_transcript("assistant", _build_tools_text(self.registry))
            return
        if command == "sessions":
            self._append_transcript("assistant", _build_sessions_text(self.state_db, self.state.selected_session_id))
            return
        if command == "inspect":
            session_id = self._resolve_session_id(arg)
            if session_id is not None:
                self.state.selected_session_id = session_id
                self._append_transcript("assistant", build_session_detail_text(self.state_db, session_id))
            return
        if command == "messages":
            session_id = self._resolve_session_id(arg)
            if session_id is not None:
                self.state.selected_session_id = session_id
                self._append_transcript("assistant", build_message_trace_text(self.state_db, session_id))
            return
        if command == "live":
            self._append_transcript("assistant", build_live_activity_text(self.background_runs.current_job))
            return
        if command == "doctor":
            self._append_transcript("assistant", _build_doctor_text(self.config, self.registry))
            return
        if command == "model":
            self._handle_model_command(arg)
            return
        if command == "theme":
            self._handle_theme_command(arg)
            return
        if command == "scope":
            self._handle_scope_command(arg)
            return
        if command == "target":
            if arg.strip():
                self.state.current_target = arg.strip()
                self.state.status_message = f"target set: {self.state.current_target}"
                self._append_transcript("system", f"default target set to {self.state.current_target}")
            else:
                self._append_transcript("system", f"current target: {self.state.current_target or '-'}")
            return
        if command == "report":
            self._handle_report_command(arg)
            return
        if command == "run":
            if not arg.strip():
                self._append_transcript("system", "usage: /run <task prompt>")
                return
            self._append_transcript("user", arg.strip())
            self._start_background_run(arg.strip())
            return
        if command == "yolo":
            self.state.approve_dangerous = not self.state.approve_dangerous
            mode = "enabled" if self.state.approve_dangerous else "disabled"
            self.state.status_message = f"dangerous approval {mode}"
            self._append_transcript("system", f"dangerous-tool approval {mode} for new runs")
            return

        self._append_transcript("system", f"unknown command: /{command}")

    def _submit_buffer(self) -> None:
        text = self.state.input_buffer.strip()
        self.state.input_buffer = ""
        if not text:
            return
        self.state.scrollback_offset = 0
        if text.startswith("/"):
            self._handle_slash_command(text)
            return
        self._append_transcript("user", text)
        self._start_background_run(text)

    def _ensure_theme_palette(self) -> None:
        theme = get_theme(self.config.ui.theme)
        if self._active_palette_theme == theme.name and self._color_roles:
            return
        if not curses.has_colors():
            self._color_roles = {}
            self._active_palette_theme = theme.name
            return
        try:
            curses.start_color()
            curses.use_default_colors()
        except curses.error:
            self._color_roles = {}
            self._active_palette_theme = theme.name
            return
        color_lookup = {
            "default": -1,
            "black": curses.COLOR_BLACK,
            "red": curses.COLOR_RED,
            "green": curses.COLOR_GREEN,
            "yellow": curses.COLOR_YELLOW,
            "blue": curses.COLOR_BLUE,
            "magenta": curses.COLOR_MAGENTA,
            "cyan": curses.COLOR_CYAN,
            "white": curses.COLOR_WHITE,
        }
        attr_lookup = {
            "bold": curses.A_BOLD,
            "underline": curses.A_UNDERLINE,
            "reverse": curses.A_REVERSE,
            "dim": curses.A_DIM,
        }
        role_pairs: dict[str, int] = {}
        for pair_id, (role, tone) in enumerate(theme.palette.items(), start=1):
            try:
                curses.init_pair(pair_id, color_lookup.get(tone.fg, -1), color_lookup.get(tone.bg, -1))
                attr = curses.color_pair(pair_id)
            except curses.error:
                attr = 0
            for attr_name in tone.attrs:
                attr |= attr_lookup.get(attr_name, 0)
            role_pairs[role] = attr
        self._color_roles = role_pairs
        self._active_palette_theme = theme.name

    def _line_role(self, line: str) -> str:
        theme = get_theme(self.config.ui.theme)
        stripped = line.strip()
        if not stripped:
            return "assistant"
        if line.startswith(theme.prompt_prefix):
            return "input"
        if stripped == theme.separator * len(stripped):
            return "separator"
        if line.startswith("operator > "):
            return "user"
        if line.startswith("ares     > "):
            return "assistant"
        if line.startswith(("stream   > ", "signal   > ", "embers   > ", "delta    > ")):
            return "stream"
        if line.startswith("tool     > "):
            return "tool"
        if line.startswith("result   > "):
            return "result"
        if line.startswith("status   > "):
            return "system"
        if line.startswith("target:") or line.startswith("status:") or line.startswith("commands:"):
            return "chrome"
        if stripped.startswith("Theme Preview") or stripped.startswith("Themes") or stripped.startswith("Model"):
            return "chrome"
        if any(token in line for token in ("AUTONOMOUS PENTEST OPERATIONS", "CYBERSECURITY OPERATOR SHELL")):
            return "hero"
        if any(char in stripped for char in ("#", "/", "\\")) and stripped == line.strip():
            return "hero"
        return "assistant"

    def _line_attr(self, line: str) -> int:
        return self._color_roles.get(self._line_role(line), 0)

    def _draw(self, stdscr: Any, text: str) -> None:
        stdscr.erase()
        self._ensure_theme_palette()
        height, width = stdscr.getmaxyx()
        visible_lines = text.splitlines()[-max(1, height - 1) :]
        for row, line in enumerate(visible_lines):
            try:
                stdscr.addnstr(row, 0, line, max(1, width - 1), self._line_attr(line))
            except curses.error:
                pass
        if visible_lines:
            cursor_row = min(len(visible_lines) - 1, max(0, height - 2))
            cursor_col = min(len(visible_lines[-1]), max(0, width - 1))
            try:
                stdscr.move(cursor_row, cursor_col)
            except curses.error:
                pass
        stdscr.refresh()

    def _loop(self, stdscr: Any) -> None:
        try:
            curses.curs_set(1)
        except curses.error:
            pass
        stdscr.keypad(True)
        stdscr.timeout(max(50, int(self.refresh_interval * 1000)))
        self._refresh_handles()
        while True:
            self._refresh_handles()
            _, width = stdscr.getmaxyx()
            self._draw(stdscr, self._frame_text(width=max(72, width - 1)))
            if self.state.should_exit:
                return
            key = stdscr.getch()
            if key == -1:
                continue
            if key in (27,):
                self.state.should_exit = True
                continue
            if key in (10, 13, curses.KEY_ENTER):
                self._submit_buffer()
                continue
            if key in (curses.KEY_BACKSPACE, 127, 8):
                self.state.input_buffer = self.state.input_buffer[:-1]
                continue
            if key == 21:
                self.state.input_buffer = ""
                continue
            if key in (curses.KEY_UP,):
                self._move_selection(-1)
                continue
            if key in (curses.KEY_DOWN,):
                self._move_selection(1)
                continue
            if 32 <= key <= 126:
                self.state.input_buffer += chr(key)

    def run(self) -> None:
        try:
            self._run_prompt_toolkit()
        except ImportError:
            curses.wrapper(self._loop)

    def _prompt_toolkit_body_text(self, *, columns: int | None = None, rows: int | None = None) -> str:
        return "".join(fragment[1] for fragment in self._prompt_toolkit_body_fragments(columns=columns, rows=rows)).rstrip("\n")

    def _prompt_toolkit_frame_lines(self, *, columns: int | None = None) -> tuple[list[str], int]:
        if columns is None:
            columns = shutil.get_terminal_size((100, 30)).columns
        width = min(120, max(72, int(columns) - 1))
        frame_lines = self._frame_text(width=width).splitlines()
        if frame_lines:
            frame_lines = frame_lines[:-1]
        return frame_lines, width

    def _prompt_toolkit_visible_lines(self, *, columns: int | None = None, rows: int | None = None) -> list[str]:
        self._refresh_handles()
        if rows is None:
            rows = shutil.get_terminal_size((100, 30)).lines
        height = max(1, int(rows) - 1)
        frame_lines, _ = self._prompt_toolkit_frame_lines(columns=columns)
        total_lines = len(frame_lines)
        max_offset = max(0, total_lines - height)

        if self.state.scrollback_follow_latest:
            self.state.scrollback_offset = 0
            self.state.scrollback_anchor_total_lines = total_lines
        else:
            anchor = int(self.state.scrollback_anchor_total_lines or total_lines)
            if total_lines != anchor:
                self.state.scrollback_offset = max(0, int(self.state.scrollback_offset) + (total_lines - anchor))
                self.state.scrollback_anchor_total_lines = total_lines
            if self.state.scrollback_offset <= 0:
                self._follow_latest_view(total_lines=total_lines)

        self.state.scrollback_offset = max(0, min(int(self.state.scrollback_offset), max_offset))
        end = total_lines - self.state.scrollback_offset
        start = max(0, end - height)
        return frame_lines[start:end]

    def _scroll_body(self, *, delta: int, columns: int | None = None, rows: int | None = None) -> None:
        if rows is None:
            rows = shutil.get_terminal_size((100, 30)).lines
        height = max(1, int(rows) - 1)
        frame_lines, _ = self._prompt_toolkit_frame_lines(columns=columns)
        total_lines = len(frame_lines)
        max_offset = max(0, total_lines - height)
        new_offset = max(0, min(max_offset, int(self.state.scrollback_offset) + int(delta)))
        self.state.scrollback_offset = new_offset
        if new_offset == 0:
            self._follow_latest_view(total_lines=total_lines)
        else:
            self._enter_history_view(total_lines=total_lines)
        self._request_redraw()

    def _copy_to_clipboard(self, text: str) -> bool:
        try:
            clipboard = _build_clipboard_backend()
            clipboard.set_data(ClipboardData(text))
            return True
        except Exception:
            return False

    def _copy_transcript_text(self, *, width: int | None = None) -> str:
        if width is None:
            width = shutil.get_terminal_size((100, 30)).columns
        return build_chat_transcript_text(self.state.transcript, width=max(72, int(width) - 1))

    def _copy_screen_text(self, *, width: int | None = None) -> str:
        if width is None:
            width = shutil.get_terminal_size((100, 30)).columns
        return self._prompt_toolkit_body_text(columns=max(72, int(width) - 1))

    def _prompt_toolkit_body_fragments(self, *, columns: int | None = None, rows: int | None = None) -> list[tuple[str, str] | tuple[str, str, Callable[[Any], Any]]]:
        visible_lines = self._prompt_toolkit_visible_lines(columns=columns, rows=rows)

        def mouse_handler(mouse_event: Any) -> Any:
            event_type = getattr(mouse_event, "event_type", None)
            if event_type == MouseEventType.SCROLL_UP:
                self._scroll_body(delta=_SCROLL_WHEEL_STEP, columns=columns, rows=rows)
                return None
            if event_type == MouseEventType.SCROLL_DOWN:
                self._scroll_body(delta=-_SCROLL_WHEEL_STEP, columns=columns, rows=rows)
                return None
            return NotImplemented

        fragments: list[tuple[str, str] | tuple[str, str, Callable[[Any], Any]]] = []
        for index, line in enumerate(visible_lines):
            fragments.append((f"class:{self._line_role(line)}", line, mouse_handler))
            if index < len(visible_lines) - 1:
                fragments.append(("", "\n"))
        return fragments

    def _prompt_toolkit_style(self) -> Any:
        from prompt_toolkit.styles import Style

        theme = get_theme(self.config.ui.theme)
        style_map = {
            role: _prompt_toolkit_tone_style(tone)
            for role, tone in theme.palette.items()
        }
        style_map["prompt"] = style_map.get("input", "")
        return Style.from_dict(style_map)

    def _run_prompt_toolkit(self) -> None:
        from prompt_toolkit.application import Application
        from prompt_toolkit.key_binding import KeyBindings
        from prompt_toolkit.layout import HSplit, Layout, Window
        from prompt_toolkit.layout.controls import FormattedTextControl
        from prompt_toolkit.layout.dimension import Dimension
        from prompt_toolkit.styles import DynamicStyle
        from prompt_toolkit.widgets import TextArea
        try:
            from rich.console import Console
        except Exception as exc:  # pragma: no cover - rich is a Typer dependency in normal installs
            raise ImportError("rich is required for the prompt_toolkit Ares TUI") from exc

        try:
            clipboard = _build_clipboard_backend()
        except Exception:  # pragma: no cover - clipboard backend fallback
            from prompt_toolkit.clipboard.in_memory import InMemoryClipboard

            clipboard = InMemoryClipboard()

        console = Console(force_terminal=True, color_system="auto", width=120)

        def body_text() -> list[tuple[str, str] | tuple[str, str, Callable[[Any], Any]]]:
            return self._prompt_toolkit_body_fragments()

        body = Window(
            FormattedTextControl(lambda: body_text()),
            wrap_lines=False,
            always_hide_cursor=True,
        )
        input_field = TextArea(
            height=Dimension.exact(1),
            prompt=lambda: [("class:prompt", get_theme(self.config.ui.theme).prompt_prefix)],
            multiline=False,
            style="class:input",
        )
        kb = KeyBindings()

        @kb.add("enter")
        def _(event: Any) -> None:
            self.state.input_buffer = input_field.text
            input_field.text = ""
            self._submit_buffer()
            if self.state.should_exit:
                event.app.exit()

        @kb.add("up")
        def _(event: Any) -> None:
            self._move_selection(-1)

        @kb.add("down")
        def _(event: Any) -> None:
            self._move_selection(1)

        @kb.add("pageup")
        def _(event: Any) -> None:
            self._scroll_body(delta=max(1, shutil.get_terminal_size((100, 30)).lines - 3))

        @kb.add("pagedown")
        def _(event: Any) -> None:
            self._scroll_body(delta=-max(1, shutil.get_terminal_size((100, 30)).lines - 3))

        @kb.add("c-y")
        @kb.add("s-insert")
        @kb.add("c-v")
        def _(event: Any) -> None:
            input_field.buffer.paste_clipboard_data(event.app.clipboard.get_data())

        @kb.add("home")
        def _(event: Any) -> None:
            self._scroll_body(delta=10**9)

        @kb.add("end")
        def _(event: Any) -> None:
            total_lines = len(self._prompt_toolkit_frame_lines()[0])
            self._follow_latest_view(total_lines=total_lines)
            self._request_redraw()

        @kb.add("c-c")
        @kb.add("escape")
        def _(event: Any) -> None:
            self.state.should_exit = True
            event.app.exit()

        app = Application(
            layout=Layout(HSplit([body, input_field]), focused_element=input_field),
            key_bindings=kb,
            clipboard=clipboard,
            full_screen=True,
            refresh_interval=None,
            mouse_support=True,
            style=DynamicStyle(lambda: self._prompt_toolkit_style()),
        )
        self._prompt_toolkit_app = app
        self._prompt_toolkit_input = input_field
        try:
            app.run()
        finally:
            self._prompt_toolkit_app = None
            self._prompt_toolkit_input = None


def launch_tui(*, refresh_interval: float = 0.5, yolo_mode: bool = False) -> None:
    AresTUI(refresh_interval=refresh_interval, yolo_mode=yolo_mode).run()


def main() -> None:
    launch_tui()


if __name__ == "__main__":
    main()

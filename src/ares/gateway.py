from __future__ import annotations

import ipaddress
import json
import threading
import time
import uuid
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Callable
from urllib.parse import parse_qs, urlparse

from ares.config.loader import AppConfig, GatewayConfig, load_config, resolve_gateway_mode
from ares.run import run_once
from ares.webui import build_web_ui_css, build_web_ui_html, build_web_ui_js


@dataclass
class GatewayRunState:
    id: str
    prompt: str
    target: str | None
    requested_agent: str | None
    approve_dangerous: bool
    max_iterations: int
    status: str = "queued"
    created_at: float = field(default_factory=time.time)
    started_at: float | None = None
    finished_at: float | None = None
    session_id: int | None = None
    final_response: str = ""
    error: str = ""
    saw_session_finished: bool = False
    saw_session_failed: bool = False
    thread: threading.Thread | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "prompt": self.prompt,
            "target": self.target,
            "requested_agent": self.requested_agent,
            "approve_dangerous": self.approve_dangerous,
            "max_iterations": self.max_iterations,
            "status": self.status,
            "created_at": self.created_at,
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "session_id": self.session_id,
            "final_response": self.final_response,
            "error": self.error,
        }


class AresGateway:
    def __init__(
        self,
        *,
        home: str | None = None,
        config: AppConfig | None = None,
        runner: Callable[..., Any] | None = None,
    ) -> None:
        self.config = config or load_config(home)
        self.runner = runner or run_once
        self._lock = threading.Lock()
        self._runs: dict[str, GatewayRunState] = {}
        self._events: list[dict[str, Any]] = []
        self._next_seq = 1

    def submit_run(
        self,
        *,
        prompt: str,
        target: str | None = None,
        requested_agent: str | None = None,
        approve_dangerous: bool = False,
        max_iterations: int = 20,
    ) -> dict[str, Any]:
        run_id = uuid.uuid4().hex[:12]
        state = GatewayRunState(
            id=run_id,
            prompt=prompt,
            target=target,
            requested_agent=requested_agent,
            approve_dangerous=approve_dangerous,
            max_iterations=max_iterations,
        )
        thread = threading.Thread(target=self._execute_run, args=(state,), daemon=True)
        state.thread = thread
        with self._lock:
            self._runs[run_id] = state
        thread.start()
        return state.to_dict()

    def list_runs(self) -> list[dict[str, Any]]:
        with self._lock:
            return [item.to_dict() for item in sorted(self._runs.values(), key=lambda run: run.created_at)]

    def get_run(self, run_id: str) -> dict[str, Any]:
        with self._lock:
            state = self._runs.get(run_id)
            if state is None:
                raise KeyError(run_id)
            return state.to_dict()

    def get_events(self, *, after: int = 0) -> list[dict[str, Any]]:
        with self._lock:
            return [dict(event) for event in self._events if int(event["seq"]) > int(after)]

    def wait_for_run(self, run_id: str, *, timeout: float = 30.0) -> dict[str, Any]:
        deadline = time.time() + timeout
        while time.time() < deadline:
            run = self.get_run(run_id)
            if run["status"] in {"completed", "failed"}:
                return run
            time.sleep(0.02)
        raise TimeoutError(f"run {run_id} did not finish within {timeout} seconds")

    def _execute_run(self, state: GatewayRunState) -> None:
        with self._lock:
            state.status = "running"
            state.started_at = time.time()
        try:
            result = self.runner(
                prompt=state.prompt,
                target=state.target,
                config=self.config,
                max_iterations=state.max_iterations,
                approve_dangerous=state.approve_dangerous,
                requested_agent=state.requested_agent,
                event_callback=lambda event: self._handle_runner_event(state, event),
                session_started_callback=lambda session_id: self._handle_session_started(state, session_id),
            )
            with self._lock:
                state.status = "completed"
                state.finished_at = time.time()
                state.final_response = getattr(result, "final_response", "") or ""
            if not state.saw_session_finished and not state.saw_session_failed:
                self._record_event(
                    {
                        "type": "session_finished",
                        "run_id": state.id,
                        "session_id": state.session_id,
                        "final_response": state.final_response,
                        "message": state.final_response or "completed",
                    }
                )
        except Exception as exc:
            with self._lock:
                state.status = "failed"
                state.finished_at = time.time()
                state.error = str(exc)
            if not state.saw_session_failed:
                self._record_event(
                    {
                        "type": "session_failed",
                        "run_id": state.id,
                        "session_id": state.session_id,
                        "error": str(exc),
                        "message": str(exc),
                    }
                )

    def _handle_session_started(self, state: GatewayRunState, session_id: int) -> None:
        with self._lock:
            state.session_id = int(session_id)
        self._record_event(
            {
                "type": "session_started",
                "run_id": state.id,
                "session_id": int(session_id),
                "target": state.target,
                "agent": state.requested_agent,
                "message": f"session {session_id} started",
            }
        )

    def _handle_runner_event(self, state: GatewayRunState, event: dict[str, Any]) -> None:
        event_type = str(event.get("type", ""))
        if event_type == "session_started":
            return
        payload = dict(event)
        payload.setdefault("run_id", state.id)
        if event_type == "session_finished":
            state.saw_session_finished = True
        if event_type == "session_failed":
            state.saw_session_failed = True
        self._record_event(payload)

    def _record_event(self, event: dict[str, Any]) -> None:
        with self._lock:
            payload = dict(event)
            payload["seq"] = self._next_seq
            self._next_seq += 1
            self._events.append(payload)


def gateway_mode_allows_client(mode: str | None, client_host: str | None) -> bool:
    normalized_mode = resolve_gateway_mode(mode)
    try:
        address = ipaddress.ip_address(str(client_host or "").strip())
    except ValueError:
        return False
    if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped is not None:
        address = address.ipv4_mapped
    if normalized_mode == "exposed":
        return True
    if normalized_mode == "loopback":
        return address.is_loopback
    return address.is_loopback or address.is_private or address.is_link_local


def start_gateway_server(
    gateway: AresGateway,
    *,
    host: str = "127.0.0.1",
    port: int = 8765,
    mode: str = "loopback",
) -> ThreadingHTTPServer:
    access_mode = resolve_gateway_mode(mode)
    class GatewayHandler(BaseHTTPRequestHandler):
        server_version = "AresGateway/0.1"

        def do_GET(self) -> None:  # noqa: N802
            if not self._client_allowed():
                self._reject_forbidden_client()
                return
            parsed = urlparse(self.path)
            if parsed.path == "/":
                self._send_text(build_web_ui_html(), content_type="text/html; charset=utf-8")
                return
            if parsed.path == "/app.js":
                self._send_text(build_web_ui_js(), content_type="application/javascript; charset=utf-8")
                return
            if parsed.path == "/app.css":
                self._send_text(build_web_ui_css(), content_type="text/css; charset=utf-8")
                return
            if parsed.path == "/health":
                self._send_json({"status": "ok", "runs": len(gateway.list_runs())})
                return
            if parsed.path == "/api/runs":
                self._send_json(gateway.list_runs())
                return
            if parsed.path.startswith("/api/runs/"):
                run_id = parsed.path.rsplit("/", 1)[-1]
                try:
                    self._send_json(gateway.get_run(run_id))
                except KeyError:
                    self._send_json({"error": "run_not_found"}, status=404)
                return
            if parsed.path == "/api/events":
                after = int(parse_qs(parsed.query).get("after", ["0"])[0])
                events = gateway.get_events(after=after)
                self._send_json({"count": len(events), "events": events})
                return
            self._send_json({"error": "not_found"}, status=404)

        def do_POST(self) -> None:  # noqa: N802
            if not self._client_allowed():
                self._reject_forbidden_client()
                return
            parsed = urlparse(self.path)
            if parsed.path != "/api/runs":
                self._send_json({"error": "not_found"}, status=404)
                return
            length = int(self.headers.get("Content-Length", "0"))
            raw = self.rfile.read(length) if length else b"{}"
            payload = json.loads(raw.decode("utf-8") or "{}")
            created = gateway.submit_run(
                prompt=str(payload.get("prompt", "")).strip(),
                target=payload.get("target"),
                requested_agent=payload.get("agent"),
                approve_dangerous=bool(payload.get("approve_dangerous", False)),
                max_iterations=int(payload.get("max_iterations", 20)),
            )
            self._send_json(created, status=202)

        def log_message(self, format: str, *args: Any) -> None:  # noqa: A003
            return

        def _send_json(self, payload: Any, *, status: int = 200) -> None:
            encoded = json.dumps(payload, sort_keys=True).encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(encoded)))
            self.end_headers()
            self.wfile.write(encoded)

        def _client_allowed(self) -> bool:
            return gateway_mode_allows_client(access_mode, self.client_address[0] if self.client_address else None)

        def _reject_forbidden_client(self) -> None:
            self._send_json(
                {
                    "error": "forbidden",
                    "mode": access_mode,
                    "detail": f"gateway mode {access_mode} does not allow client {self.client_address[0]}",
                },
                status=403,
            )

        def _send_text(self, payload: str, *, content_type: str, status: int = 200) -> None:
            encoded = payload.encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(encoded)))
            self.end_headers()
            self.wfile.write(encoded)

    return ThreadingHTTPServer((host, int(port)), GatewayHandler)


def serve_gateway(*, config: AppConfig | None = None, gateway: AresGateway | None = None) -> ThreadingHTTPServer:
    config = config or load_config()
    gateway = gateway or AresGateway(config=config)
    gateway_config: GatewayConfig = config.gateway
    server = start_gateway_server(
        gateway,
        host=gateway_config.host,
        port=gateway_config.port,
        mode=gateway_config.mode,
    )
    server.serve_forever()
    return server

from __future__ import annotations

import ipaddress
import json
import threading
import time
import uuid
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Callable
from urllib.parse import parse_qs, urlparse

from ares.config.loader import AppConfig, GatewayConfig, load_config, resolve_gateway_mode
from ares.dashboard import build_dashboard_css, build_dashboard_html, build_dashboard_js
from ares.gateway_auth import GatewayAuthManager, extract_bearer_token
from ares.run import run_once
from ares.secure_files import append_private_line
from ares.state.db import StateDB



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
    """Backend gateway/control-plane state and actions.

    The browser dashboard is a separate frontend surface served from
    `ares.dashboard`; this class owns runs, events, auth, pairing, and audit.
    """

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
        self.auth = GatewayAuthManager(
            auth_enabled=self.config.gateway.auth_enabled,
            operator_token=self.config.gateway.operator_token,
        )
        self.audit_log_path = Path(self.config.home) / "gateway-audit.jsonl"

    def issue_pairing_code(self, *, label: str | None = None, client_host: str | None = None) -> str:
        code = self.auth.issue_pairing_code(label=label)
        self._append_audit_event("pairing_code_issued", label=str(label or ""), client_host=client_host)
        return code

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
        self._append_audit_event(
            "run_submitted",
            run_id=run_id,
            target=target,
            requested_agent=requested_agent,
        )
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

    def login_operator(self, operator_token: str, *, client_host: str | None = None) -> str | None:
        session_token = self.auth.login(operator_token)
        self._append_audit_event(
            "auth_login_succeeded" if session_token else "auth_login_failed",
            client_host=client_host,
        )
        return session_token

    def exchange_pairing_code(self, code: str, *, client_host: str | None = None) -> str | None:
        session_token = self.auth.exchange_pairing_code(code)
        self._append_audit_event(
            "pairing_exchange_succeeded" if session_token else "pairing_exchange_failed",
            client_host=client_host,
        )
        return session_token

    def request_is_authenticated(self, authorization_header: str | None) -> bool:
        return self.auth.validate_session(extract_bearer_token(authorization_header))

    def _append_audit_event(self, event: str, **fields: Any) -> None:
        payload = {"event": event, "ts": time.time(), **fields}
        append_private_line(self.audit_log_path, json.dumps(payload, sort_keys=True) + "\n")


def _normalize_client_address(client_host: str | None) -> ipaddress._BaseAddress | None:
    try:
        address = ipaddress.ip_address(str(client_host or "").strip())
    except ValueError:
        return None
    if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped is not None:
        address = address.ipv4_mapped
    return address


def gateway_allowlist_allows_client(allow_cidrs: tuple[str, ...] | list[str] | None, client_host: str | None) -> bool:
    if not allow_cidrs:
        return True
    address = _normalize_client_address(client_host)
    if address is None:
        return False
    for raw_network in allow_cidrs:
        try:
            network = ipaddress.ip_network(str(raw_network).strip(), strict=False)
        except ValueError:
            continue
        if address in network:
            return True
    return False


def gateway_mode_allows_client(mode: str | None, client_host: str | None) -> bool:
    normalized_mode = resolve_gateway_mode(mode)
    address = _normalize_client_address(client_host)
    if address is None:
        return False
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
        server_version = "AresGateway/1.0"

        def do_GET(self) -> None:  # noqa: N802
            parsed = urlparse(self.path)
            if not self._client_allowed():
                self._reject_forbidden_client()
                return
            if not self._request_authorized(parsed.path):
                self._reject_unauthorized()
                return
            if parsed.path in {"/", "/dashboard"}:
                self._send_text(
                    build_dashboard_html(auth_required=gateway.auth.auth_required(mode=access_mode)),
                    content_type="text/html; charset=utf-8",
                )
                return
            if parsed.path == "/app.js":
                self._send_text(
                    build_dashboard_js(auth_required=gateway.auth.auth_required(mode=access_mode)),
                    content_type="application/javascript; charset=utf-8",
                )
                return
            if parsed.path == "/app.css":
                self._send_text(build_dashboard_css(), content_type="text/css; charset=utf-8")
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
            if parsed.path == "/api/mission/list":
                db = StateDB(gateway.config.home / "state.db")
                self._send_json(db.list_missions())
                return
            if parsed.path.startswith("/api/mission/"):
                parts = parsed.path.strip("/").split("/")
                if len(parts) == 3:
                    mission_id = parts[2]
                    db = StateDB(gateway.config.home / "state.db")
                    m = db.get_mission(mission_id)
                    if m:
                        self._send_json(m)
                    else:
                        self._send_json({"error": "mission_not_found"}, status=404)
                    return
                elif len(parts) == 4 and parts[3] == "report":
                    mission_id = parts[2]
                    db = StateDB(gateway.config.home / "state.db")
                    m_dict = db.get_mission(mission_id)
                    if not m_dict:
                        self._send_json({"error": "mission_not_found"}, status=404)
                        return

                    from ares.mission.model import MissionRun, MissionScope, MissionStatus, MissionPhase
                    from ares.mission.report import render_mission_report
                    scope_data = m_dict["scope"]
                    scope = MissionScope(
                        target=scope_data.get("target", ""),
                        allowed_paths=scope_data.get("allowed_paths") or [],
                        forbidden_paths=scope_data.get("forbidden_paths") or [],
                        allowed_hosts=scope_data.get("allowed_hosts") or [],
                        forbidden_actions=scope_data.get("forbidden_actions") or [],
                        max_risk=scope_data.get("max_risk", "post-exploitation"),
                    )
                    mission_run = MissionRun(
                        id=m_dict["id"],
                        profile_id=m_dict["profile_id"],
                        scope=scope,
                        status=MissionStatus(m_dict["status"]),
                        phase=MissionPhase(m_dict["phase"]),
                    )
                    tasks = db.list_mission_tasks(mission_id)
                    findings = db.list_mission_findings(mission_id)

                    with db._connection() as conn:
                        session_rows = conn.execute(
                            "SELECT DISTINCT session_id FROM mission_operator_runs WHERE mission_id = ?",
                            (mission_id,)
                        ).fetchall()
                    session_ids = [r["session_id"] for r in session_rows if r["session_id"] is not None]

                    memory_chunks = []
                    if session_ids:
                        placeholders = ",".join("?" for _ in session_ids)
                        with db._connection() as conn:
                            rows = conn.execute(
                                f"SELECT * FROM memory_chunks WHERE session_id IN ({placeholders})",
                                session_ids
                            ).fetchall()
                            for r in rows:
                                c = dict(r)
                                c["tags"] = json.loads(c.pop("tags_json"))
                                memory_chunks.append(c)

                    report = render_mission_report(
                        mission=mission_run,
                        tasks=tasks,
                        findings=findings,
                        evidence_chunks=memory_chunks,
                    )
                    self._send_json({"mission_id": mission_id, "report": report})
                    return
            self._send_json({"error": "not_found"}, status=404)

        def do_POST(self) -> None:  # noqa: N802
            parsed = urlparse(self.path)
            if not self._client_allowed():
                self._reject_forbidden_client()
                return
            if parsed.path == "/api/auth/login":
                payload = self._read_json_payload()
                session_token = gateway.login_operator(
                    str(payload.get("operator_token", "")),
                    client_host=self.client_address[0] if self.client_address else None,
                )
                if session_token is None:
                    self._send_json({"error": "unauthorized"}, status=401)
                    return
                self._send_json({"session_token": session_token}, status=200)
                return
            if parsed.path == "/api/auth/pair":
                payload = self._read_json_payload()
                session_token = gateway.exchange_pairing_code(
                    str(payload.get("code", "")),
                    client_host=self.client_address[0] if self.client_address else None,
                )
                if session_token is None:
                    self._send_json({"error": "unauthorized"}, status=401)
                    return
                self._send_json({"session_token": session_token}, status=200)
                return
            if parsed.path == "/api/auth/pairing-codes":
                if not self._request_authorized(parsed.path):
                    self._reject_unauthorized()
                    return
                payload = self._read_json_payload()
                code = gateway.issue_pairing_code(
                    label=str(payload.get("label", "")).strip() or None,
                    client_host=self.client_address[0] if self.client_address else None,
                )
                self._send_json({"code": code}, status=201)
                return
            if not self._request_authorized(parsed.path):
                self._reject_unauthorized()
                return
            if parsed.path == "/api/mission/run":
                payload = self._read_json_payload()
                profile_id = payload.get("profile_id", "secrets-audit")
                target = payload.get("target")
                if not target:
                    self._send_json({"error": "missing_target"}, status=400)
                    return
                allowed_paths = payload.get("allowed_paths") or [target]
                forbidden_paths = payload.get("forbidden_paths") or []
                allowed_hosts = payload.get("allowed_hosts") or []
                forbidden_actions = payload.get("forbidden_actions") or []
                for field_name, field_value in (
                    ("allowed_paths", allowed_paths),
                    ("forbidden_paths", forbidden_paths),
                    ("allowed_hosts", allowed_hosts),
                    ("forbidden_actions", forbidden_actions),
                ):
                    if not isinstance(field_value, list) or not all(
                        isinstance(item, str) for item in field_value
                    ):
                        self._send_json(
                            {"error": f"{field_name}_must_be_string_array"},
                            status=400,
                        )
                        return
                max_risk = str(payload.get("max_risk") or "scan")
                ghostmcp_policy_file = payload.get("ghostmcp_policy_file")
                approve_high_risk = bool(
                    payload.get("approve_high_risk", False)
                )

                requested_dry_run = bool(payload.get("dry_run", False))
                if access_mode != "loopback":
                    dry_run = True
                else:
                    dry_run = requested_dry_run

                import secrets
                import threading
                m_id = str(payload.get("mission_id") or f"m_{secrets.token_hex(4)}")

                from ares.mission.coordinator import MissionCoordinator
                from ares.mission.model import (
                    MissionPhase,
                    MissionRun,
                    MissionScope,
                    MissionStatus,
                )
                from ares.mission.tasks import parse_initial_tasks

                scope = MissionScope(
                    target=target,
                    allowed_paths=allowed_paths,
                    forbidden_paths=forbidden_paths,
                    allowed_hosts=allowed_hosts,
                    forbidden_actions=forbidden_actions,
                    max_risk=max_risk,
                )
                mission = MissionRun(
                    id=m_id,
                    profile_id=profile_id,
                    scope=scope,
                    status=MissionStatus.CREATED,
                    phase=MissionPhase.PLAN,
                )
                try:
                    coordinator = MissionCoordinator(mission)
                    initial_tasks = (
                        parse_initial_tasks(
                            payload["initial_tasks"],
                            mission_id=m_id,
                        )
                        if payload.get("initial_tasks") is not None
                        else None
                    )
                    tasks = (
                        initial_tasks
                        if initial_tasks is not None
                        else coordinator.seed_initial_tasks()
                    )
                    for task in tasks:
                        valid, reason = coordinator.validate_task(task)
                        if not valid:
                            raise ValueError(
                                f"task {task.id} failed validation: {reason}"
                            )
                    if (
                        not dry_run
                        and profile_id == "authorized-operator-validation"
                        and not ghostmcp_policy_file
                    ):
                        raise ValueError(
                            "ghostmcp_policy_file is required for authorized "
                            "operator validation"
                        )
                except Exception as exc:
                    self._send_json({"error": str(exc)}, status=400)
                    return

                if dry_run:
                    task_list = [
                        {
                            "id": task.id,
                            "role_id": task.role_id,
                            "phase": task.phase,
                            "description": task.description,
                        }
                        for task in tasks
                    ]
                    self._send_json({
                        "mission_id": m_id,
                        "profile_id": profile_id,
                        "target": target,
                        "dry_run": True,
                        "tasks": task_list
                    }, status=200)
                    return
                else:
                    def run_bg():
                        db = StateDB(gateway.config.home / "state.db")
                        try:
                            from ares.run import build_registry

                            registry = build_registry(
                                gateway.config,
                                ghostmcp_engagement_policy_file=(
                                    ghostmcp_policy_file
                                ),
                            )
                            coordinator.run_deterministic(
                                registry,
                                db,
                                initial_tasks=initial_tasks,
                                approval_callback=(
                                    (lambda _call, _entry: True)
                                    if approve_high_risk
                                    else None
                                ),
                            )
                        except Exception as exc:
                            if db.get_mission(m_id) is None:
                                db.create_mission(mission)
                            db.update_mission_status(m_id, "failed")
                            gateway._record_event(
                                {
                                    "type": "mission_failed",
                                    "mission_id": m_id,
                                    "message": str(exc),
                                }
                            )
                            gateway._append_audit_event(
                                "mission_failed",
                                mission_id=m_id,
                                error_type=type(exc).__name__,
                            )

                    t = threading.Thread(target=run_bg, daemon=True)
                    t.start()

                    self._send_json({
                        "mission_id": m_id,
                        "profile_id": profile_id,
                        "target": target,
                        "dry_run": False,
                        "status": "queued"
                    }, status=202)
                    return

            if parsed.path != "/api/runs":
                self._send_json({"error": "not_found"}, status=404)
                return
            payload = self._read_json_payload()
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

        def _read_json_payload(self) -> dict[str, Any]:
            length = int(self.headers.get("Content-Length", "0"))
            raw = self.rfile.read(length) if length else b"{}"
            payload = json.loads(raw.decode("utf-8") or "{}")
            return payload if isinstance(payload, dict) else {}

        def _client_allowed(self) -> bool:
            client_host = self.client_address[0] if self.client_address else None
            return gateway_mode_allows_client(access_mode, client_host) and gateway_allowlist_allows_client(
                gateway.config.gateway.allow_cidrs,
                client_host,
            )

        def _request_authorized(self, path: str) -> bool:
            if path in {"/", "/dashboard", "/app.js", "/app.css", "/api/auth/login", "/api/auth/pair"}:
                return True
            if not gateway.auth.auth_required(mode=access_mode):
                return True
            return gateway.request_is_authenticated(self.headers.get("Authorization"))

        def _reject_forbidden_client(self) -> None:
            self._send_json(
                {
                    "error": "forbidden",
                    "mode": access_mode,
                    "detail": f"gateway mode {access_mode} does not allow client {self.client_address[0]}",
                },
                status=403,
            )

        def _reject_unauthorized(self) -> None:
            gateway._append_audit_event(
                "auth_required_denied",
                client_host=self.client_address[0] if self.client_address else None,
                path=self.path,
            )
            self._send_json({"error": "unauthorized"}, status=401)

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

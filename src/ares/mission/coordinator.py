from __future__ import annotations

import json
import ipaddress
import time
from pathlib import Path
from typing import Any, Callable
from urllib.parse import urlparse

from ares.mission.model import MissionRun, MissionStatus
from ares.mission.tasks import MissionTask, TaskStatus, task_can_run
from ares.mission.operators import get_operator
from ares.mission.profiles import get_profile
from ares.mission.findings import MissionFinding, FindingState, Severity
from ares.mission.report import render_mission_report
from ares.mission.context import build_mission_context_pack

from ares.tools.registry import ToolRegistry
from ares.state.db import StateDB
from ares.agent.dispatcher import ToolDispatcher
from ares.agent.runtime import ToolCall
from ares.policy.context import PolicyContext
from ares.config.loader import AppConfig
from ares.policy.risk import RISK_ORDER


def is_forbidden_path(path: Path) -> bool:
    forbidden = {".git", ".env", "node_modules", ".venv", "venv", "__pycache__"}
    for part in path.parts:
        for f in forbidden:
            if f in part:
                return True
    return False


def _host_from_target(target: str) -> str:
    parsed = urlparse(target)
    if parsed.scheme and parsed.hostname:
        return parsed.hostname.lower()
    value = target.strip().strip("[]")
    if ":" in value:
        value = value.split(":", 1)[0]
    return value.lower()


def _host_is_allowed(target: str, allowed_hosts: list[str]) -> bool:
    host = _host_from_target(target)
    if not host:
        return False
    for allowed in allowed_hosts:
        candidate = allowed.strip()
        if not candidate:
            continue
        try:
            if ipaddress.ip_address(host) in ipaddress.ip_network(candidate, strict=False):
                return True
        except ValueError:
            if host == _host_from_target(candidate):
                return True
    return False


def _task_network_targets(task: MissionTask) -> list[str]:
    targets = [task.target]
    for key in ("target", "host", "ip", "url", "base_url"):
        value = task.args.get(key)
        if isinstance(value, str) and value.strip():
            targets.append(value.strip())
    for key in ("targets", "hosts", "urls"):
        value = task.args.get(key)
        if isinstance(value, list):
            targets.extend(str(item).strip() for item in value if str(item).strip())
        elif isinstance(value, str):
            targets.extend(part.strip() for part in value.replace("\n", ";").split(";") if part.strip())
    return targets


class MissionCoordinator:
    def __init__(self, mission: MissionRun):
        self.mission = mission
        self.profile = get_profile(mission.profile_id)

    def validate_task(self, task: MissionTask) -> tuple[bool, str]:
        if task.mission_id != self.mission.id:
            return False, "mission_id mismatch"
            
        if task.toolset != "redteam_report" and task.toolset not in self.profile.enabled_toolsets:
            return False, f"toolset {task.toolset} not enabled in profile"

        try:
            operator = get_operator(task.role_id)
        except ValueError as exc:
            return False, str(exc)

        if task.toolset not in operator.allowed_toolsets:
            return False, f"toolset {task.toolset} not allowed for role {task.role_id}"

        if not operator.allows_tool(task.tool_name):
            return False, f"tool {task.tool_name} not allowed for role {task.role_id}"

        if task.phase not in operator.allowed_phases:
            return False, f"phase {task.phase} not allowed for role {task.role_id}"

        profile_phases = {phase.value for phase in self.profile.phases}
        if task.phase not in profile_phases:
            return False, f"phase {task.phase} not enabled in profile"

        if self.mission.scope.max_risk not in RISK_ORDER:
            return False, f"unknown mission risk level: {self.mission.scope.max_risk}"

        if RISK_ORDER[operator.max_risk] > RISK_ORDER[self.profile.max_risk]:
            return False, (
                f"role {task.role_id} requires risk ceiling {operator.max_risk}; "
                f"profile allows {self.profile.max_risk}"
            )

        if RISK_ORDER[operator.max_risk] > RISK_ORDER[self.mission.scope.max_risk]:
            return False, (
                f"role {task.role_id} requires risk ceiling {operator.max_risk}; "
                f"mission allows {self.mission.scope.max_risk}"
            )

        if not task.target:
            return False, "target cannot be empty"

        if task.toolset == "ghostmcp":
            if not self.mission.scope.allowed_hosts:
                return False, "network task requires explicit allowed_hosts"
            for target in _task_network_targets(task):
                if not _host_is_allowed(target, self.mission.scope.allowed_hosts):
                    return False, f"network target {target!r} is outside allowed host scope"
        else:
            try:
                resolved_target = Path(task.target).resolve()
            except Exception as exc:
                return False, f"invalid target path: {exc}"

            if is_forbidden_path(resolved_target):
                return False, "target path contains forbidden components"

            for forbidden in self.mission.scope.forbidden_paths:
                try:
                    resolved_target.relative_to(Path(forbidden).resolve())
                    return False, "target path is inside forbidden scope"
                except ValueError:
                    pass

            if self.mission.scope.allowed_paths:
                is_inside = False
                for p in self.mission.scope.allowed_paths:
                    resolved_p = Path(p).resolve()
                    try:
                        resolved_target.relative_to(resolved_p)
                        is_inside = True
                        break
                    except ValueError:
                        pass
                if not is_inside:
                    return False, "target path is outside allowed scope paths"

        action_text = " ".join(
            [task.tool_name or "", task.description, json.dumps(task.args, sort_keys=True)]
        ).lower()
        for action in self.mission.scope.forbidden_actions:
            if action.strip() and action.strip().lower() in action_text:
                return False, f"task requests forbidden action: {action}"

        if not task.description or not task.description.strip():
            return False, "task description is empty"

        return True, ""

    def seed_initial_tasks(self) -> list[MissionTask]:
        tasks: list[MissionTask] = []
        m_id = self.mission.id
        target = self.mission.scope.target

        if self.mission.profile_id == "secrets-audit":
            scanner_id = f"{m_id}-scan-secrets"
            validator_id = f"{m_id}-validate-secrets"
            analyst_id = f"{m_id}-report-secrets"

            tasks.append(
                MissionTask(
                    id=scanner_id,
                    mission_id=m_id,
                    role_id="scanner",
                    phase="scan",
                    tool_name="redteam_secret_scan",
                    toolset="redteam_secrets",
                    target=target,
                    description="Scan scoped files for secrets.",
                )
            )
            tasks.append(
                MissionTask(
                    id=validator_id,
                    mission_id=m_id,
                    role_id="validator",
                    phase="validate",
                    tool_name=None,
                    toolset="redteam_secrets",
                    target=target,
                    description="Validate secret findings.",
                    depends_on=[scanner_id],
                )
            )
            tasks.append(
                MissionTask(
                    id=analyst_id,
                    mission_id=m_id,
                    role_id="analyst",
                    phase="report",
                    tool_name=None,
                    toolset="redteam_report",
                    target=target,
                    description="Generate report.",
                    depends_on=[validator_id],
                )
            )

        elif self.mission.profile_id == "dependency-audit":
            scanner_id = f"{m_id}-scan-deps"
            analyst_id = f"{m_id}-report-deps"

            tasks.append(
                MissionTask(
                    id=scanner_id,
                    mission_id=m_id,
                    role_id="scanner",
                    phase="scan",
                    tool_name="redteam_dependency_manifest_scan",
                    toolset="redteam_deps",
                    target=target,
                    description="Scan dependency manifests.",
                )
            )
            tasks.append(
                MissionTask(
                    id=analyst_id,
                    mission_id=m_id,
                    role_id="analyst",
                    phase="report",
                    tool_name=None,
                    toolset="redteam_report",
                    target=target,
                    description="Generate report.",
                    depends_on=[scanner_id],
                )
            )

        elif self.mission.profile_id == "source-code-audit":
            secret_scanner_id = f"{m_id}-scan-secrets"
            dep_scanner_id = f"{m_id}-scan-deps"
            validator_id = f"{m_id}-validate"
            analyst_id = f"{m_id}-report"

            tasks.append(
                MissionTask(
                    id=secret_scanner_id,
                    mission_id=m_id,
                    role_id="scanner",
                    phase="scan",
                    tool_name="redteam_secret_scan",
                    toolset="redteam_secrets",
                    target=target,
                    description="Scan scoped files for secrets.",
                )
            )
            tasks.append(
                MissionTask(
                    id=dep_scanner_id,
                    mission_id=m_id,
                    role_id="scanner",
                    phase="scan",
                    tool_name="redteam_dependency_manifest_scan",
                    toolset="redteam_deps",
                    target=target,
                    description="Scan dependency manifests.",
                )
            )
            tasks.append(
                MissionTask(
                    id=validator_id,
                    mission_id=m_id,
                    role_id="validator",
                    phase="validate",
                    tool_name=None,
                    toolset="redteam_secrets",
                    target=target,
                    description="Validate all findings.",
                    depends_on=[secret_scanner_id, dep_scanner_id],
                )
            )
            tasks.append(
                MissionTask(
                    id=analyst_id,
                    mission_id=m_id,
                    role_id="analyst",
                    phase="report",
                    tool_name=None,
                    toolset="redteam_report",
                    target=target,
                    description="Generate report.",
                    depends_on=[validator_id],
                )
            )

        elif self.mission.profile_id == "report-only":
            analyst_id = f"{m_id}-report-only"

            tasks.append(
                MissionTask(
                    id=analyst_id,
                    mission_id=m_id,
                    role_id="analyst",
                    phase="report",
                    tool_name=None,
                    toolset="redteam_report",
                    target=target,
                    description="Generate report.",
                )
            )

        elif self.mission.profile_id == "authorized-operator-validation":
            raise ValueError(
                "authorized-operator-validation requires explicit prevalidated tasks; "
                "no high-risk task graph is inferred"
            )

        # Validate all seeded tasks
        for task in tasks:
            valid, reason = self.validate_task(task)
            if not valid:
                raise ValueError(f"seeded task {task.id} failed validation: {reason}")

        return tasks

    def run_deterministic(
        self,
        registry: ToolRegistry,
        state_db: StateDB,
        *,
        initial_tasks: list[MissionTask] | None = None,
        approval_callback: Callable[[ToolCall, Any], bool] | None = None,
    ) -> str:
        # 1. Ensure mission exists in DB
        if state_db.get_mission(self.mission.id) is None:
            state_db.create_mission(self.mission)

        # 2. Seed initial tasks
        seeded_tasks = initial_tasks if initial_tasks is not None else self.seed_initial_tasks()

        # 3. Validate each seeded task
        for task in seeded_tasks:
            valid, reason = self.validate_task(task)
            if not valid:
                task.status = TaskStatus.BLOCKED
                task.block_reason = reason
            state_db.record_mission_task(task)

        # 4. Create ARES session
        session_id = state_db.create_session(
            prompt="Deterministic mission run",
            target=self.mission.scope.target,
        )

        # 5. Create policy
        policy = PolicyContext(
            max_risk=self.mission.scope.max_risk,
            allowed_cidrs=(
                tuple()
                if self.mission.scope.allowed_hosts
                else PolicyContext().allowed_cidrs
            ),
            allowed_hosts=tuple(self.mission.scope.allowed_hosts),
        )
        dispatcher = ToolDispatcher(
            registry=registry,
            policy=policy,
            recorder=state_db,
            session_id=session_id,
            approval_callback=approval_callback,
            engagement_id=self.mission.id,
        )

        # Execution Loop
        while True:
            tasks_db = state_db.list_mission_tasks(self.mission.id)
            completed_task_ids = {t["id"] for t in tasks_db if t["status"] == "completed"}

            runnable_task = None
            for t_dict in tasks_db:
                if t_dict["status"] in ("pending", "approved"):
                    t_obj = MissionTask(
                        id=t_dict["id"],
                        mission_id=t_dict["mission_id"],
                        role_id=t_dict["role_id"],
                        phase=t_dict["phase"],
                        tool_name=t_dict["tool_name"],
                        toolset=t_dict["toolset"],
                        target=t_dict["target"],
                        description=t_dict["description"],
                        args=t_dict["args"],
                        depends_on=t_dict["depends_on"],
                        status=TaskStatus(t_dict["status"]),
                        block_reason=t_dict.get("block_reason") or "",
                    )
                    valid, reason = self.validate_task(t_obj)
                    if not valid:
                        state_db.update_mission_task_status(t_obj.id, "blocked", reason)
                        continue
                    if task_can_run(t_obj, completed_task_ids):
                        runnable_task = t_obj
                        break

            if not runnable_task:
                break

            # Update status to RUNNING
            state_db.update_mission_task_status(runnable_task.id, "running")
            state_db.record_mission_operator_run(
                mission_id=self.mission.id,
                task_id=runnable_task.id,
                role_id=runnable_task.role_id,
                session_id=session_id,
                status="running",
            )

            if runnable_task.tool_name:
                tool_args = dict(runnable_task.args) if runnable_task.args else {}
                if runnable_task.toolset.startswith("redteam_"):
                    if "root" not in tool_args:
                        tool_args["root"] = runnable_task.target
                    if "paths" not in tool_args:
                        tool_args["paths"] = ["."]
                operator = get_operator(runnable_task.role_id)
                call = ToolCall(
                    name=runnable_task.tool_name,
                    args=tool_args,
                    required_risk=operator.max_risk,
                )
                result = dispatcher.dispatch(call)

                if result.status == "ok":
                    state_db.update_mission_task_status(runnable_task.id, "completed")

                    # Parse findings for redteam_secret_scan
                    if runnable_task.tool_name == "redteam_secret_scan":
                        with state_db._connection() as conn:
                            row = conn.execute(
                                "SELECT result_json FROM tool_calls WHERE session_id = ? AND tool = ? ORDER BY id DESC LIMIT 1",
                                (session_id, runnable_task.tool_name)
                            ).fetchone()
                        
                        raw_findings = []
                        if row and row["result_json"]:
                            try:
                                raw_output = json.loads(row["result_json"])
                                raw_findings = raw_output.get("findings", [])
                            except Exception:
                                pass

                        # Evidence chunk
                        with state_db._connection() as conn:
                            row_mem = conn.execute(
                                "SELECT id FROM memory_chunks WHERE session_id = ? ORDER BY id DESC LIMIT 1",
                                (session_id,)
                            ).fetchone()
                        evidence_chunk_id = row_mem["id"] if row_mem else None

                        for idx, f_dict in enumerate(raw_findings, 1):
                            finding_id = f"{self.mission.id}-finding-{idx}"
                            finding = MissionFinding(
                                id=finding_id,
                                mission_id=self.mission.id,
                                title=f_dict.get("title", "Possible hardcoded secret"),
                                severity=Severity(f_dict.get("severity", "medium")),
                                state=FindingState.HYPOTHESIS,
                                affected_component=f_dict.get("file", ""),
                                confidence=0.0,
                                validator_note="",
                                recommendation=f_dict.get("recommendation", "Rotate secret immediately."),
                                redacted=f_dict.get("redacted", ""),
                            )
                            if evidence_chunk_id is not None:
                                finding.add_evidence_chunk(evidence_chunk_id)

                            # Validate rule
                            is_forbidden = False
                            file_path = f_dict.get("file", "")
                            if file_path:
                                forbidden_names = {".git", ".env", "node_modules", "venv", ".venv", "__pycache__"}
                                if any(name in file_path for name in forbidden_names):
                                    is_forbidden = True

                            if evidence_chunk_id is not None and not is_forbidden:
                                finding.confidence = 0.75
                                finding.validator_note = "Validated as scoped static evidence. Manual review still required."
                                finding.validate()
                            else:
                                finding.refute("Refuted due to missing evidence or forbidden file target.")

                            state_db.record_mission_finding(finding)
                else:
                    state_db.update_mission_task_status(runnable_task.id, "failed")
            else:
                # Stub/report task without tool
                state_db.update_mission_task_status(runnable_task.id, "completed")

        # Report rendering
        final_tasks = state_db.list_mission_tasks(self.mission.id)
        final_findings = state_db.list_mission_findings(self.mission.id)
        evidence_chunks = []
        with state_db._connection() as conn:
            rows = conn.execute("SELECT * FROM memory_chunks WHERE session_id = ?", (session_id,)).fetchall()
            for r in rows:
                c = dict(r)
                c["tags"] = json.loads(c.pop("tags_json"))
                evidence_chunks.append(c)

        statuses = {task["status"] for task in final_tasks}
        if "failed" in statuses:
            self.mission.status = MissionStatus.FAILED
        elif statuses & {"blocked", "pending", "approved", "running"}:
            self.mission.status = MissionStatus.BLOCKED
        else:
            self.mission.status = MissionStatus.COMPLETED
        state_db.update_mission_status(self.mission.id, self.mission.status.value)

        return render_mission_report(
            mission=self.mission,
            tasks=final_tasks,
            findings=final_findings,
            evidence_chunks=evidence_chunks,
        )

    def run_agentic(
        self,
        *,
        config: AppConfig,
        state_db: StateDB,
        max_tasks: int = 10,
        initial_tasks: list[MissionTask] | None = None,
        approval_callback: Callable[[ToolCall, Any], bool] | None = None,
    ) -> str:
        from ares.run import build_registry
        registry = build_registry(config, state_db=state_db)

        # For the agentic path, we run exactly like run_deterministic,
        # but generating context pack and logging/stubbing model decisions.
        if state_db.get_mission(self.mission.id) is None:
            state_db.create_mission(self.mission)

        seeded_tasks = initial_tasks if initial_tasks is not None else self.seed_initial_tasks()
        for task in seeded_tasks:
            valid, reason = self.validate_task(task)
            if not valid:
                task.status = TaskStatus.BLOCKED
                task.block_reason = reason
            state_db.record_mission_task(task)

        session_id = state_db.create_session(
            prompt="Agentic mission run",
            target=self.mission.scope.target,
        )

        policy = PolicyContext(
            max_risk=self.mission.scope.max_risk,
            allowed_cidrs=(
                tuple()
                if self.mission.scope.allowed_hosts
                else PolicyContext().allowed_cidrs
            ),
            allowed_hosts=tuple(self.mission.scope.allowed_hosts),
        )
        dispatcher = ToolDispatcher(
            registry=registry,
            policy=policy,
            recorder=state_db,
            session_id=session_id,
            approval_callback=approval_callback,
            engagement_id=self.mission.id,
        )

        task_count = 0
        while task_count < max_tasks:
            tasks_db = state_db.list_mission_tasks(self.mission.id)
            completed_task_ids = {t["id"] for t in tasks_db if t["status"] == "completed"}

            runnable_task = None
            for t_dict in tasks_db:
                if t_dict["status"] in ("pending", "approved"):
                    t_obj = MissionTask(
                        id=t_dict["id"],
                        mission_id=t_dict["mission_id"],
                        role_id=t_dict["role_id"],
                        phase=t_dict["phase"],
                        tool_name=t_dict["tool_name"],
                        toolset=t_dict["toolset"],
                        target=t_dict["target"],
                        description=t_dict["description"],
                        args=t_dict["args"],
                        depends_on=t_dict["depends_on"],
                        status=TaskStatus(t_dict["status"]),
                        block_reason=t_dict.get("block_reason") or "",
                    )
                    valid, reason = self.validate_task(t_obj)
                    if not valid:
                        state_db.update_mission_task_status(t_obj.id, "blocked", reason)
                        continue
                    if task_can_run(t_obj, completed_task_ids):
                        runnable_task = t_obj
                        break

            if not runnable_task:
                break

            task_count += 1

            # Generate context pack
            findings_db = state_db.list_mission_findings(self.mission.id)
            memory_chunks = []
            with state_db._connection() as conn:
                rows = conn.execute("SELECT * FROM memory_chunks WHERE session_id = ?", (session_id,)).fetchall()
                for r in rows:
                    c = dict(r)
                    c["tags"] = json.loads(c.pop("tags_json"))
                    memory_chunks.append(c)

            _ = build_mission_context_pack(
                self.mission,
                role_id=runnable_task.role_id,
                tasks=tasks_db,
                findings=findings_db,
                memory_chunks=memory_chunks,
            )

            # Update status to RUNNING
            state_db.update_mission_task_status(runnable_task.id, "running")
            state_db.record_mission_operator_run(
                mission_id=self.mission.id,
                task_id=runnable_task.id,
                role_id=runnable_task.role_id,
                session_id=session_id,
                status="running",
            )

            if runnable_task.tool_name:
                tool_args = dict(runnable_task.args) if runnable_task.args else {}
                if runnable_task.toolset.startswith("redteam_"):
                    if "root" not in tool_args:
                        tool_args["root"] = runnable_task.target
                    if "paths" not in tool_args:
                        tool_args["paths"] = ["."]
                operator = get_operator(runnable_task.role_id)
                call = ToolCall(
                    name=runnable_task.tool_name,
                    args=tool_args,
                    required_risk=operator.max_risk,
                )
                result = dispatcher.dispatch(call)

                if result.status == "ok":
                    state_db.update_mission_task_status(runnable_task.id, "completed")

                    if runnable_task.tool_name == "redteam_secret_scan":
                        with state_db._connection() as conn:
                            row = conn.execute(
                                "SELECT result_json FROM tool_calls WHERE session_id = ? AND tool = ? ORDER BY id DESC LIMIT 1",
                                (session_id, runnable_task.tool_name)
                            ).fetchone()
                        
                        raw_findings = []
                        if row and row["result_json"]:
                            try:
                                raw_output = json.loads(row["result_json"])
                                raw_findings = raw_output.get("findings", [])
                            except Exception:
                                pass

                        with state_db._connection() as conn:
                            row_mem = conn.execute(
                                "SELECT id FROM memory_chunks WHERE session_id = ? ORDER BY id DESC LIMIT 1",
                                (session_id,)
                            ).fetchone()
                        evidence_chunk_id = row_mem["id"] if row_mem else None

                        for idx, f_dict in enumerate(raw_findings, 1):
                            finding_id = f"{self.mission.id}-finding-{idx}"
                            finding = MissionFinding(
                                id=finding_id,
                                mission_id=self.mission.id,
                                title=f_dict.get("title", "Possible hardcoded secret"),
                                severity=Severity(f_dict.get("severity", "medium")),
                                state=FindingState.HYPOTHESIS,
                                affected_component=f_dict.get("file", ""),
                                confidence=0.0,
                                validator_note="",
                                recommendation=f_dict.get("recommendation", "Rotate secret immediately."),
                                redacted=f_dict.get("redacted", ""),
                            )
                            if evidence_chunk_id is not None:
                                finding.add_evidence_chunk(evidence_chunk_id)

                            is_forbidden = False
                            file_path = f_dict.get("file", "")
                            if file_path:
                                forbidden_names = {".git", ".env", "node_modules", "venv", ".venv", "__pycache__"}
                                if any(name in file_path for name in forbidden_names):
                                    is_forbidden = True

                            if evidence_chunk_id is not None and not is_forbidden:
                                finding.confidence = 0.75
                                finding.validator_note = "Validated as scoped static evidence. Manual review still required."
                                finding.validate()
                            else:
                                finding.refute("Refuted due to missing evidence or forbidden file target.")

                            state_db.record_mission_finding(finding)
                else:
                    state_db.update_mission_task_status(runnable_task.id, "failed")
            else:
                state_db.update_mission_task_status(runnable_task.id, "completed")

        final_tasks = state_db.list_mission_tasks(self.mission.id)
        final_findings = state_db.list_mission_findings(self.mission.id)
        evidence_chunks = []
        with state_db._connection() as conn:
            rows = conn.execute("SELECT * FROM memory_chunks WHERE session_id = ?", (session_id,)).fetchall()
            for r in rows:
                c = dict(r)
                c["tags"] = json.loads(c.pop("tags_json"))
                evidence_chunks.append(c)

        statuses = {task["status"] for task in final_tasks}
        if "failed" in statuses:
            self.mission.status = MissionStatus.FAILED
        elif statuses & {"blocked", "pending", "approved", "running"}:
            self.mission.status = MissionStatus.BLOCKED
        else:
            self.mission.status = MissionStatus.COMPLETED
        state_db.update_mission_status(self.mission.id, self.mission.status.value)

        return render_mission_report(
            mission=self.mission,
            tasks=final_tasks,
            findings=final_findings,
            evidence_chunks=evidence_chunks,
        )

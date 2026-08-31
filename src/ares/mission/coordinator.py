from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any, Callable

from ares.mission.model import MissionPhase, MissionRun, MissionStatus
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
from ares.policy.context import (
    PolicyContext,
    target_is_within_allowed_hosts,
    target_to_scope_host,
)
from ares.config.loader import AppConfig
from ares.policy.risk import RISK_ORDER
from ares.mission.approvals import ADVANCED_ROLES, task_approval_digest


def is_forbidden_path(path: Path) -> bool:
    forbidden = {".git", ".env", "node_modules", ".venv", "venv", "__pycache__"}
    for part in path.parts:
        for f in forbidden:
            if f in part:
                return True
    return False


def _host_from_target(target: str) -> str:
    return target_to_scope_host(target)


def _host_is_allowed(target: str, allowed_hosts: list[str]) -> bool:
    return target_is_within_allowed_hosts(target, allowed_hosts)


def _task_network_targets(task: MissionTask) -> list[str]:
    targets = [task.target]
    for key in (
        "target", "host", "hostname", "domain", "ip", "url", "base_url"
    ):
        value = task.args.get(key)
        if isinstance(value, str) and value.strip():
            targets.append(value.strip())
    for key in ("targets", "hosts", "urls"):
        value = task.args.get(key)
        if isinstance(value, list):
            targets.extend(str(item).strip() for item in value if str(item).strip())
        elif isinstance(value, str):
            normalized = value.replace("\n", ";")
            if key != "urls":
                normalized = normalized.replace(",", ";")
            targets.extend(
                part.strip()
                for part in normalized.split(";")
                if part.strip()
            )
    return targets


class MissionCoordinator:
    def __init__(self, mission: MissionRun):
        self.mission = mission
        self.profile = get_profile(mission.profile_id)

    def _dispatcher_allowed_paths(self) -> tuple[str, ...]:
        if self.mission.scope.effective_allowed_paths:
            return self.mission.scope.effective_allowed_paths
        return ()

    def _finish_failed_mission_session(
        self,
        state_db: StateDB,
        session_id: int,
        error: Exception,
    ) -> None:
        """Close in-flight deterministic state after an unexpected error."""
        summary = str(error)
        self.mission.status = MissionStatus.FAILED
        try:
            with state_db._connection() as conn:
                running_rows = conn.execute(
                    """
                    SELECT id, task_id
                    FROM mission_operator_runs
                    WHERE mission_id = ? AND session_id = ?
                      AND status = 'running' AND finished_at IS NULL
                    ORDER BY id
                    """,
                    (self.mission.id, session_id),
                ).fetchall()

            for row in running_rows:
                try:
                    if row["task_id"] is not None:
                        state_db.update_mission_task_status(
                            row["task_id"],
                            "failed",
                            summary,
                        )
                finally:
                    state_db.finish_mission_operator_run(
                        int(row["id"]),
                        status="error",
                        summary=summary,
                    )
        finally:
            try:
                state_db.update_mission_status(
                    self.mission.id,
                    MissionStatus.FAILED.value,
                )
            finally:
                state_db.finish_session(session_id, "error")

    def _validate_existing_mission_contract(
        self, stored: dict[str, Any] | None
    ) -> None:
        if stored is None:
            return
        expected_scope = {
            "target": self.mission.scope.target,
            "allowed_paths": self.mission.scope.allowed_paths,
            "forbidden_paths": self.mission.scope.forbidden_paths,
            "allowed_hosts": self.mission.scope.allowed_hosts,
            "forbidden_actions": self.mission.scope.forbidden_actions,
            "max_risk": self.mission.scope.max_risk,
        }
        if (
            stored["profile_id"] != self.mission.profile_id
            or stored["target"] != self.mission.scope.target
            or stored["scope"] != expected_scope
            or stored["metadata"] != self.mission.metadata
        ):
            raise ValueError(
                "existing mission id is bound to a different profile, scope, "
                "or execution metadata"
            )

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

            for forbidden in self.mission.scope.effective_forbidden_paths:
                try:
                    resolved_target.relative_to(Path(forbidden))
                    return False, "target path is inside forbidden scope"
                except ValueError:
                    pass

            if self.mission.scope.effective_allowed_paths:
                is_inside = False
                for p in self.mission.scope.effective_allowed_paths:
                    try:
                        resolved_target.relative_to(Path(p))
                        is_inside = True
                        break
                    except ValueError:
                        pass
                if not is_inside:
                    return False, "target path is outside allowed scope paths"
            else:
                return False, "local task requires explicit allowed_paths"

        action_text = " ".join(
            [task.tool_name or "", task.description, json.dumps(task.args, sort_keys=True)]
        ).lower()
        for action in self.mission.scope.forbidden_actions:
            if action.strip() and action.strip().lower() in action_text:
                return False, f"task requests forbidden action: {action}"

        if not task.description or not task.description.strip():
            return False, "task description is empty"

        if (
            task.role_id in ADVANCED_ROLES
            and len(task.supporting_evidence_tool_call_ids)
            < operator.minimum_evidence_items
        ):
            return False, (
                f"role {task.role_id} requires at least "
                f"{operator.minimum_evidence_items} persisted evidence item"
            )

        return True, ""

    def _validate_advanced_authorization(
        self, task: MissionTask, state_db: StateDB
    ) -> tuple[bool, str]:
        if task.role_id not in ADVANCED_ROLES:
            return True, ""
        operator = get_operator(task.role_id)
        if (
            len(task.supporting_evidence_tool_call_ids)
            < operator.minimum_evidence_items
        ):
            return False, (
                f"role {task.role_id} requires at least "
                f"{operator.minimum_evidence_items} persisted evidence item"
            )
        if not task.approval_receipt_id:
            return False, f"role {task.role_id} requires a bound approval receipt"
        task_hosts = {
            _host_from_target(value)
            for value in _task_network_targets(task)
            if _host_from_target(value)
        }
        for evidence_id in task.supporting_evidence_tool_call_ids:
            evidence = state_db.get_mission_tool_call(
                self.mission.id, evidence_id
            )
            if evidence is None:
                return False, (
                    f"supporting evidence {evidence_id} is not bound to "
                    f"mission {self.mission.id}"
                )
            if evidence["status"] != "ok":
                return False, (
                    f"supporting evidence {evidence_id} did not complete "
                    "successfully"
                )
            try:
                evidence_result = json.loads(evidence["result_json"] or "null")
                evidence_args = json.loads(evidence["args_json"] or "{}")
            except (TypeError, json.JSONDecodeError):
                return False, (
                    f"supporting evidence {evidence_id} is malformed"
                )
            if evidence_result in (None, {}, [], ""):
                return False, (
                    f"supporting evidence {evidence_id} has no observed result"
                )
            evidence_task = MissionTask(
                id="evidence-target-check",
                mission_id=self.mission.id,
                role_id="recon",
                phase="recon",
                tool_name=str(evidence["tool"]),
                toolset="ghostmcp",
                target=str(
                    evidence_args.get("target")
                    or evidence_args.get("host")
                    or evidence_args.get("hostname")
                    or evidence_args.get("domain")
                    or evidence_args.get("url")
                    or ""
                ),
                description="evidence target check",
                args=evidence_args,
            )
            evidence_hosts = {
                _host_from_target(value)
                for value in _task_network_targets(evidence_task)
                if _host_from_target(value)
            }
            if not task_hosts.intersection(evidence_hosts):
                return False, (
                    f"supporting evidence {evidence_id} is not bound to "
                    f"task target {task.target}"
                )
        receipt = state_db.get_approval_receipt(task.approval_receipt_id)
        if receipt is None:
            return False, "bound approval receipt was not persisted"
        if receipt["mission_id"] != self.mission.id:
            return False, "approval receipt mission mismatch"
        if receipt["task_id"] != task.id:
            return False, "approval receipt task mismatch"
        if receipt["task_digest"] != task_approval_digest(task):
            return False, "approval receipt digest mismatch"
        if receipt["used_at"] is not None:
            return False, "approval receipt has already been consumed"
        if (
            receipt["expires_at"] is not None
            and float(receipt["expires_at"]) <= time.time()
        ):
            return False, "approval receipt has expired"
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
        stored_mission = state_db.get_mission(self.mission.id)
        self._validate_existing_mission_contract(stored_mission)
        if stored_mission is None:
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

        try:
            return self._run_deterministic_session(
                registry=registry,
                state_db=state_db,
                session_id=session_id,
                approval_callback=approval_callback,
            )
        except Exception as exc:
            self._finish_failed_mission_session(state_db, session_id, exc)
            raise

    def _run_deterministic_session(
        self,
        *,
        registry: ToolRegistry,
        state_db: StateDB,
        session_id: int,
        approval_callback: Callable[[ToolCall, Any], bool] | None,
    ) -> str:
        # 5. Create policy
        policy = PolicyContext(
            max_risk=self.mission.scope.max_risk,
            allowed_cidrs=(
                tuple()
                if self.mission.scope.allowed_hosts
                else PolicyContext().allowed_cidrs
            ),
            allowed_hosts=tuple(self.mission.scope.allowed_hosts),
            allowed_paths=self._dispatcher_allowed_paths(),
            forbidden_paths=self.mission.scope.effective_forbidden_paths,
            scope_bound=True,
            paths_are_bound=True,
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
                        supporting_evidence_tool_call_ids=t_dict.get(
                            "supporting_evidence_tool_call_ids", []
                        ),
                        approval_receipt_id=t_dict.get(
                            "approval_receipt_id"
                        ) or "",
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
            authorized, authorization_reason = (
                self._validate_advanced_authorization(
                    runnable_task, state_db
                )
            )
            if not authorized:
                state_db.update_mission_task_status(
                    runnable_task.id, "blocked", authorization_reason
                )
                continue
            if runnable_task.role_id in ADVANCED_ROLES:
                if not state_db.consume_approval_receipt(
                    runnable_task.approval_receipt_id
                ):
                    state_db.update_mission_task_status(
                        runnable_task.id,
                        "blocked",
                        "approval receipt could not be consumed",
                    )
                    continue
            operator_run_id = state_db.record_mission_operator_run(
                mission_id=self.mission.id,
                task_id=runnable_task.id,
                role_id=runnable_task.role_id,
                session_id=session_id,
                status="running",
            )
            state_db.update_mission_task_status(runnable_task.id, "running")

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
                                "SELECT id, result_json FROM tool_calls WHERE session_id = ? AND tool = ? ORDER BY id DESC LIMIT 1",
                                (session_id, runnable_task.tool_name)
                            ).fetchone()
                        
                        tool_call_id = int(row["id"]) if row else None
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
                                state=FindingState.OBSERVED,
                                affected_component=f_dict.get("file", ""),
                                confidence=0.0,
                                validator_note="",
                                recommendation=f_dict.get("recommendation", "Rotate secret immediately."),
                                redacted=f_dict.get("redacted", ""),
                                confidence_rationale=(
                                    "A deterministic secret-pattern scanner "
                                    "matched scoped source content."
                                ),
                                severity_rationale=(
                                    "Scanner severity is provisional until "
                                    "independent corroboration and review."
                                ),
                                reproduction_steps=[
                                    "Re-run the scoped secret-pattern scan "
                                    f"against {f_dict.get('file', '')}."
                                ],
                            )
                            if evidence_chunk_id is not None:
                                finding.add_evidence_chunk(evidence_chunk_id)
                            if tool_call_id is not None:
                                finding.add_evidence_tool_call(tool_call_id)

                            # Validate rule
                            is_forbidden = False
                            file_path = f_dict.get("file", "")
                            if file_path:
                                forbidden_names = {".git", ".env", "node_modules", "venv", ".venv", "__pycache__"}
                                if any(name in file_path for name in forbidden_names):
                                    is_forbidden = True

                            if evidence_chunk_id is not None and not is_forbidden:
                                finding.confidence = 0.6
                                finding.validator_note = (
                                    "Observed in scoped static evidence; "
                                    "independent corroboration is still required."
                                )
                                finding.hypothesize()
                            else:
                                finding.refute("Refuted due to missing evidence or forbidden file target.")

                            state_db.record_mission_finding(finding)
                    state_db.finish_mission_operator_run(
                        operator_run_id,
                        status="completed",
                    )
                else:
                    state_db.update_mission_task_status(
                        runnable_task.id,
                        "failed",
                        result.error,
                    )
                    state_db.finish_mission_operator_run(
                        operator_run_id,
                        status="failed",
                        summary=result.error,
                    )
            else:
                # Stub/report task without tool
                state_db.update_mission_task_status(runnable_task.id, "completed")
                state_db.finish_mission_operator_run(
                    operator_run_id,
                    status="completed",
                )

        # Report rendering
        final_tasks = state_db.list_mission_tasks(self.mission.id)
        final_findings = state_db.list_mission_findings(self.mission.id)
        evidence_chunks = state_db.list_mission_evidence_chunks(
            self.mission.id
        )

        statuses = {task["status"] for task in final_tasks}
        if "failed" in statuses:
            self.mission.status = MissionStatus.FAILED
        elif statuses & {"blocked", "pending", "approved", "running"}:
            self.mission.status = MissionStatus.BLOCKED
        else:
            self.mission.status = MissionStatus.COMPLETED
        state_db.update_mission_status(self.mission.id, self.mission.status.value)

        report = render_mission_report(
            mission=self.mission,
            tasks=final_tasks,
            findings=final_findings,
            evidence_chunks=evidence_chunks,
        )
        state_db.finish_session(session_id, self.mission.status.value)
        return report

    def run_agentic(
        self,
        *,
        config: AppConfig,
        state_db: StateDB,
        model: Any | None = None,
        registry: ToolRegistry | None = None,
        max_tasks: int = 20,
        approval_callback: Callable[[ToolCall, Any], bool] | None = None,
    ) -> str:
        """Run a model-planned mission through deterministic governance.

        The model selects only from pending coverage IDs. Trusted code compiles
        that choice into a fixed capability, tool, target, and argument set
        before the existing task validator and dispatcher can execute it.
        """
        from ares.autonomy.catalog import ReconCapabilityCatalog
        from ares.autonomy.coverage import CoverageLedger, CoverageStatus
        from ares.autonomy.graph import AttackSurfaceGraph, NodeKind
        from ares.autonomy.planner import MissionPlanner
        from ares.autonomy.projector import AttackSurfaceProjector
        from ares.autonomy.recovery import ReconRecoveryPolicy
        from ares.autonomy.findings import AutonomousFindingManager
        from ares.run import build_model, build_registry

        if self.mission.profile_id != "autonomous-recon":
            raise ValueError(
                "model-driven planning is currently supported only by the "
                "autonomous-recon profile"
            )
        if not self.mission.scope.allowed_hosts:
            raise ValueError(
                "autonomous network missions require explicit allowed_hosts"
            )
        if not _host_is_allowed(
            self.mission.scope.target,
            self.mission.scope.allowed_hosts,
        ):
            raise ValueError("mission target is outside explicit allowed_hosts")
        if max_tasks < 1:
            raise ValueError("max_tasks must be at least 1")

        stored_mission = state_db.get_mission(self.mission.id)
        self._validate_existing_mission_contract(stored_mission)
        if stored_mission is None:
            state_db.create_mission(self.mission)
        state_db.update_mission_status(
            self.mission.id,
            MissionStatus.RUNNING.value,
            "plan",
        )
        self.mission.status = MissionStatus.RUNNING

        session_id = state_db.create_session(
            prompt="Autonomous recon mission",
            target=self.mission.scope.target,
            agent="mission-planner",
            model=config.llm.model,
            mode="safe-active",
        )
        effective_registry = registry or build_registry(
            config,
            state_db=state_db,
            session_id=session_id,
        )
        effective_model = model or build_model(config)
        policy = PolicyContext(
            max_risk=self.mission.scope.max_risk,
            allowed_cidrs=(),
            allowed_hosts=tuple(self.mission.scope.allowed_hosts),
            allowed_paths=(),
            forbidden_paths=self.mission.scope.effective_forbidden_paths,
            scope_bound=True,
            paths_are_bound=True,
        )
        dispatcher = ToolDispatcher(
            registry=effective_registry,
            policy=policy,
            recorder=state_db,
            session_id=session_id,
            approval_callback=approval_callback,
            engagement_id=self.mission.id,
        )

        graph = AttackSurfaceGraph(state_db, self.mission.id)
        target_host = _host_from_target(self.mission.scope.target)
        graph.upsert_node(
            kind=NodeKind.HOST,
            key=target_host,
            label=target_host,
            attributes={"address": target_host, "scope_root": True},
        )
        coverage = CoverageLedger(
            state_db,
            self.mission.id,
            graph,
            port_scope=str(
                self.mission.metadata.get("port_scope") or "1-1000"
            ),
        )
        coverage.refresh_requirements()
        planner = MissionPlanner(
            model=effective_model,
            state_db=state_db,
            mission_id=self.mission.id,
            session_id=session_id,
            graph=graph,
            coverage=coverage,
        )
        projector = AttackSurfaceProjector(
            state_db,
            self.mission.id,
            session_id,
            graph,
        )
        catalog = ReconCapabilityCatalog()
        recovery = ReconRecoveryPolicy(
            state_db=state_db,
            mission_id=self.mission.id,
            target_allowed=lambda value: _host_is_allowed(
                value, self.mission.scope.allowed_hosts
            ),
        )
        finding_manager = AutonomousFindingManager(
            state_db, self.mission.id, graph
        )
        start_cycle = (
            len(state_db.list_planner_cycles(self.mission.id)) + 1
        )
        tool_tasks_used = 0

        try:
            for cycle in range(start_cycle, start_cycle + max_tasks):
                if tool_tasks_used >= max_tasks:
                    break
                coverage.refresh_requirements()
                decision = planner.plan_next(cycle=cycle)
                if decision.stop:
                    break
                pending_by_id = {
                    item["id"]: item for item in coverage.pending()
                }
                coverage_item = pending_by_id.get(decision.coverage_id or "")
                if coverage_item is None:
                    raise RuntimeError(
                        "governed planner decision no longer references "
                        "pending coverage"
                    )
                task = catalog.compile(
                    mission_id=self.mission.id,
                    cycle=cycle,
                    coverage_item=coverage_item,
                )
                valid, reason = self.validate_task(task)
                if not valid:
                    task.status = TaskStatus.BLOCKED
                    task.block_reason = reason
                    state_db.record_mission_task(task)
                    coverage.update(
                        coverage_item["id"],
                        status=CoverageStatus.BLOCKED,
                        last_error=reason,
                    )
                    continue

                state_db.record_mission_task(task)
                coverage.update(
                    coverage_item["id"],
                    status=CoverageStatus.RUNNING,
                    increment_attempts=True,
                )
                state_db.update_mission_task_status(task.id, "running")
                operator_run_id = state_db.record_mission_operator_run(
                    mission_id=self.mission.id,
                    task_id=task.id,
                    role_id=task.role_id,
                    session_id=session_id,
                    status="running",
                    summary=decision.reason,
                )
                operator = get_operator(task.role_id)
                tool_tasks_used += 1
                result = dispatcher.dispatch(
                    ToolCall(
                        name=task.tool_name or "",
                        args=dict(task.args),
                        required_risk=operator.max_risk,
                    )
                )
                calls = state_db.list_tool_calls(session_id)
                tool_call_id = int(calls[-1]["id"]) if calls else None
                evidence_ids = [tool_call_id] if tool_call_id is not None else []

                if result.status == "ok":
                    state_db.update_mission_task_status(task.id, "completed")
                    coverage.update(
                        coverage_item["id"],
                        status=CoverageStatus.COMPLETE,
                        evidence_tool_call_ids=evidence_ids,
                    )
                    if tool_call_id is not None:
                        projector.project_tool_call(tool_call_id)
                    state_db.finish_mission_operator_run(
                        operator_run_id,
                        status="completed",
                        summary=decision.reason,
                    )
                else:
                    state_db.update_mission_task_status(
                        task.id,
                        "failed",
                        result.error,
                    )
                    decision_recovery = recovery.decide(
                        original_task=task,
                        coverage_item=coverage_item,
                        original_tool_call_id=tool_call_id,
                    )
                    recovery_attempt_id = state_db.record_recovery_attempt(
                        mission_id=self.mission.id,
                        coverage_id=coverage_item["id"],
                        original_tool_call_id=tool_call_id,
                        recovery_tool_call_id=None,
                        strategy=decision_recovery.strategy,
                        status="reserved",
                        reason=decision_recovery.reason,
                    )
                    recovery_task = decision_recovery.task
                    recovery_call_id = None
                    recovery_status = "not_applicable"
                    recovery_error = decision_recovery.reason
                    if recovery_attempt_id == 0:
                        recovery_task = None
                        recovery_status = "inconclusive"
                        recovery_error = (
                            "bounded recovery was already reserved or attempted"
                        )
                    elif (
                        recovery_task is None
                        and decision_recovery.strategy
                        == "preserve_http_response"
                    ):
                        recovery_status = "completed"
                        recovery_error = ""
                        coverage.update(
                            coverage_item["id"],
                            status=CoverageStatus.COMPLETE,
                            evidence_tool_call_ids=evidence_ids,
                        )
                    elif (
                        recovery_task is not None
                        and tool_tasks_used >= max_tasks
                    ):
                        recovery_status = "inconclusive"
                        recovery_error = (
                            "bounded recovery was not dispatched because the "
                            "autonomous tool-task budget was exhausted"
                        )
                    elif recovery_task is not None:
                        recovery_valid, recovery_reason = self.validate_task(
                            recovery_task
                        )
                        if recovery_valid:
                            state_db.record_mission_task(recovery_task)
                            state_db.update_mission_task_status(
                                recovery_task.id, "running"
                            )
                            tool_tasks_used += 1
                            recovery_result = dispatcher.dispatch(
                                ToolCall(
                                    name=recovery_task.tool_name or "",
                                    args=dict(recovery_task.args),
                                    required_risk="active",
                                )
                            )
                            calls = state_db.list_tool_calls(session_id)
                            recovery_call_id = (
                                int(calls[-1]["id"]) if calls else None
                            )
                            if recovery_result.status == "ok":
                                recovery_status = "completed"
                                recovery_error = ""
                                state_db.update_mission_task_status(
                                    recovery_task.id, "completed"
                                )
                                coverage.update(
                                    coverage_item["id"],
                                    status=CoverageStatus.COMPLETE,
                                    evidence_tool_call_ids=[
                                        value for value in
                                        (tool_call_id, recovery_call_id)
                                        if value is not None
                                    ],
                                )
                                if recovery_call_id is not None:
                                    projector.project_tool_call(
                                        recovery_call_id
                                    )
                            else:
                                recovery_status = "inconclusive"
                                recovery_error = recovery_result.error
                                state_db.update_mission_task_status(
                                    recovery_task.id,
                                    "failed",
                                    recovery_result.error,
                                )
                        else:
                            recovery_status = "blocked"
                            recovery_error = recovery_reason
                    if recovery_attempt_id:
                        state_db.update_recovery_attempt(
                            recovery_attempt_id,
                            recovery_tool_call_id=recovery_call_id,
                            status=recovery_status,
                            reason=recovery_error,
                        )
                    if recovery_status != "completed":
                        coverage.update(
                            coverage_item["id"],
                            status=CoverageStatus.INCONCLUSIVE,
                            evidence_tool_call_ids=[
                                value for value in
                                (tool_call_id, recovery_call_id)
                                if value is not None
                            ],
                            last_error=recovery_error,
                        )
                    state_db.finish_mission_operator_run(
                        operator_run_id,
                        status=(
                            "completed"
                            if recovery_status == "completed" else "failed"
                        ),
                        summary=(
                            decision_recovery.reason
                            if recovery_status == "completed"
                            else recovery_error
                        ),
                    )
                finding_manager.refresh()
            coverage.refresh_requirements()
        except Exception:
            self.mission.status = MissionStatus.FAILED
            self.mission.phase = MissionPhase.REPORT
            state_db.update_mission_status(
                self.mission.id,
                MissionStatus.FAILED.value,
                "report",
            )
            state_db.finish_session(session_id, "error")
            raise

        if coverage.required_open():
            self.mission.status = MissionStatus.BLOCKED
        else:
            self.mission.status = MissionStatus.COMPLETED
        self.mission.phase = MissionPhase.REPORT
        state_db.update_mission_status(
            self.mission.id,
            self.mission.status.value,
            "report",
        )
        state_db.finish_session(
            session_id,
            (
                "final_response"
                if self.mission.status == MissionStatus.COMPLETED
                else "blocked"
            ),
        )

        tasks = state_db.list_mission_tasks(self.mission.id)
        findings = state_db.list_mission_findings(self.mission.id)
        evidence_chunks = state_db.list_mission_evidence_chunks(
            self.mission.id
        )
        return render_mission_report(
            mission=self.mission,
            tasks=tasks,
            findings=findings,
            evidence_chunks=evidence_chunks,
            attack_surface_nodes=graph.nodes(),
            attack_surface_edges=graph.edges(),
            coverage_items=coverage.items(),
            planner_cycles=state_db.list_planner_cycles(self.mission.id),
            recovery_attempts=state_db.list_recovery_attempts(
                self.mission.id
            ),
        )

    def run_contextual_deterministic(
        self,
        *,
        config: AppConfig,
        state_db: StateDB,
        max_tasks: int = 10,
        initial_tasks: list[MissionTask] | None = None,
        approval_callback: Callable[[ToolCall, Any], bool] | None = None,
    ) -> str:
        if self.mission.profile_id == "authorized-operator-validation":
            raise ValueError(
                "advanced roles require the receipt-enforced deterministic "
                "mission workflow"
            )
        from ares.run import build_registry
        registry = build_registry(config, state_db=state_db)

        # This deterministic path builds bounded context packs for future
        # planning integrations but never asks a model to create or alter tasks.
        stored_mission = state_db.get_mission(self.mission.id)
        self._validate_existing_mission_contract(stored_mission)
        if stored_mission is None:
            state_db.create_mission(self.mission)

        seeded_tasks = initial_tasks if initial_tasks is not None else self.seed_initial_tasks()
        for task in seeded_tasks:
            valid, reason = self.validate_task(task)
            if not valid:
                task.status = TaskStatus.BLOCKED
                task.block_reason = reason
            state_db.record_mission_task(task)

        session_id = state_db.create_session(
            prompt="Contextual deterministic mission run",
            target=self.mission.scope.target,
        )

        try:
            return self._run_contextual_deterministic_session(
                registry=registry,
                state_db=state_db,
                session_id=session_id,
                max_tasks=max_tasks,
                approval_callback=approval_callback,
            )
        except Exception as exc:
            self._finish_failed_mission_session(state_db, session_id, exc)
            raise

    def _run_contextual_deterministic_session(
        self,
        *,
        registry: ToolRegistry,
        state_db: StateDB,
        session_id: int,
        max_tasks: int,
        approval_callback: Callable[[ToolCall, Any], bool] | None,
    ) -> str:
        policy = PolicyContext(
            max_risk=self.mission.scope.max_risk,
            allowed_cidrs=(
                tuple()
                if self.mission.scope.allowed_hosts
                else PolicyContext().allowed_cidrs
            ),
            allowed_hosts=tuple(self.mission.scope.allowed_hosts),
            allowed_paths=self._dispatcher_allowed_paths(),
            forbidden_paths=self.mission.scope.effective_forbidden_paths,
            scope_bound=True,
            paths_are_bound=True,
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
                        supporting_evidence_tool_call_ids=t_dict.get(
                            "supporting_evidence_tool_call_ids", []
                        ),
                        approval_receipt_id=t_dict.get(
                            "approval_receipt_id"
                        ) or "",
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
            operator_run_id = state_db.record_mission_operator_run(
                mission_id=self.mission.id,
                task_id=runnable_task.id,
                role_id=runnable_task.role_id,
                session_id=session_id,
                status="running",
            )
            state_db.update_mission_task_status(runnable_task.id, "running")

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
                                "SELECT id, result_json FROM tool_calls WHERE session_id = ? AND tool = ? ORDER BY id DESC LIMIT 1",
                                (session_id, runnable_task.tool_name)
                            ).fetchone()
                        
                        tool_call_id = int(row["id"]) if row else None
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
                                state=FindingState.OBSERVED,
                                affected_component=f_dict.get("file", ""),
                                confidence=0.0,
                                validator_note="",
                                recommendation=f_dict.get("recommendation", "Rotate secret immediately."),
                                redacted=f_dict.get("redacted", ""),
                                confidence_rationale=(
                                    "A deterministic secret-pattern scanner "
                                    "matched scoped source content."
                                ),
                                severity_rationale=(
                                    "Scanner severity is provisional until "
                                    "independent corroboration and review."
                                ),
                                reproduction_steps=[
                                    "Re-run the scoped secret-pattern scan "
                                    f"against {f_dict.get('file', '')}."
                                ],
                            )
                            if evidence_chunk_id is not None:
                                finding.add_evidence_chunk(evidence_chunk_id)
                            if tool_call_id is not None:
                                finding.add_evidence_tool_call(tool_call_id)

                            is_forbidden = False
                            file_path = f_dict.get("file", "")
                            if file_path:
                                forbidden_names = {".git", ".env", "node_modules", "venv", ".venv", "__pycache__"}
                                if any(name in file_path for name in forbidden_names):
                                    is_forbidden = True

                            if evidence_chunk_id is not None and not is_forbidden:
                                finding.confidence = 0.6
                                finding.validator_note = (
                                    "Observed in scoped static evidence; "
                                    "independent corroboration is still required."
                                )
                                finding.hypothesize()
                            else:
                                finding.refute("Refuted due to missing evidence or forbidden file target.")

                            state_db.record_mission_finding(finding)
                    state_db.finish_mission_operator_run(
                        operator_run_id,
                        status="completed",
                    )
                else:
                    state_db.update_mission_task_status(
                        runnable_task.id,
                        "failed",
                        result.error,
                    )
                    state_db.finish_mission_operator_run(
                        operator_run_id,
                        status="failed",
                        summary=result.error,
                    )
            else:
                state_db.update_mission_task_status(runnable_task.id, "completed")
                state_db.finish_mission_operator_run(
                    operator_run_id,
                    status="completed",
                )

        final_tasks = state_db.list_mission_tasks(self.mission.id)
        final_findings = state_db.list_mission_findings(self.mission.id)
        evidence_chunks = state_db.list_mission_evidence_chunks(
            self.mission.id
        )

        statuses = {task["status"] for task in final_tasks}
        if "failed" in statuses:
            self.mission.status = MissionStatus.FAILED
        elif statuses & {"blocked", "pending", "approved", "running"}:
            self.mission.status = MissionStatus.BLOCKED
        else:
            self.mission.status = MissionStatus.COMPLETED
        state_db.update_mission_status(self.mission.id, self.mission.status.value)

        report = render_mission_report(
            mission=self.mission,
            tasks=final_tasks,
            findings=final_findings,
            evidence_chunks=evidence_chunks,
        )
        state_db.finish_session(session_id, self.mission.status.value)
        return report

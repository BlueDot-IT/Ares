from __future__ import annotations

import hashlib
import json
import tempfile
from importlib import resources
from pathlib import Path
from typing import Any, Callable

from ares.mission.coordinator import MissionCoordinator
from ares.mission.findings import FindingState, MissionFinding, Severity
from ares.mission.model import MissionRun, MissionScope
from ares.mission.tasks import MissionTask
from ares.secure_files import write_private_text
from ares.state.db import StateDB
from ares.tools.registry import ToolRegistry


RESULT_SCHEMA = "ares.evaluation.result.v1"
FIXTURE_RESOURCE = "fixtures/v1.json"

_REASON_CODES = (
    ("outside allowed scope paths", "outside_allowed_paths"),
    ("outside allowed host scope", "outside_allowed_hosts"),
    ("inside forbidden scope", "inside_forbidden_path"),
    ("contains forbidden components", "forbidden_path_component"),
    ("requests forbidden action", "forbidden_action"),
    ("mission allows", "exceeds_mission_risk"),
    ("profile allows", "exceeds_profile_risk"),
    ("requires explicit allowed_hosts", "missing_allowed_hosts"),
    ("mission_id mismatch", "mission_id_mismatch"),
)


def _load_bundled_corpus() -> tuple[dict[str, Any], str]:
    fixture = resources.files("ares.evaluation").joinpath(FIXTURE_RESOURCE)
    raw = fixture.read_bytes()
    payload = json.loads(raw)
    if not isinstance(payload, dict):
        raise ValueError("evaluation corpus must be a JSON object")
    _validate_corpus(payload)
    return payload, hashlib.sha256(raw).hexdigest()


def _validate_corpus(corpus: dict[str, Any]) -> None:
    if not isinstance(corpus.get("corpus_id"), str):
        raise ValueError("evaluation corpus_id must be a string")
    if not isinstance(corpus.get("corpus_version"), str):
        raise ValueError("evaluation corpus_version must be a string")
    suites = corpus.get("suites")
    if not isinstance(suites, list) or not suites:
        raise ValueError("evaluation corpus must contain suites")

    known_evaluators = {
        "mission_outcome",
        "scope_policy",
        "finding_readiness",
    }
    suite_ids: set[str] = set()
    case_ids: set[str] = set()
    for suite in suites:
        if not isinstance(suite, dict):
            raise ValueError("evaluation suite must be a JSON object")
        suite_id = suite.get("id")
        if not isinstance(suite_id, str) or not suite_id:
            raise ValueError("evaluation suite id must be a non-empty string")
        if suite_id in suite_ids:
            raise ValueError(f"duplicate evaluation suite id: {suite_id}")
        suite_ids.add(suite_id)
        if suite.get("evaluator") not in known_evaluators:
            raise ValueError(f"unknown evaluation suite evaluator: {suite.get('evaluator')}")
        cases = suite.get("cases")
        if not isinstance(cases, list) or not cases:
            raise ValueError(f"evaluation suite {suite_id} must contain cases")
        for case in cases:
            if not isinstance(case, dict):
                raise ValueError("evaluation case must be a JSON object")
            case_id = case.get("id")
            if not isinstance(case_id, str) or not case_id:
                raise ValueError("evaluation case id must be a non-empty string")
            if case_id in case_ids:
                raise ValueError(f"duplicate evaluation case id: {case_id}")
            case_ids.add(case_id)
            if not isinstance(case.get("expected"), dict):
                raise ValueError(f"evaluation case {case_id} must define expected")


def _offline_fixture_failure(_args: dict[str, Any], **_context: Any) -> Any:
    raise RuntimeError("intentional offline fixture failure")


def _mission_fixture(case: dict[str, Any]) -> dict[str, Any]:
    scenario = case.get("scenario")
    fixture_root = "/ares-evaluation/fixture-project"
    mission_id = f"evaluation-{case['id']}"
    registry = ToolRegistry()

    if scenario == "report_task_success":
        mission = MissionRun(
            id=mission_id,
            profile_id="report-only",
            scope=MissionScope(
                target=fixture_root,
                allowed_paths=[fixture_root],
                max_risk="safe",
            ),
        )
        task = MissionTask(
            id=f"{mission_id}-report",
            mission_id=mission_id,
            role_id="analyst",
            phase="report",
            tool_name=None,
            toolset="redteam_report",
            target=fixture_root,
            description="Summarize the bounded fixture evidence.",
        )
    elif scenario == "blocked_outside_scope":
        mission = MissionRun(
            id=mission_id,
            profile_id="report-only",
            scope=MissionScope(
                target=fixture_root,
                allowed_paths=[fixture_root],
                max_risk="safe",
            ),
        )
        task = MissionTask(
            id=f"{mission_id}-report",
            mission_id=mission_id,
            role_id="analyst",
            phase="report",
            tool_name=None,
            toolset="redteam_report",
            target="/ares-evaluation/outside-project",
            description="Summarize an unscoped fixture path.",
        )
    elif scenario == "tool_failure":
        mission = MissionRun(
            id=mission_id,
            profile_id="source-code-audit",
            scope=MissionScope(
                target=fixture_root,
                allowed_paths=[fixture_root],
                max_risk="scan",
            ),
        )
        task = MissionTask(
            id=f"{mission_id}-scan",
            mission_id=mission_id,
            role_id="scanner",
            phase="scan",
            tool_name="offline_fixture_scan",
            toolset="redteam_static",
            target=fixture_root,
            description="Run the intentional offline failure fixture.",
        )
        registry.register(
            name="offline_fixture_scan",
            toolset="redteam_static",
            risk="scan",
            schema={"type": "object"},
            handler=_offline_fixture_failure,
        )
    else:
        raise ValueError(f"unknown mission evaluation scenario: {scenario}")

    with tempfile.TemporaryDirectory(prefix="ares-evaluation-") as tmp:
        state_db = StateDB(Path(tmp) / "state.db")
        MissionCoordinator(mission).run_deterministic(
            registry,
            state_db,
            initial_tasks=[task],
        )
        stored_mission = state_db.get_mission(mission.id)
        tasks = state_db.list_mission_tasks(mission.id)

    return {
        "mission_status": stored_mission["status"],
        "task_statuses": sorted(str(task_row["status"]) for task_row in tasks),
    }


def _reason_code(*, allowed: bool, reason: str) -> str:
    if allowed:
        return "allowed"
    for fragment, code in _REASON_CODES:
        if fragment in reason:
            return code
    return "other_rejection"


def _scope_policy_fixture(case: dict[str, Any]) -> dict[str, Any]:
    mission_data = case.get("mission")
    task_data = case.get("task")
    if not isinstance(mission_data, dict) or not isinstance(task_data, dict):
        raise ValueError("scope policy fixture requires mission and task objects")

    mission_id = f"evaluation-{case['id']}"
    mission = MissionRun(
        id=mission_id,
        profile_id=str(mission_data["profile_id"]),
        scope=MissionScope(
            target=str(mission_data["target"]),
            allowed_paths=list(mission_data.get("allowed_paths") or []),
            forbidden_paths=list(mission_data.get("forbidden_paths") or []),
            allowed_hosts=list(mission_data.get("allowed_hosts") or []),
            forbidden_actions=list(mission_data.get("forbidden_actions") or []),
            max_risk=str(mission_data.get("max_risk") or "scan"),
        ),
    )
    task = MissionTask(
        id=f"{mission_id}-task",
        mission_id=mission_id,
        role_id=str(task_data["role_id"]),
        phase=str(task_data["phase"]),
        tool_name=(
            str(task_data["tool_name"])
            if task_data.get("tool_name") is not None
            else None
        ),
        toolset=str(task_data["toolset"]),
        target=str(task_data["target"]),
        description=str(task_data["description"]),
        args=dict(task_data.get("args") or {}),
        supporting_evidence_tool_call_ids=list(
            task_data.get("supporting_evidence_tool_call_ids") or []
        ),
    )
    allowed, reason = MissionCoordinator(mission).validate_task(task)
    return {
        "allowed": allowed,
        "reason_code": _reason_code(allowed=allowed, reason=reason),
    }


def _finding_fixture(case: dict[str, Any]) -> dict[str, Any]:
    finding_data = case.get("finding")
    if not isinstance(finding_data, dict):
        raise ValueError("finding readiness fixture requires a finding object")
    finding = MissionFinding(
        id=f"evaluation-{case['id']}",
        mission_id="evaluation-finding-readiness",
        title="Offline fixture observation",
        severity=Severity.MEDIUM,
        state=FindingState(str(finding_data.get("state") or "observed")),
        evidence_chunk_ids=list(finding_data.get("evidence_chunk_ids") or []),
        evidence_tool_call_ids=list(
            finding_data.get("evidence_tool_call_ids") or []
        ),
        contradictory_evidence_tool_call_ids=list(
            finding_data.get("contradictory_evidence_tool_call_ids") or []
        ),
        contradiction_resolution=str(
            finding_data.get("contradiction_resolution") or ""
        ),
        reproduction_steps=list(finding_data.get("reproduction_steps") or []),
        confidence=float(finding_data.get("confidence") or 0.0),
        confidence_rationale=str(
            finding_data.get("confidence_rationale") or ""
        ),
        severity_rationale=str(finding_data.get("severity_rationale") or ""),
        validator_note=str(finding_data.get("validator_note") or ""),
        version_only=bool(finding_data.get("version_only", False)),
    )
    return {"ready_for_safe_validation": finding.can_validate()}


_EVALUATORS: dict[str, Callable[[dict[str, Any]], dict[str, Any]]] = {
    "mission_outcome": _mission_fixture,
    "scope_policy": _scope_policy_fixture,
    "finding_readiness": _finding_fixture,
}


def _run_case(
    evaluator: Callable[[dict[str, Any]], dict[str, Any]],
    case: dict[str, Any],
) -> dict[str, Any]:
    expected = dict(case["expected"])
    try:
        observed = evaluator(case)
    except Exception:
        # Evaluation output is intentionally bounded and must not echo an
        # exception that could contain a local path or environment detail.
        observed = {"error_code": "fixture_execution_error"}
    return {
        "id": case["id"],
        "passed": observed == expected,
        "expected": expected,
        "observed": observed,
    }


def run_evaluation() -> dict[str, Any]:
    """Run the bundled, deterministic fixture corpus without network access."""
    corpus, corpus_sha256 = _load_bundled_corpus()
    suite_results: list[dict[str, Any]] = []
    total_passed = 0
    total_cases = 0

    for suite in corpus["suites"]:
        evaluator = _EVALUATORS[str(suite["evaluator"])]
        case_results = [_run_case(evaluator, case) for case in suite["cases"]]
        passed = sum(1 for case in case_results if case["passed"])
        total = len(case_results)
        total_passed += passed
        total_cases += total
        suite_results.append(
            {
                "id": suite["id"],
                "name": suite["name"],
                "passed": passed,
                "failed": total - passed,
                "total": total,
                "cases": case_results,
            }
        )

    failed = total_cases - total_passed
    return {
        "schema": RESULT_SCHEMA,
        "corpus": {
            "id": corpus["corpus_id"],
            "version": corpus["corpus_version"],
            "sha256": corpus_sha256,
        },
        "execution": {
            "mode": "offline",
            "deterministic": True,
            "uses_model": False,
            "uses_network": False,
        },
        "result": "pass" if failed == 0 else "fail",
        "summary": {
            "passed": total_passed,
            "failed": failed,
            "total": total_cases,
            "fixture_pass_rate": total_passed / total_cases,
        },
        "metric": {
            "name": "fixture_agreement",
            "definition": (
                "The fraction of bundled fixture cases whose observed deterministic "
                "outcome exactly matches the versioned expected outcome."
            ),
        },
        "suites": suite_results,
        "limitations": [
            "Measures only the bundled offline fixtures and named invariants.",
            "Does not measure model quality or model behavior.",
            "Does not access live targets or measure vulnerability discovery.",
            "Does not establish broad security efficacy or production readiness.",
        ],
    }


def serialize_evaluation_result(result: dict[str, Any]) -> str:
    """Return stable, newline-terminated JSON for an evaluation result."""
    return json.dumps(result, indent=2, sort_keys=True) + "\n"


def write_evaluation_result(
    result: dict[str, Any],
    path: Path | str,
) -> Path:
    """Write an evaluation result atomically with private file permissions."""
    return write_private_text(
        path,
        serialize_evaluation_result(result),
        private_parent=False,
    )


def format_evaluation_summary(result: dict[str, Any]) -> str:
    """Render a concise, plain-language summary of fixture agreement."""
    summary = result["summary"]
    lines = [
        "Ares Evaluation Lab v1",
        f"Result: {str(result['result']).upper()}",
        (
            f"Fixtures: {summary['passed']}/{summary['total']} passed "
            f"({summary['failed']} failed)"
        ),
    ]
    for suite in result["suites"]:
        lines.append(
            f"- {suite['name']}: {suite['passed']}/{suite['total']} passed"
        )
    lines.extend(
        [
            "Measured: exact outcomes for the bundled deterministic fixtures.",
            (
                "Not measured: model quality, live-target behavior, vulnerability "
                "discovery, or broad security efficacy."
            ),
        ]
    )
    return "\n".join(lines)

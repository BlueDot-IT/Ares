from __future__ import annotations

from pathlib import Path

import pytest

from ares.config.loader import load_config
from ares.mission.coordinator import MissionCoordinator
from ares.mission.model import MissionRun, MissionScope
from ares.mission.tasks import MissionTask
from ares.state.db import StateDB
from ares.tools.registry import ToolRegistry


RUNNERS = ("deterministic", "contextual")


def _mission(tmp_path: Path, runner: str, suffix: str) -> MissionRun:
    return MissionRun(
        id=f"mission-{runner}-{suffix}",
        profile_id="secrets-audit",
        scope=MissionScope(
            target=str(tmp_path),
            allowed_paths=[str(tmp_path)],
        ),
    )


def _scan_task(mission: MissionRun) -> MissionTask:
    return MissionTask(
        id=f"{mission.id}-scan",
        mission_id=mission.id,
        role_id="scanner",
        phase="scan",
        tool_name="redteam_secret_scan",
        toolset="redteam_secrets",
        target=mission.scope.target,
        description="Run the scoped secret scan.",
    )


def _validation_task(
    mission: MissionRun,
    *,
    depends_on: list[str] | None = None,
) -> MissionTask:
    return MissionTask(
        id=f"{mission.id}-validate",
        mission_id=mission.id,
        role_id="validator",
        phase="validate",
        tool_name=None,
        toolset="redteam_secrets",
        target=mission.scope.target,
        description="Validate the persisted scan evidence.",
        depends_on=depends_on or [],
    )


def _registry(handler) -> ToolRegistry:
    registry = ToolRegistry()
    registry.register(
        name="redteam_secret_scan",
        toolset="redteam_secrets",
        risk="scan",
        schema={"type": "object", "properties": {}},
        handler=handler,
    )
    return registry


def _run(
    runner: str,
    *,
    coordinator: MissionCoordinator,
    registry: ToolRegistry,
    state_db: StateDB,
    tasks: list[MissionTask],
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> str:
    if runner == "deterministic":
        return coordinator.run_deterministic(
            registry,
            state_db,
            initial_tasks=tasks,
        )

    monkeypatch.setattr(
        "ares.run.build_registry",
        lambda _config, **_kwargs: registry,
    )
    return coordinator.run_contextual_deterministic(
        config=load_config(tmp_path / "app-home"),
        state_db=state_db,
        initial_tasks=tasks,
    )


def _operator_runs(state_db: StateDB) -> list[dict]:
    with state_db._connection() as conn:
        rows = conn.execute(
            "SELECT * FROM mission_operator_runs ORDER BY id"
        ).fetchall()
    return [dict(row) for row in rows]


@pytest.mark.parametrize("runner", RUNNERS)
def test_deterministic_paths_finish_tool_and_no_tool_runs(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    runner: str,
) -> None:
    state_db = StateDB(tmp_path / "state.db")
    mission = _mission(tmp_path, runner, "completed")
    scan_task = _scan_task(mission)
    validation_task = _validation_task(
        mission,
        depends_on=[scan_task.id],
    )

    _run(
        runner,
        coordinator=MissionCoordinator(mission),
        registry=_registry(lambda _args, **_kwargs: {"findings": []}),
        state_db=state_db,
        tasks=[scan_task, validation_task],
        tmp_path=tmp_path,
        monkeypatch=monkeypatch,
    )

    runs = _operator_runs(state_db)
    assert [run["status"] for run in runs] == ["completed", "completed"]
    assert all(run["finished_at"] is not None for run in runs)
    assert {task["status"] for task in state_db.list_mission_tasks(mission.id)} == {
        "completed"
    }
    assert state_db.get_mission(mission.id)["status"] == "completed"
    assert state_db.list_sessions()[0]["status"] == "completed"


@pytest.mark.parametrize("runner", RUNNERS)
def test_deterministic_paths_distinguish_tool_failure_from_runtime_error(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    runner: str,
) -> None:
    state_db = StateDB(tmp_path / "state.db")
    mission = _mission(tmp_path, runner, "failed")
    task = _scan_task(mission)

    def fail_tool(_args, **_kwargs):
        raise RuntimeError("expected tool failure")

    _run(
        runner,
        coordinator=MissionCoordinator(mission),
        registry=_registry(fail_tool),
        state_db=state_db,
        tasks=[task],
        tmp_path=tmp_path,
        monkeypatch=monkeypatch,
    )

    run = _operator_runs(state_db)[0]
    assert run["status"] == "failed"
    assert run["finished_at"] is not None
    assert "expected tool failure" in run["summary"]
    assert state_db.list_mission_tasks(mission.id)[0]["status"] == "failed"
    assert state_db.get_mission(mission.id)["status"] == "failed"
    assert state_db.list_sessions()[0]["status"] == "failed"


@pytest.mark.parametrize("runner", RUNNERS)
def test_deterministic_paths_close_active_state_on_unexpected_exception(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    runner: str,
) -> None:
    state_db = StateDB(tmp_path / "state.db")
    mission = _mission(tmp_path, runner, "error")
    task = _scan_task(mission)

    with pytest.raises(ValueError, match="not a valid Severity"):
        _run(
            runner,
            coordinator=MissionCoordinator(mission),
            registry=_registry(
                lambda _args, **_kwargs: {
                    "findings": [{"severity": "invalid"}]
                }
            ),
            state_db=state_db,
            tasks=[task],
            tmp_path=tmp_path,
            monkeypatch=monkeypatch,
        )

    run = _operator_runs(state_db)[0]
    assert run["status"] == "error"
    assert run["finished_at"] is not None
    assert "not a valid Severity" in run["summary"]
    assert state_db.list_mission_tasks(mission.id)[0]["status"] == "failed"
    assert state_db.get_mission(mission.id)["status"] == "failed"
    assert state_db.list_sessions()[0]["status"] == "error"


@pytest.mark.parametrize("runner", RUNNERS)
def test_deterministic_paths_finish_blocked_sessions_without_operator_runs(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    runner: str,
) -> None:
    state_db = StateDB(tmp_path / "state.db")
    mission = _mission(tmp_path, runner, "blocked")
    task = _scan_task(mission)
    task.target = str(tmp_path.parent)

    _run(
        runner,
        coordinator=MissionCoordinator(mission),
        registry=_registry(lambda _args, **_kwargs: {"findings": []}),
        state_db=state_db,
        tasks=[task],
        tmp_path=tmp_path,
        monkeypatch=monkeypatch,
    )

    assert _operator_runs(state_db) == []
    assert state_db.list_mission_tasks(mission.id)[0]["status"] == "blocked"
    assert state_db.get_mission(mission.id)["status"] == "blocked"
    assert state_db.list_sessions()[0]["status"] == "blocked"


@pytest.mark.parametrize("runner", RUNNERS)
def test_deterministic_paths_do_not_strand_running_task_when_run_insert_fails(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    runner: str,
) -> None:
    state_db = StateDB(tmp_path / "state.db")
    mission = _mission(tmp_path, runner, "operator-insert-error")
    task = _scan_task(mission)

    def fail_operator_run(**_kwargs):
        raise RuntimeError("operator run insert failed")

    monkeypatch.setattr(
        state_db,
        "record_mission_operator_run",
        fail_operator_run,
    )

    with pytest.raises(RuntimeError, match="operator run insert failed"):
        _run(
            runner,
            coordinator=MissionCoordinator(mission),
            registry=_registry(lambda _args, **_kwargs: {"findings": []}),
            state_db=state_db,
            tasks=[task],
            tmp_path=tmp_path,
            monkeypatch=monkeypatch,
        )

    assert _operator_runs(state_db) == []
    assert state_db.list_mission_tasks(mission.id)[0]["status"] == "pending"
    assert state_db.get_mission(mission.id)["status"] == "failed"
    assert state_db.list_sessions()[0]["status"] == "error"

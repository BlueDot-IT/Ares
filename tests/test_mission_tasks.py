from __future__ import annotations

import pytest

from ares.mission.tasks import (
    MissionTask,
    TaskStatus,
    parse_initial_tasks,
    task_can_run,
)


def test_task_defaults():
    task = MissionTask(
        id="task1",
        mission_id="m1",
        role_id="scanner",
        phase="scan",
        tool_name="redteam_secret_scan",
        toolset="redteam_secrets",
        target="src",
        description="Scan code for secrets",
    )
    assert task.status == TaskStatus.PENDING
    assert task.block_reason == ""
    assert task.args == {}
    assert task.depends_on == []


def test_task_can_run_no_deps():
    task = MissionTask(
        id="task1",
        mission_id="m1",
        role_id="scanner",
        phase="scan",
        tool_name="redteam_secret_scan",
        toolset="redteam_secrets",
        target="src",
        description="Scan code for secrets",
    )
    assert task_can_run(task, set()) is True


def test_task_can_run_missing_deps():
    task = MissionTask(
        id="task2",
        mission_id="m1",
        role_id="validator",
        phase="validate",
        tool_name="validate_secret_findings",
        toolset="redteam_secrets",
        target="src",
        description="Validate secret findings",
        depends_on=["task1"],
    )
    assert task_can_run(task, set()) is False
    assert task_can_run(task, {"task3"}) is False


def test_task_can_run_completed_deps():
    task = MissionTask(
        id="task2",
        mission_id="m1",
        role_id="validator",
        phase="validate",
        tool_name="validate_secret_findings",
        toolset="redteam_secrets",
        target="src",
        description="Validate secret findings",
        depends_on=["task1"],
    )
    assert task_can_run(task, {"task1"}) is True
    assert task_can_run(task, {"task1", "task3"}) is True


def test_parse_initial_tasks_rebinds_mission_and_rejects_unknown_fields():
    item = {
        "id": "bounded-check",
        "role_id": "infiltrator",
        "phase": "post-exploitation",
        "tool_name": "smbmap",
        "toolset": "ghostmcp",
        "target": "127.0.0.1",
        "description": "Validate one authorized access boundary.",
        "args": {"host": "127.0.0.1"},
    }
    tasks = parse_initial_tasks([item], mission_id="m_authorized")
    assert tasks[0].mission_id == "m_authorized"

    with pytest.raises(ValueError, match="unsupported fields"):
        parse_initial_tasks(
            [{**item, "mission_id": "attacker-selected"}],
            mission_id="m_authorized",
        )

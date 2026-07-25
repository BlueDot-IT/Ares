from __future__ import annotations

import json
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any


class TaskStatus(str, Enum):
    PENDING = "pending"
    APPROVED = "approved"
    BLOCKED = "blocked"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"


@dataclass
class MissionTask:
    id: str
    mission_id: str
    role_id: str
    phase: str
    tool_name: str | None
    toolset: str
    target: str
    description: str
    args: dict[str, Any] = field(default_factory=dict)
    depends_on: list[str] = field(default_factory=list)
    status: TaskStatus = TaskStatus.PENDING
    block_reason: str = ""


def task_can_run(task: MissionTask, completed_task_ids: set[str]) -> bool:
    return all(dep in completed_task_ids for dep in task.depends_on)


def load_initial_tasks(path: str | Path, *, mission_id: str) -> list[MissionTask]:
    """Load an explicit, non-model-generated mission task graph."""
    payload = json.loads(Path(path).expanduser().resolve().read_text(encoding="utf-8"))
    return parse_initial_tasks(payload, mission_id=mission_id)


def parse_initial_tasks(payload: Any, *, mission_id: str) -> list[MissionTask]:
    """Validate explicit task graph data received from a trusted operator surface."""
    if not isinstance(payload, list) or not payload:
        raise ValueError("initial task graph must contain a non-empty JSON array")
    allowed_fields = {
        "id",
        "role_id",
        "phase",
        "tool_name",
        "toolset",
        "target",
        "description",
        "args",
        "depends_on",
    }
    tasks: list[MissionTask] = []
    seen_ids: set[str] = set()
    for index, item in enumerate(payload):
        if not isinstance(item, dict):
            raise ValueError(f"initial task {index} must be an object")
        unknown = sorted(set(item) - allowed_fields)
        if unknown:
            raise ValueError(
                f"initial task {index} contains unsupported fields: "
                f"{', '.join(unknown)}"
            )
        missing = sorted(
            {
                "id",
                "role_id",
                "phase",
                "toolset",
                "target",
                "description",
            }
            - set(item)
        )
        if missing:
            raise ValueError(
                f"initial task {index} is missing fields: {', '.join(missing)}"
            )
        task_id = str(item["id"]).strip()
        if not task_id or task_id in seen_ids:
            raise ValueError(f"initial task {index} has an empty or duplicate id")
        args = item.get("args", {})
        depends_on = item.get("depends_on", [])
        if not isinstance(args, dict) or not isinstance(depends_on, list):
            raise ValueError(
                f"initial task {index} args must be an object and depends_on an array"
            )
        seen_ids.add(task_id)
        tasks.append(
            MissionTask(
                id=task_id,
                mission_id=mission_id,
                role_id=str(item["role_id"]),
                phase=str(item["phase"]),
                tool_name=(
                    str(item["tool_name"])
                    if item.get("tool_name") is not None
                    else None
                ),
                toolset=str(item["toolset"]),
                target=str(item["target"]),
                description=str(item["description"]),
                args=dict(args),
                depends_on=[str(value) for value in depends_on],
            )
        )
    for task in tasks:
        unknown_dependencies = sorted(set(task.depends_on) - seen_ids)
        if unknown_dependencies:
            raise ValueError(
                f"task {task.id} has unknown dependencies: "
                f"{', '.join(unknown_dependencies)}"
            )
        if task.id in task.depends_on:
            raise ValueError(f"task {task.id} cannot depend on itself")
    return tasks

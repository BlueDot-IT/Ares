from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class MissionStatus(str, Enum):
    CREATED = "created"
    RUNNING = "running"
    BLOCKED = "blocked"
    COMPLETED = "completed"
    FAILED = "failed"


class MissionPhase(str, Enum):
    PLAN = "plan"
    RECON = "recon"
    SCAN = "scan"
    WEAPONIZE = "weaponize"
    DELIVER = "deliver"
    EXPLOIT = "exploit"
    VALIDATE = "validate"
    POST_EXPLOITATION = "post-exploitation"
    PERSISTENCE = "persistence"
    ACTIONS = "actions"
    ANALYZE = "analyze"
    REPORT = "report"


@dataclass
class MissionScope:
    target: str
    allowed_paths: list[str] = field(default_factory=list)
    forbidden_paths: list[str] = field(default_factory=list)
    allowed_hosts: list[str] = field(default_factory=list)
    forbidden_actions: list[str] = field(default_factory=list)
    max_risk: str = "scan"


@dataclass
class MissionRun:
    id: str
    profile_id: str
    scope: MissionScope
    status: MissionStatus = MissionStatus.CREATED
    phase: MissionPhase = MissionPhase.PLAN
    metadata: dict[str, Any] = field(default_factory=dict)

# ARES Mission Swarm Integration Spec

## Goal

Add a T3MP3ST-style mission swarm layer to ARES without replacing ARES.

ARES remains the runtime:

* `ToolDispatcher`
* `ToolRegistry`
* `PolicyContext`
* `StateDB`
* `ContextBuilder`
* `ContextBudgeter`
* `memory_chunks`
* Markdown reporting
* training export

The new code adds:

* mission model
* mission task queue
* operator roles
* role-specific context packs
* mission findings ledger
* safe red-team toolsets
* benchmark missions
* experimental mission CLI

Do not build a separate framework.

---

# Hard Rules

> **Historical source note (2026-07-25):** The role exclusions below describe
> the original migration boundary. They were superseded by the later request to
> port the remaining T3MP3ST operator archetypes. Ares implements those names as
> scope-bound, tool-allowlisted validation roles; the prohibitions on destructive
> exploitation, credential harvesting, persistence installation, stealth, and
> data exfiltration remain in force.

1. Do not assume the local ARES clone is clean.
2. Do not bypass `ToolDispatcher`.
3. Do not create a second tool registry.
4. Do not create a second memory database.
5. Do not break existing commands.
6. Do not add destructive exploitation.
7. Do not add credential attacks.
8. Do not add persistence.
9. Do not add stealth.
10. Do not add exfiltration.
11. Every mission task must pass scope and policy validation.
12. Every confirmed finding must have evidence.
13. Every finding must have a refuter or validator note before being reported.

---

# Phase 0: Inspect Repo First

## Purpose

Verify the local repo before editing.

## Run

```bash id="h6yqs3"
pwd
git status --short
git branch --show-current
git log --oneline -5
find src/ares -maxdepth 3 -type f | sort | sed -n '1,240p'
find tests -maxdepth 2 -type f | sort | sed -n '1,240p'
```

## Stop Condition

If `git status --short` prints anything, stop.

Report the changed files.

Do not edit until the user says to continue.

## Expected Existing Files

These should exist:

```text id="ok3kyc"
src/ares/run.py
src/ares/agent/dispatcher.py
src/ares/agent/context_builder.py
src/ares/agent/context_budget.py
src/ares/state/db.py
src/ares/tools/registry.py
src/ares/reporting/markdown.py
src/ares/training/export.py
```

If any are missing, stop and report.

---

# Phase 1: Create Mission Package Skeleton

## Purpose

Add empty mission package files.

## Add Files

```text id="ql4hg8"
src/ares/mission/__init__.py
src/ares/mission/model.py
src/ares/mission/profiles.py
src/ares/mission/operators.py
src/ares/mission/tasks.py
src/ares/mission/findings.py
src/ares/mission/context.py
src/ares/mission/coordinator.py
src/ares/mission/report.py
src/ares/mission/tools.py
tests/test_mission_models.py
tests/test_mission_profiles.py
tests/test_mission_tasks.py
```

## Do Not

Do not wire this into `ares run` yet.

## Acceptance

```bash id="e5efl6"
python -m pytest tests/test_mission_models.py tests/test_mission_profiles.py tests/test_mission_tasks.py
git diff --check
```

---

# Phase 2: Mission Core Models

## File

```text id="st17i7"
src/ares/mission/model.py
```

## Implement

```python id="imzh0o"
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
    VALIDATE = "validate"
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
```

## Tests

In `tests/test_mission_models.py`:

```text id="mtk7oh"
test mission defaults to CREATED
test mission defaults to PLAN
test scope stores target
test metadata default is independent per object
```

---

# Phase 3: Mission Profiles

## File

```text id="kff3zg"
src/ares/mission/profiles.py
```

## Implement

```python id="cjppdr"
from __future__ import annotations

from dataclasses import dataclass

from ares.mission.model import MissionPhase


@dataclass(frozen=True)
class MissionProfile:
    id: str
    name: str
    phases: tuple[MissionPhase, ...]
    enabled_toolsets: tuple[str, ...]
    max_risk: str
    description: str


PROFILES: dict[str, MissionProfile] = {
    "source-code-audit": MissionProfile(
        id="source-code-audit",
        name="Source Code Audit",
        phases=(MissionPhase.PLAN, MissionPhase.SCAN, MissionPhase.VALIDATE, MissionPhase.REPORT),
        enabled_toolsets=("redteam_static", "redteam_secrets", "redteam_deps"),
        max_risk="scan",
        description="White-box review of local source files.",
    ),
    "secrets-audit": MissionProfile(
        id="secrets-audit",
        name="Secrets Audit",
        phases=(MissionPhase.PLAN, MissionPhase.SCAN, MissionPhase.VALIDATE, MissionPhase.REPORT),
        enabled_toolsets=("redteam_secrets",),
        max_risk="scan",
        description="Local secret-pattern review with redaction.",
    ),
    "dependency-audit": MissionProfile(
        id="dependency-audit",
        name="Dependency Audit",
        phases=(MissionPhase.PLAN, MissionPhase.SCAN, MissionPhase.ANALYZE, MissionPhase.REPORT),
        enabled_toolsets=("redteam_deps",),
        max_risk="scan",
        description="Local dependency manifest review.",
    ),
    "report-only": MissionProfile(
        id="report-only",
        name="Report Only",
        phases=(MissionPhase.REPORT,),
        enabled_toolsets=("redteam_report",),
        max_risk="safe",
        description="Generate a report from existing mission state.",
    ),
}


def get_profile(profile_id: str) -> MissionProfile:
    try:
        return PROFILES[profile_id]
    except KeyError as exc:
        raise ValueError(f"unknown mission profile: {profile_id}") from exc
```

## Tests

```text id="qkfpl8"
test each required profile exists
test unknown profile raises ValueError
test secrets-audit enables only redteam_secrets
test report-only max risk is safe
```

---

# Phase 4: Operator Roles

## File

```text id="5vh3sk"
src/ares/mission/operators.py
```

## Implement

```python id="8ut1f0"
from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class OperatorRole:
    id: str
    name: str
    purpose: str
    allowed_phases: tuple[str, ...]
    allowed_toolsets: tuple[str, ...]


OPERATORS: dict[str, OperatorRole] = {
    "coordinator": OperatorRole(
        id="coordinator",
        name="Coordinator",
        purpose="Plan mission tasks and decide when to stop.",
        allowed_phases=("plan", "report"),
        allowed_toolsets=("redteam_report",),
    ),
    "recon": OperatorRole(
        id="recon",
        name="Recon",
        purpose="Collect scoped target facts without exploitation.",
        allowed_phases=("recon",),
        allowed_toolsets=("redteam_recon",),
    ),
    "scanner": OperatorRole(
        id="scanner",
        name="Scanner",
        purpose="Run safe static, dependency, and secret scans.",
        allowed_phases=("scan",),
        allowed_toolsets=("redteam_static", "redteam_secrets", "redteam_deps"),
    ),
    "validator": OperatorRole(
        id="validator",
        name="Validator",
        purpose="Try to validate or weaken findings using evidence only.",
        allowed_phases=("validate",),
        allowed_toolsets=("redteam_static", "redteam_secrets", "redteam_deps"),
    ),
    "analyst": OperatorRole(
        id="analyst",
        name="Analyst",
        purpose="Summarize evidence, risk, limitations, and fixes.",
        allowed_phases=("analyze", "report"),
        allowed_toolsets=("redteam_report",),
    ),
}


def get_operator(role_id: str) -> OperatorRole:
    try:
        return OPERATORS[role_id]
    except KeyError as exc:
        raise ValueError(f"unknown operator role: {role_id}") from exc
```

## Do Not Implement

Do not implement:

```text id="c4f56f"
infiltrator
exfiltrator
ghost
persistence
credential harvesting
```

## Tests

```text id="pgwbz9"
test required safe operators exist
test unknown operator raises
test scanner can use redteam_secrets
test validator cannot use post-exploitation toolsets
```

---

# Phase 5: Mission Tasks

## File

```text id="jcsej6"
src/ares/mission/tasks.py
```

## Implement

```python id="fr9izu"
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
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
```

## Add Helper

```python id="k4sj58"
def task_can_run(task: MissionTask, completed_task_ids: set[str]) -> bool:
    return all(dep in completed_task_ids for dep in task.depends_on)
```

## Tests

```text id="k4rpfe"
test task defaults to PENDING
test task_can_run true with no dependencies
test task_can_run false with missing dependency
test task_can_run true when all dependencies completed
```

---

# Phase 6: Finding Model

## File

```text id="xb0n4t"
src/ares/mission/findings.py
```

## Implement

```python id="okjxin"
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum


class FindingState(str, Enum):
    HYPOTHESIS = "hypothesis"
    OBSERVED = "observed"
    VALIDATED = "validated"
    REFUTED = "refuted"
    REPORTED = "reported"


class Severity(str, Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class MissionFinding:
    id: str
    mission_id: str
    title: str
    severity: Severity
    state: FindingState = FindingState.HYPOTHESIS
    affected_component: str = ""
    evidence_chunk_ids: list[int] = field(default_factory=list)
    confidence: float = 0.0
    validator_note: str = ""
    recommendation: str = ""

    def add_evidence_chunk(self, chunk_id: int) -> None:
        if chunk_id not in self.evidence_chunk_ids:
            self.evidence_chunk_ids.append(chunk_id)

    def can_validate(self) -> bool:
        return bool(self.evidence_chunk_ids) and bool(self.validator_note.strip()) and self.confidence >= 0.7

    def validate(self) -> None:
        if not self.can_validate():
            raise ValueError("finding requires evidence, validator note, and confidence >= 0.7")
        self.state = FindingState.VALIDATED

    def refute(self, note: str) -> None:
        if not note.strip():
            raise ValueError("refute note is required")
        self.validator_note = note
        self.state = FindingState.REFUTED

    def report(self) -> None:
        if self.state != FindingState.VALIDATED:
            raise ValueError("only validated findings can be reported")
        self.state = FindingState.REPORTED
```

## Tests

```text id="e7ez9l"
test cannot validate without evidence
test cannot validate without validator note
test cannot validate below confidence threshold
test can validate with evidence note and confidence
test cannot report unvalidated finding
test refute requires note
```

---

# Phase 7: Extend StateDB for Missions

## File

```text id="si5rjo"
src/ares/state/db.py
```

## Modify Carefully

Add new schema method:

```python id="prcbn2"
def _ensure_mission_schema(self, conn: sqlite3.Connection) -> None:
    ...
```

Call it from `_init_schema()` after `_ensure_memory_schema(conn)`.

## Tables

Add:

```sql id="ba01dy"
CREATE TABLE IF NOT EXISTS missions (
    id TEXT PRIMARY KEY,
    created_at REAL NOT NULL,
    profile_id TEXT NOT NULL,
    target TEXT NOT NULL,
    scope_json TEXT NOT NULL,
    status TEXT NOT NULL,
    phase TEXT NOT NULL,
    metadata_json TEXT NOT NULL DEFAULT '{}'
)
```

```sql id="h9ucth"
CREATE TABLE IF NOT EXISTS mission_tasks (
    id TEXT PRIMARY KEY,
    mission_id TEXT NOT NULL,
    created_at REAL NOT NULL,
    role_id TEXT NOT NULL,
    phase TEXT NOT NULL,
    tool_name TEXT,
    toolset TEXT NOT NULL,
    target TEXT NOT NULL,
    description TEXT NOT NULL,
    args_json TEXT NOT NULL DEFAULT '{}',
    depends_on_json TEXT NOT NULL DEFAULT '[]',
    status TEXT NOT NULL,
    block_reason TEXT,
    FOREIGN KEY(mission_id) REFERENCES missions(id)
)
```

```sql id="lx6i6q"
CREATE TABLE IF NOT EXISTS mission_findings (
    id TEXT PRIMARY KEY,
    mission_id TEXT NOT NULL,
    title TEXT NOT NULL,
    severity TEXT NOT NULL,
    state TEXT NOT NULL,
    affected_component TEXT,
    evidence_chunk_ids_json TEXT NOT NULL DEFAULT '[]',
    confidence REAL NOT NULL DEFAULT 0,
    validator_note TEXT,
    recommendation TEXT,
    FOREIGN KEY(mission_id) REFERENCES missions(id)
)
```

```sql id="x7ff6w"
CREATE TABLE IF NOT EXISTS mission_operator_runs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    mission_id TEXT NOT NULL,
    task_id TEXT,
    role_id TEXT NOT NULL,
    session_id INTEGER,
    started_at REAL NOT NULL,
    finished_at REAL,
    status TEXT NOT NULL,
    summary TEXT,
    FOREIGN KEY(mission_id) REFERENCES missions(id),
    FOREIGN KEY(session_id) REFERENCES sessions(id)
)
```

## Add DB Methods

```python id="zxx8w7"
def create_mission(self, mission: MissionRun) -> None: ...
def get_mission(self, mission_id: str) -> dict[str, Any] | None: ...
def list_missions(self) -> list[dict[str, Any]]: ...
def update_mission_status(self, mission_id: str, status: str, phase: str | None = None) -> None: ...

def record_mission_task(self, task: MissionTask) -> None: ...
def update_mission_task_status(self, task_id: str, status: str, block_reason: str = "") -> None: ...
def list_mission_tasks(self, mission_id: str) -> list[dict[str, Any]]: ...

def record_mission_finding(self, finding: MissionFinding) -> None: ...
def list_mission_findings(self, mission_id: str) -> list[dict[str, Any]]: ...

def record_mission_operator_run(
    self,
    *,
    mission_id: str,
    task_id: str | None,
    role_id: str,
    session_id: int | None,
    status: str,
    summary: str = "",
) -> int: ...
```

## Tests

Add:

```text id="xn6utv"
tests/test_mission_state_db.py
```

Test:

```text id="ouxy2k"
create mission
get mission
record task
list tasks
update task status
record finding
list findings
record operator run
schema version still works
existing StateDB tests still pass
```

## Acceptance

```bash id="b86pdb"
python -m pytest tests/test_state_schema_migrations.py tests/test_state_memory_chunks.py tests/test_mission_state_db.py
```

---

# Phase 8: Scope Validation for Mission Tasks

## File

```text id="j8g40h"
src/ares/mission/coordinator.py
```

## Implement Class Skeleton

```python id="efhwby"
from __future__ import annotations

from pathlib import Path

from ares.mission.model import MissionRun
from ares.mission.tasks import MissionTask
from ares.mission.operators import get_operator
from ares.mission.profiles import get_profile


class MissionCoordinator:
    def __init__(self, mission: MissionRun):
        self.mission = mission
        self.profile = get_profile(mission.profile_id)

    def validate_task(self, task: MissionTask) -> tuple[bool, str]:
        ...
```

## Validation Rules

`validate_task` must reject if:

```text id="a62ihu"
task mission_id != mission.id
task toolset not in profile.enabled_toolsets
task role unknown
task role cannot use task toolset
task phase not in role.allowed_phases
task target path is forbidden
task target path is outside allowed_paths when allowed_paths is non-empty
task description is empty
```

## Path Rules

Use `Path.resolve()`.

Default forbidden names:

```text id="hjk3sa"
.git
.env
node_modules
.venv
venv
__pycache__
```

## Tests

Add:

```text id="d45xbk"
tests/test_mission_coordinator.py
```

Test:

```text id="lecej5"
valid scanner task passes
wrong mission id fails
unknown role fails
wrong toolset fails
forbidden .env path fails
outside allowed path fails
empty description fails
```

---

# Phase 9: Task Planning

## File

```text id="gl6azq"
src/ares/mission/coordinator.py
```

## Add

```python id="mzucch"
def seed_initial_tasks(self) -> list[MissionTask]:
    ...
```

## Behavior

For `secrets-audit`, create:

```text id="hd4e6q"
scanner task: redteam_secret_scan
validator task: validate_secret_findings depends on scanner
analyst task: generate report depends on validator
```

For `dependency-audit`, create:

```text id="m037co"
scanner task: redteam_dependency_manifest_scan
analyst task: generate report depends on scanner
```

For `source-code-audit`, create:

```text id="cpjtoc"
scanner task: redteam_secret_scan
scanner task: redteam_dependency_manifest_scan
validator task: validate findings depends on both scanner tasks
analyst task: generate report depends on validator
```

For `report-only`, create:

```text id="x6n0yk"
analyst task: generate report
```

## Important

This phase only creates tasks.

It does not run tools.

## Tests

```text id="cwo8z2"
test secrets-audit creates 3 tasks
test dependency-audit creates 2 tasks
test source-code-audit creates secret and dependency tasks
test report-only creates report task
test all seeded tasks pass validate_task
```

---

# Phase 10: Role-Specific Context Packs

## File

```text id="wd8wt7"
src/ares/mission/context.py
```

## Use Existing

Use:

```text id="nrurcp"
ares.agent.context_budget.ContextBudgeter
```

## Implement

```python id="vt1cy7"
from __future__ import annotations

from ares.agent.context_budget import ContextBudgeter
from ares.mission.model import MissionRun


def build_mission_context_pack(
    mission: MissionRun,
    *,
    role_id: str,
    tasks: list[dict] | None = None,
    findings: list[dict] | None = None,
    memory_chunks: list[dict] | None = None,
    max_tokens: int = 4000,
) -> str:
    ...
```

## Required Output By Role

Coordinator:

```text id="kdcgsn"
mission id
profile
phase
scope
open tasks
blocked tasks
```

Scanner:

```text id="9glz3j"
scope
allowed paths
current scan task
relevant prior memory
```

Validator:

```text id="qn5t3z"
candidate findings
linked evidence chunks
missing proof checklist
```

Analyst:

```text id="a29dmm"
validated findings
refuted findings
limitations
scope
```

## Tests

```text id="xd03nu"
tests/test_mission_context.py
```

Test:

```text id="jdsms4"
different roles get different context
context respects max token budget
validator context includes missing proof
analyst context includes limitations
```

---

# Phase 11: Register Safe Red-Team Tools

## File

```text id="ov91b5"
src/ares/mission/tools.py
```

## Use Existing ToolRegistry

Import:

```python id="9dme4e"
from ares.tools.registry import ToolRegistry
```

## Implement

```python id="eg5u6c"
def register_mission_tools(registry: ToolRegistry) -> None:
    registry.register(
        name="redteam_secret_scan",
        toolset="redteam_secrets",
        risk="scan",
        schema={...},
        handler=redteam_secret_scan,
        description="Scan scoped local files for obvious secret patterns with redaction.",
    )
    registry.register(
        name="redteam_dependency_manifest_scan",
        toolset="redteam_deps",
        risk="scan",
        schema={...},
        handler=redteam_dependency_manifest_scan,
        description="Locate dependency manifest files in scoped local paths.",
    )
```

## Tool 1: redteam_secret_scan

Input:

```json id="v0ravb"
{
  "root": ".",
  "paths": ["src"]
}
```

Output:

```json id="c35oxa"
{
  "summary": "Found 1 possible secret pattern.",
  "findings": [
    {
      "title": "Possible hardcoded secret",
      "severity": "medium",
      "file": "src/config.py",
      "line": 3,
      "redacted": "api_key = ***REDACTED***"
    }
  ]
}
```

Rules:

```text id="xbcicr"
only read text files
skip binary files
skip files larger than 1 MB
skip .git
skip .env
skip node_modules
skip .venv
never return full secret value
```

Patterns:

```text id="ymay8v"
api_key =
token =
password =
-----BEGIN PRIVATE KEY-----
AWS_ACCESS_KEY_ID
ghp_
```

## Tool 2: redteam_dependency_manifest_scan

Detect:

```text id="a6231v"
package.json
package-lock.json
pnpm-lock.yaml
requirements.txt
pyproject.toml
Pipfile
poetry.lock
```

Output:

```json id="wvq8w6"
{
  "summary": "Found 2 dependency manifests.",
  "manifests": [
    {
      "file": "package.json",
      "type": "npm"
    }
  ]
}
```

## Wire Into Registry

Modify `src/ares/run.py`:

In `build_registry`, after existing tool registration, call:

```python id="lq8nvf"
from ares.mission.tools import register_mission_tools
register_mission_tools(registry)
```

## Tests

```text id="fanj6w"
tests/test_mission_tools.py
```

Test:

```text id="znzfz4"
tools register
secret scan detects fake secret
secret scan redacts value
secret scan skips .env
dependency scan finds package.json
dependency scan skips node_modules
```

---

# Phase 12: Mission Execution Without LLM

## Purpose

Make deterministic mission execution work before adding agentic behavior.

## File

```text id="s9gw0x"
src/ares/mission/coordinator.py
```

## Add

```python id="npl5bb"
def run_deterministic(self, registry: ToolRegistry, state_db: StateDB) -> str:
    ...
```

## Behavior

```text id="ke6v7m"
create mission in StateDB
seed tasks
validate each task
record tasks
run scanner tasks by calling registry.dispatch through ToolDispatcher if possible
store raw tool result as tool_call
index useful result into memory_chunks
create MissionFinding objects from tool results
run validator rule
record findings
return markdown report string
```

## Important

Prefer using `ToolDispatcher`.

If that is too hard in this phase, stop and report.

Do not call tool handlers directly unless absolutely necessary, and document it as temporary technical debt.

## Validator Rule

For each finding:

```text id="foi7f0"
if evidence exists and file is not forbidden, confidence = 0.75
validator_note = "Validated as scoped static evidence. Manual review still required."
state = VALIDATED
else refute
```

## Tests

```text id="ws0kwt"
tests/test_mission_e2e_deterministic.py
```

Test:

```text id="d3ktpj"
mission runs against temp repo
fake secret in src is found
fake secret in .env is skipped
memory chunk is created
finding is validated
report contains finding
```

---

# Phase 13: Mission Markdown Report

## File

```text id="fl6pal"
src/ares/mission/report.py
```

## Implement

```python id="jst7pi"
def render_mission_report(
    *,
    mission: MissionRun,
    tasks: list[dict],
    findings: list[dict],
    evidence_chunks: list[dict],
) -> str:
    ...
```

## Required Sections

```text id="bwu1am"
# ARES Mission Report
## Summary
## Scope
## Tasks
## Validated Findings
## Refuted Findings
## Evidence
## Limitations
## Recommendations
```

## Rules

```text id="x2v5ez"
validated findings first
do not include raw secrets
include validator notes
include memory chunk ids
include skipped/blocked tasks
include limitations
```

## Tests

```text id="tjglbj"
tests/test_mission_report.py
```

Test:

```text id="op9qm4"
report has all headings
report includes validator note
report includes blocked task section
report does not include fake secret raw value
```

---

# Phase 14: Experimental CLI

## First Inspect Existing CLI

Run:

```bash id="y7id1w"
find src/ares -maxdepth 3 -type f | grep -E 'cli|main|argparse|commands'
```

Find where commands are registered.

## Add Experimental Commands

Do not break existing commands.

Add:

```text id="f1basd"
ares mission run
ares mission list
ares mission report
```

If the CLI structure cannot support nested commands easily, use:

```text id="wxw0mp"
ares mission-run
ares mission-list
ares mission-report
```

## `ares mission run`

Required args:

```text id="wvq90b"
--profile
--target
--allowed-path
--forbidden-path
--out
--dry-run
```

Example:

```bash id="y11kxw"
ares mission run \
  --profile secrets-audit \
  --target bench/redteam/secrets-basic \
  --allowed-path bench/redteam/secrets-basic/src \
  --forbidden-path bench/redteam/secrets-basic/.env \
  --out out/mission-report.md
```

## Dry Run Behavior

```text id="t7v1s9"
create mission object
seed tasks
validate tasks
print approved/blocked task list
do not run tools
do not write report
```

## Normal Run Behavior

```text id="xzel8m"
run deterministic mission
write report
print report path
```

## Tests

Add CLI tests if existing test pattern supports them.

Minimum:

```text id="qzlwgj"
dry run exits 0
normal run creates report
unknown profile exits nonzero
forbidden path remains skipped
```

---

# Phase 15: Benchmarks

## Add Directory

```text id="ju24ab"
bench/redteam/secrets-basic/
bench/redteam/secrets-basic/src/
bench/redteam/deps-basic/
```

## Add Files

```text id="lz4tcv"
bench/redteam/secrets-basic/README.md
bench/redteam/secrets-basic/src/config.py
bench/redteam/secrets-basic/.env
bench/redteam/deps-basic/package.json
```

## File Content Rules

`src/config.py` should contain fake secret:

```python id="s6m61a"
api_key = "FAKE_SECRET_FOR_ARES_TEST_ONLY"
```

`.env` should also contain fake secret, but it must be skipped:

```text id="yxpb58"
API_KEY=FAKE_SECRET_IN_FORBIDDEN_ENV_FILE
```

## Acceptance

Run:

```bash id="kl6wit"
ares mission run \
  --profile secrets-audit \
  --target bench/redteam/secrets-basic \
  --allowed-path bench/redteam/secrets-basic/src \
  --forbidden-path bench/redteam/secrets-basic/.env \
  --out out/secrets-basic-report.md
```

Expected:

```text id="tn0x7f"
report created
config.py finding present
.env finding absent
raw secret values absent
validator note present
```

---

# Phase 16: Training Export Support

## File

```text id="wxoynk"
src/ares/training/export.py
```

## Add

Mission export records.

Do not break current session export.

Add function:

```python id="zy7fau"
def export_mission_traces(state_db: StateDB, out_path: Path) -> int:
    ...
```

## JSONL Record Shape

```json id="b8i4oq"
{
  "type": "mission_trace",
  "mission_id": "mission-...",
  "profile_id": "secrets-audit",
  "target": "bench/redteam/secrets-basic",
  "tasks": [],
  "findings": [],
  "evidence_chunk_ids": [],
  "report_summary": ""
}
```

## Rules

```text id="q14sp7"
redact secret values
include blocked tasks
include refuted findings
do not include forbidden file contents
do not export raw .env content
```

## Tests

```text id="t6rrkn"
tests/test_mission_training_export.py
```

---

# Phase 17: Agentic Mission Loop

## Purpose

Use ARES runtime and model only after deterministic flow works.

## File

```text id="m2bqg2"
src/ares/mission/coordinator.py
```

## Add

```python id="gzm5d6"
def run_agentic(
    self,
    *,
    config: AppConfig,
    state_db: StateDB,
    max_tasks: int = 10,
) -> str:
    ...
```

## Behavior

Loop:

```text id="jku9am"
seed tasks
validate tasks
for each approved task:
  build role-specific context pack
  call existing run_once with requested_agent or prompt prefix
  let existing ToolDispatcher handle tools
  collect tool calls from StateDB
  create/update findings
  validate/refute findings
generate report
```

## Stop Conditions

Stop when:

```text id="phqbri"
max_tasks reached
no pending approved tasks
all remaining tasks blocked
mission status failed
```

## Do Not

Do not allow the model to invent new unvalidated tasks and run them directly.

If the model proposes a new task, convert it into `MissionTask`, then call `validate_task`.

## Tests

Mock model only.

```text id="z4vrti"
agentic loop stops
agentic loop validates proposed task before running
blocked task is not run
```

---

# Phase 18: External Tool Adapters

Only after Phases 1-17 pass.

## Add Optional Tools

```text id="r7m1oq"
redteam_semgrep_scan
redteam_gitleaks_scan
redteam_osv_scan
```

## Rules

```text id="l8hmw9"
tool missing returns clean unavailable
no install required for tests
fixture parser tests required
scope checks required
redaction required
```

## Tests Per Tool

```text id="aqq873"
availability false when binary missing
parse fixture output
does not read forbidden path
records findings as evidence
```

---

# Phase 19: Gateway API

Only after CLI works.

## File

```text id="dlx0c7"
src/ares/gateway.py
```

## Add Experimental Endpoints

```text id="g7twc4"
POST /api/mission/run
GET /api/mission/list
GET /api/mission/{id}
GET /api/mission/{id}/report
```

## Rules

```text id="mm75i6"
reuse existing gateway auth
reuse existing allowlist behavior
do not expose remote dangerous execution
default to dry-run unless local/loopback mode
```

---

# Phase 20: Documentation

## Add Docs

```text id="jv96bw"
docs/mission-swarm.md
docs/mission-cli.md
docs/mission-tools.md
docs/mission-training-export.md
```

## README

Add a short experimental section:

```text id="b3cq4s"
Experimental Mission Swarm
```

Mention:

```text id="ke9o1d"
authorized use only
local scoped missions first
safe scanner tools only
agentic loop is experimental
deterministic mission mode is preferred initially
```

---

# Final Test Gate

Run:

```bash id="gqfbrf"
python -m pytest
git diff --check
git status --short
```

Run smoke test:

```bash id="o8pmra"
ares mission run \
  --profile secrets-audit \
  --target bench/redteam/secrets-basic \
  --allowed-path bench/redteam/secrets-basic/src \
  --forbidden-path bench/redteam/secrets-basic/.env \
  --out out/secrets-basic-report.md
```

Verify:

```text id="a4ga45"
report exists
src/config.py finding exists
.env finding absent
raw fake secret absent
validator note exists
memory chunk exists
mission appears in mission list
```

---

# Build Order Summary

```text id="if5qjo"
0. Inspect repo and stop if dirty.
1. Add mission package skeleton.
2. Add MissionRun and MissionScope.
3. Add mission profiles.
4. Add operator roles.
5. Add MissionTask.
6. Add MissionFinding.
7. Extend StateDB with mission tables.
8. Add MissionCoordinator validation.
9. Add deterministic task seeding.
10. Add role-specific context packs.
11. Register safe redteam tools through ToolRegistry.
12. Add deterministic mission execution.
13. Add mission Markdown report.

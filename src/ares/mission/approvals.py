from __future__ import annotations

import hashlib
import json
import math
import os
import re
import time
from pathlib import Path
from typing import Any

from ares.mission.tasks import MissionTask
from ares.secure_files import PRIVATE_FILE_MODE


ADVANCED_ROLES = frozenset(
    {"exploiter", "infiltrator", "exfiltrator", "ghost"}
)
APPROVAL_DIGEST_SCHEMA = "ares.mission-task-approval.v1"
MAX_APPROVAL_CLOCK_SKEW_SECONDS = 300
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")


def task_approval_digest(task: MissionTask) -> str:
    """Bind approval to the exact role, target, tool, arguments, and evidence."""
    payload = {
        "schema": APPROVAL_DIGEST_SCHEMA,
        "mission_id": task.mission_id,
        "task_id": task.id,
        "role_id": task.role_id,
        "phase": task.phase,
        "tool_name": task.tool_name,
        "toolset": task.toolset,
        "target": task.target,
        "description": task.description,
        "args": task.args,
        "depends_on": sorted(task.depends_on),
        "supporting_evidence_tool_call_ids": sorted(
            task.supporting_evidence_tool_call_ids
        ),
    }
    canonical = json.dumps(
        payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    )
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def load_approval_receipts(path: str | Path) -> list[dict[str, Any]]:
    receipt_path = Path(path).expanduser().resolve()
    mode = os.stat(receipt_path).st_mode & 0o777
    if mode != PRIVATE_FILE_MODE:
        raise ValueError("approval receipt file must have mode 0600")
    payload = json.loads(receipt_path.read_text(encoding="utf-8"))
    return parse_approval_receipts(payload)


def parse_approval_receipts(payload: Any) -> list[dict[str, Any]]:
    if not isinstance(payload, list) or not payload:
        raise ValueError("approval receipt file must contain a non-empty array")
    required = {
        "id", "task_id", "task_digest", "source", "approver", "approved_at",
        "expires_at",
    }
    receipts: list[dict[str, Any]] = []
    for index, item in enumerate(payload):
        if not isinstance(item, dict):
            raise ValueError(f"approval receipt {index} must be an object")
        missing = sorted(required - set(item))
        if missing:
            raise ValueError(
                f"approval receipt {index} missing: {', '.join(missing)}"
            )
        receipt = {
            "id": str(item["id"]).strip(),
            "task_id": str(item["task_id"]).strip(),
            "task_digest": str(item["task_digest"]).strip().lower(),
            "source": str(item["source"]).strip(),
            "approver": str(item["approver"]).strip(),
            "approved_at": float(item["approved_at"]),
            "expires_at": float(item["expires_at"]),
        }
        if (
            not all(
                receipt[key]
                for key in ("id", "task_id", "source", "approver")
            )
            or _SHA256_RE.fullmatch(receipt["task_digest"]) is None
            or not math.isfinite(receipt["approved_at"])
            or (
                not math.isfinite(receipt["expires_at"])
            )
        ):
            raise ValueError(f"approval receipt {index} is malformed")
        now = time.time()
        if receipt["approved_at"] > now + MAX_APPROVAL_CLOCK_SKEW_SECONDS:
            raise ValueError(
                f"approval receipt {index} approval time is in the future"
            )
        if receipt["approved_at"] <= 0:
            raise ValueError(f"approval receipt {index} is malformed")
        if (
            receipt["expires_at"] <= receipt["approved_at"]
        ):
            raise ValueError(
                f"approval receipt {index} expires before approval"
            )
        if (
            receipt["expires_at"] <= now
        ):
            raise ValueError(f"approval receipt {index} is expired")
        receipts.append(receipt)
    return receipts

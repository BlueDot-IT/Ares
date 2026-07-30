from __future__ import annotations

import hashlib
import re
from enum import Enum
from typing import Any

from ares.autonomy.graph import AttackSurfaceGraph, NodeKind
from ares.state.db import StateDB


class CoverageStatus(str, Enum):
    PENDING = "pending"
    PLANNED = "planned"
    RUNNING = "running"
    COMPLETE = "complete"
    INCONCLUSIVE = "inconclusive"
    BLOCKED = "blocked"
    FAILED = "failed"


TERMINAL_COVERAGE_STATUSES = {
    CoverageStatus.COMPLETE.value,
    CoverageStatus.INCONCLUSIVE.value,
    CoverageStatus.BLOCKED.value,
    CoverageStatus.FAILED.value,
}

_PORT_SCOPE_RE = re.compile(r"^\d+(?:-\d+)?(?:,\d+(?:-\d+)?)*$")


def normalize_port_scope(value: str) -> str:
    normalized = "".join(str(value or "").split())
    if not normalized or not _PORT_SCOPE_RE.fullmatch(normalized):
        raise ValueError(
            "port scope must be a comma-separated list of ports or ranges"
        )
    port_count = 0
    for token in normalized.split(","):
        if "-" in token:
            start_text, end_text = token.split("-", 1)
            start, end = int(start_text), int(end_text)
        else:
            start = end = int(token)
        if start < 1 or end > 65535 or start > end:
            raise ValueError("port scope values must be within 1-65535")
        port_count += end - start + 1
    if port_count > 4096:
        raise ValueError(
            "autonomous port scope is limited to 4096 ports per mission"
        )
    return normalized


def _coverage_id(mission_id: str, subject_node_id: str, capability: str) -> str:
    material = "\x1f".join(
        (mission_id, subject_node_id, capability)
    )
    digest = hashlib.sha256(material.encode("utf-8")).hexdigest()[:20]
    return f"cov_{digest}"


class CoverageLedger:
    """Persistent record of planned, completed, and unresolved assessment work."""

    def __init__(
        self,
        state_db: StateDB,
        mission_id: str,
        graph: AttackSurfaceGraph,
        *,
        port_scope: str = "1-1000",
    ) -> None:
        self.state_db = state_db
        self.mission_id = mission_id
        self.graph = graph
        self.port_scope = normalize_port_scope(port_scope)

    def ensure(
        self,
        *,
        subject_node_id: str,
        capability: str,
        required: bool = True,
        status: CoverageStatus | str = CoverageStatus.PENDING,
    ) -> str:
        status_value = (
            status.value if isinstance(status, CoverageStatus) else str(status)
        )
        coverage_id = _coverage_id(
            self.mission_id,
            subject_node_id,
            capability,
        )
        self.state_db.upsert_mission_coverage(
            coverage_id=coverage_id,
            mission_id=self.mission_id,
            subject_node_id=subject_node_id,
            capability=capability,
            required=required,
            status=status_value,
        )
        return coverage_id

    def update(
        self,
        coverage_id: str,
        *,
        status: CoverageStatus | str,
        evidence_tool_call_ids: list[int] | tuple[int, ...] = (),
        last_error: str = "",
        increment_attempts: bool = False,
    ) -> None:
        status_value = (
            status.value if isinstance(status, CoverageStatus) else str(status)
        )
        self.state_db.update_mission_coverage(
            coverage_id,
            status=status_value,
            evidence_tool_call_ids=evidence_tool_call_ids,
            last_error=last_error,
            increment_attempts=increment_attempts,
        )

    def refresh_requirements(self) -> None:
        hosts = self.graph.nodes(kind=NodeKind.HOST)
        for host in hosts:
            self.ensure(
                subject_node_id=host["id"],
                capability="host.identity",
            )
            self.ensure(
                subject_node_id=host["id"],
                capability=f"network.port_scan:{self.port_scope}",
            )

        for service in self.graph.nodes(kind=NodeKind.SERVICE):
            attributes = service.get("attributes") or {}
            fingerprint_id = self.ensure(
                subject_node_id=service["id"],
                capability="service.fingerprint",
            )
            if attributes.get("service") or attributes.get("product"):
                self.update(
                    fingerprint_id,
                    status=CoverageStatus.COMPLETE,
                    evidence_tool_call_ids=service.get(
                        "evidence_tool_call_ids", []
                    ),
                )

            service_name = str(attributes.get("service") or "").lower()
            port = int(attributes.get("port") or 0)
            is_http = "http" in service_name or port in {
                80,
                443,
                8000,
                8080,
                8081,
                8443,
                8888,
            }
            is_tls = (
                "ssl" in service_name
                or "tls" in service_name
                or port in {443, 465, 993, 995, 8443}
            )
            if is_http:
                self.ensure(
                    subject_node_id=service["id"],
                    capability="web.probe",
                )
                self.ensure(
                    subject_node_id=service["id"],
                    capability="web.fingerprint",
                )
            if is_tls:
                self.ensure(
                    subject_node_id=service["id"],
                    capability="tls.assessment",
                )

    def items(
        self,
        *,
        statuses: tuple[CoverageStatus | str, ...] = (),
    ) -> list[dict[str, Any]]:
        status_values = tuple(
            value.value if isinstance(value, CoverageStatus) else str(value)
            for value in statuses
        )
        nodes = {node["id"]: node for node in self.graph.nodes()}
        items = self.state_db.list_mission_coverage(
            self.mission_id,
            statuses=status_values,
        )
        for item in items:
            item["subject"] = nodes.get(item["subject_node_id"])
        return items

    def pending(self) -> list[dict[str, Any]]:
        return self.items(
            statuses=(
                CoverageStatus.PENDING,
                CoverageStatus.PLANNED,
            )
        )

    def required_open(self) -> list[dict[str, Any]]:
        return [
            item
            for item in self.items()
            if item["required"]
            and item["status"] not in TERMINAL_COVERAGE_STATUSES
        ]

    def summary(self) -> dict[str, Any]:
        items = self.items()
        by_status: dict[str, int] = {}
        by_capability: dict[str, dict[str, int]] = {}
        for item in items:
            by_status[item["status"]] = by_status.get(item["status"], 0) + 1
            capability_status = by_capability.setdefault(
                item["capability"], {}
            )
            capability_status[item["status"]] = (
                capability_status.get(item["status"], 0) + 1
            )
        return {
            "total": len(items),
            "required_open": len(self.required_open()),
            "by_status": by_status,
            "by_capability": by_capability,
        }

from __future__ import annotations

import hashlib

from ares.autonomy.graph import AttackSurfaceGraph, NodeKind
from ares.mission.findings import FindingState, MissionFinding, Severity
from ares.state.db import StateDB


class AutonomousFindingManager:
    """Create conservative hypotheses from persisted attack-surface evidence."""

    def __init__(
        self,
        state_db: StateDB,
        mission_id: str,
        graph: AttackSurfaceGraph,
    ) -> None:
        self.state_db = state_db
        self.mission_id = mission_id
        self.graph = graph

    def refresh(self) -> None:
        existing = {
            item["id"] for item in
            self.state_db.list_mission_findings(self.mission_id)
        }
        for node in self.graph.nodes(kind=NodeKind.TECHNOLOGY):
            evidence_ids = [
                int(value)
                for value in node.get("evidence_tool_call_ids") or []
            ]
            if not evidence_ids:
                continue
            finding_id = self._id(str(node["id"]))
            if finding_id in existing:
                continue
            label = str(node.get("label") or node.get("node_key"))
            finding = MissionFinding(
                id=finding_id,
                mission_id=self.mission_id,
                title=f"Version or product exposure requires review: {label}",
                severity=Severity.INFO,
                state=FindingState.OBSERVED,
                affected_component=label,
                evidence_tool_call_ids=evidence_ids,
                confidence=0.4,
                confidence_rationale=(
                    "A product or version marker was observed, but no "
                    "vulnerability behavior was demonstrated."
                ),
                severity_rationale=(
                    "Informational only until an independently corroborated "
                    "and safely reproduced security impact exists."
                ),
                recommendation=(
                    "Confirm the deployed version and compare it with vendor "
                    "advisories; do not treat banner data as proof."
                ),
                version_only=True,
            )
            finding.hypothesize()
            if len(set(evidence_ids)) >= 2:
                finding.corroborate()
            self.state_db.record_mission_finding(finding)

    def _id(self, node_id: str) -> str:
        digest = hashlib.sha256(
            f"{self.mission_id}\x1f{node_id}".encode("utf-8")
        ).hexdigest()[:20]
        return f"finding_{digest}"

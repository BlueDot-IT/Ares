from __future__ import annotations

import hashlib
from enum import Enum
from typing import Any

from ares.state.db import StateDB


class NodeKind(str, Enum):
    HOST = "host"
    DOMAIN = "domain"
    SERVICE = "service"
    ENDPOINT = "endpoint"
    TECHNOLOGY = "technology"
    IDENTITY = "identity"
    FINDING = "finding"


def stable_graph_id(prefix: str, mission_id: str, *parts: object) -> str:
    material = "\x1f".join(
        [mission_id, *(str(part).strip().lower() for part in parts)]
    )
    digest = hashlib.sha256(material.encode("utf-8")).hexdigest()[:20]
    return f"{prefix}_{digest}"


class AttackSurfaceGraph:
    """Persistent, mission-bound graph of typed attack-surface observations."""

    def __init__(self, state_db: StateDB, mission_id: str) -> None:
        self.state_db = state_db
        self.mission_id = mission_id

    def upsert_node(
        self,
        *,
        kind: NodeKind | str,
        key: str,
        label: str | None = None,
        attributes: dict[str, Any] | None = None,
        evidence_tool_call_ids: list[int] | tuple[int, ...] = (),
    ) -> str:
        kind_value = kind.value if isinstance(kind, NodeKind) else str(kind)
        normalized_key = str(key).strip().lower()
        if not normalized_key:
            raise ValueError("attack-surface node key cannot be empty")
        node_id = stable_graph_id(
            "asn",
            self.mission_id,
            kind_value,
            normalized_key,
        )
        self.state_db.upsert_attack_surface_node(
            node_id=node_id,
            mission_id=self.mission_id,
            kind=kind_value,
            node_key=normalized_key,
            label=(label or str(key)).strip(),
            attributes=attributes,
            evidence_tool_call_ids=evidence_tool_call_ids,
        )
        return node_id

    def connect(
        self,
        source_node_id: str,
        target_node_id: str,
        relationship: str,
        *,
        attributes: dict[str, Any] | None = None,
        evidence_tool_call_ids: list[int] | tuple[int, ...] = (),
    ) -> str:
        relationship = relationship.strip().lower()
        if not relationship:
            raise ValueError("attack-surface relationship cannot be empty")
        known_ids = {
            node["id"]
            for node in self.state_db.list_attack_surface_nodes(
                self.mission_id
            )
        }
        if source_node_id not in known_ids or target_node_id not in known_ids:
            raise ValueError("attack-surface edges require existing mission nodes")
        edge_id = stable_graph_id(
            "ase",
            self.mission_id,
            source_node_id,
            target_node_id,
            relationship,
        )
        self.state_db.upsert_attack_surface_edge(
            edge_id=edge_id,
            mission_id=self.mission_id,
            source_node_id=source_node_id,
            target_node_id=target_node_id,
            relationship=relationship,
            attributes=attributes,
            evidence_tool_call_ids=evidence_tool_call_ids,
        )
        return edge_id

    def nodes(self, *, kind: NodeKind | str | None = None) -> list[dict[str, Any]]:
        kind_value = (
            kind.value if isinstance(kind, NodeKind) else str(kind)
            if kind is not None
            else None
        )
        return self.state_db.list_attack_surface_nodes(
            self.mission_id,
            kind=kind_value,
        )

    def edges(self) -> list[dict[str, Any]]:
        return self.state_db.list_attack_surface_edges(self.mission_id)

    def get_node(self, node_id: str) -> dict[str, Any] | None:
        return next(
            (node for node in self.nodes() if node["id"] == node_id),
            None,
        )

    def snapshot(self) -> dict[str, Any]:
        return {
            "mission_id": self.mission_id,
            "nodes": self.nodes(),
            "edges": self.edges(),
        }

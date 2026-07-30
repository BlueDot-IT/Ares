from __future__ import annotations

from pathlib import Path

import pytest

from ares.autonomy.coverage import (
    CoverageLedger,
    CoverageStatus,
    normalize_port_scope,
)
from ares.autonomy.graph import AttackSurfaceGraph, NodeKind
from ares.autonomy.projector import AttackSurfaceProjector
from ares.mission.model import MissionRun, MissionScope
from ares.state.db import StateDB


def _db_with_mission(tmp_path: Path) -> StateDB:
    db = StateDB(tmp_path / "state.db")
    db.create_mission(
        MissionRun(
            id="m_graph",
            profile_id="autonomous-recon",
            scope=MissionScope(
                target="127.0.0.1",
                allowed_hosts=["127.0.0.1"],
                max_risk="active",
            ),
        )
    )
    return db


def test_attack_surface_graph_is_typed_deduplicated_and_evidence_linked(
    tmp_path: Path,
) -> None:
    db = _db_with_mission(tmp_path)
    graph = AttackSurfaceGraph(db, "m_graph")

    host_id = graph.upsert_node(
        kind=NodeKind.HOST,
        key="127.0.0.1",
        attributes={"address": "127.0.0.1"},
        evidence_tool_call_ids=[10],
    )
    same_host_id = graph.upsert_node(
        kind=NodeKind.HOST,
        key="127.0.0.1",
        label="localhost",
        attributes={"hostname": "localhost"},
        evidence_tool_call_ids=[11],
    )
    service_id = graph.upsert_node(
        kind=NodeKind.SERVICE,
        key="127.0.0.1:443/tcp",
        attributes={
            "host_address": "127.0.0.1",
            "port": 443,
            "proto": "tcp",
            "service": "ssl/http",
        },
        evidence_tool_call_ids=[12],
    )
    first_edge = graph.connect(
        host_id,
        service_id,
        "exposes",
        evidence_tool_call_ids=[12],
    )
    second_edge = graph.connect(
        host_id,
        service_id,
        "exposes",
        evidence_tool_call_ids=[13],
    )

    assert host_id == same_host_id
    assert first_edge == second_edge
    host = graph.get_node(host_id)
    assert host is not None
    assert host["label"] == "localhost"
    assert host["attributes"] == {
        "address": "127.0.0.1",
        "hostname": "localhost",
    }
    assert host["evidence_tool_call_ids"] == [10, 11]
    assert graph.edges()[0]["evidence_tool_call_ids"] == [12, 13]


def test_coverage_ledger_expands_from_discovered_services(
    tmp_path: Path,
) -> None:
    db = _db_with_mission(tmp_path)
    graph = AttackSurfaceGraph(db, "m_graph")
    host_id = graph.upsert_node(
        kind=NodeKind.HOST,
        key="127.0.0.1",
        attributes={"address": "127.0.0.1"},
    )
    ledger = CoverageLedger(db, "m_graph", graph)

    ledger.refresh_requirements()
    assert {
        item["capability"] for item in ledger.pending()
    } == {"host.identity", "network.port_scan:1-1000"}

    service_id = graph.upsert_node(
        kind=NodeKind.SERVICE,
        key="127.0.0.1:443/tcp",
        attributes={
            "host_address": "127.0.0.1",
            "port": 443,
            "proto": "tcp",
            "service": "ssl/http",
            "product": "nginx",
        },
        evidence_tool_call_ids=[42],
    )
    graph.connect(host_id, service_id, "exposes")
    ledger.refresh_requirements()

    by_capability = {
        item["capability"]: item for item in ledger.items()
        if item["subject_node_id"] == service_id
    }
    assert by_capability["service.fingerprint"]["status"] == "complete"
    assert by_capability["service.fingerprint"][
        "evidence_tool_call_ids"
    ] == [42]
    assert by_capability["web.probe"]["status"] == "pending"
    assert by_capability["web.fingerprint"]["status"] == "pending"
    assert by_capability["tls.assessment"]["status"] == "pending"

    ledger.update(
        by_capability["tls.assessment"]["id"],
        status=CoverageStatus.INCONCLUSIVE,
        last_error="certificate name mismatch",
        increment_attempts=True,
    )
    updated = {
        item["capability"]: item for item in ledger.items()
        if item["subject_node_id"] == service_id
    }
    assert updated["tls.assessment"]["attempts"] == 1
    assert updated["tls.assessment"]["last_error"] == (
        "certificate name mismatch"
    )


def test_autonomous_port_scope_is_explicit_normalized_and_bounded() -> None:
    assert normalize_port_scope("1-1000, 8000") == "1-1000,8000"
    with pytest.raises(ValueError, match="1-65535"):
        normalize_port_scope("0,443")
    with pytest.raises(ValueError, match="4096"):
        normalize_port_scope("1-4097")


@pytest.mark.parametrize(
    ("args", "expected"),
    [
        ({"host": "mail.example.test", "port": 993}, ("mail.example.test", 993)),
        ({"target": "mail.example.test:443"}, ("mail.example.test", 443)),
        ({"target": "[2001:db8::1]:995"}, ("2001:db8::1", 995)),
        ({"target": "2001:db8::1", "port": 443}, ("2001:db8::1", 443)),
    ],
)
def test_tls_projection_preserves_ipv6_and_extracts_optional_port(
    args: dict[str, object],
    expected: tuple[str, int],
) -> None:
    assert AttackSurfaceProjector._tls_target(args) == expected

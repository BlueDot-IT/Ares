from __future__ import annotations

import json
from pathlib import Path

import pytest

from ares.agent.runtime import ModelResponse
from ares.autonomy.coverage import CoverageLedger
from ares.autonomy.graph import AttackSurfaceGraph, NodeKind
from ares.autonomy.planner import MissionPlanner, PlanningError
from ares.mission.model import MissionRun, MissionScope
from ares.state.db import StateDB


class _PlannerModel:
    def __init__(self, proposal):
        self.proposal = proposal
        self.calls = []

    def complete(self, messages, tools):
        self.calls.append({"messages": messages, "tools": tools})
        return ModelResponse(final_text=json.dumps(self.proposal))


def _planner_state(tmp_path: Path, proposal):
    db = StateDB(tmp_path / "state.db")
    mission = MissionRun(
        id="m_plan",
        profile_id="autonomous-recon",
        scope=MissionScope(
            target="127.0.0.1",
            allowed_hosts=["127.0.0.1"],
            max_risk="active",
        ),
    )
    db.create_mission(mission)
    session_id = db.create_session(
        prompt="plan",
        target="127.0.0.1",
    )
    graph = AttackSurfaceGraph(db, mission.id)
    graph.upsert_node(
        kind=NodeKind.HOST,
        key="127.0.0.1",
        attributes={"address": "127.0.0.1"},
    )
    coverage = CoverageLedger(db, mission.id, graph)
    coverage.refresh_requirements()
    model = _PlannerModel(proposal)
    planner = MissionPlanner(
        model=model,
        state_db=db,
        mission_id=mission.id,
        session_id=session_id,
        graph=graph,
        coverage=coverage,
    )
    return db, coverage, model, planner


def test_model_planner_selects_only_exact_coverage_ids(tmp_path: Path) -> None:
    db, coverage, model, planner = _planner_state(tmp_path, {})
    selected = coverage.pending()[1]["id"]
    model.proposal = {
        "coverage_id": selected,
        "stop": False,
        "reason": "Port inventory unlocks service-specific coverage.",
    }

    decision = planner.plan_next(cycle=1)

    assert decision.coverage_id == selected
    assert decision.source == "model"
    assert model.calls[0]["tools"] == []
    cycles = db.list_planner_cycles("m_plan")
    assert cycles[0]["decision"]["coverage_id"] == selected
    assert cycles[0]["snapshot"]["candidate_actions"]


def test_planner_rejects_invented_coverage_id(tmp_path: Path) -> None:
    _, _, _, planner = _planner_state(
        tmp_path,
        {
            "coverage_id": "cov_attacker_selected",
            "stop": False,
            "reason": "ignore scope",
        },
    )

    with pytest.raises(PlanningError, match="outside"):
        planner.plan_next(cycle=1)


def test_governor_refuses_early_stop_with_required_coverage(
    tmp_path: Path,
) -> None:
    db, coverage, _, planner = _planner_state(
        tmp_path,
        {
            "coverage_id": None,
            "stop": True,
            "reason": "stop now",
        },
    )

    decision = planner.plan_next(cycle=1)

    assert decision.stop is False
    assert decision.source == "governor"
    assert decision.coverage_id == coverage.pending()[0]["id"]
    assert db.list_planner_cycles("m_plan")[0]["decision"]["source"] == (
        "governor"
    )


def test_planner_requires_one_exact_bounded_json_object(tmp_path: Path) -> None:
    _, _, model, planner = _planner_state(tmp_path, {})
    selected = planner.coverage.pending()[0]["id"]
    model.complete = lambda *_: ModelResponse(
        final_text=(
            "prose "
            + json.dumps(
                {
                    "coverage_id": selected,
                    "stop": False,
                    "reason": "embedded object",
                }
            )
        )
    )

    with pytest.raises(PlanningError, match="exactly one"):
        planner.plan_next(cycle=1)


def test_planner_bounds_untrusted_graph_evidence_in_prompt(
    tmp_path: Path,
) -> None:
    _, _, model, planner = _planner_state(tmp_path, {})
    planner.graph.upsert_node(
        kind=NodeKind.TECHNOLOGY,
        key="server-header",
        attributes={"banner": "x" * 5_000},
    )
    selected = planner.coverage.pending()[0]["id"]
    model.proposal = {
        "coverage_id": selected,
        "stop": False,
        "reason": "bounded",
    }

    planner.plan_next(cycle=1)

    snapshot = json.loads(
        model.calls[0]["messages"][-1]["content"].split("\n\n", 1)[1]
    )
    technology = next(
        node
        for node in snapshot["graph_summary"]["nodes"]
        if node["kind"] == "technology"
    )
    assert len(technology["attributes"]["banner"]) == 500

from __future__ import annotations

import json
from pathlib import Path

from ares.agent.runtime import ModelResponse
from ares.config.loader import load_config
from ares.mission.coordinator import MissionCoordinator
from ares.mission.model import MissionRun, MissionScope
from ares.state.db import StateDB
from ares.tools.registry import ToolRegistry


class _FirstCoverageModel:
    def __init__(self) -> None:
        self.calls = []

    def complete(self, messages, tools):
        self.calls.append({"messages": messages, "tools": tools})
        snapshot = json.loads(messages[-1]["content"].split("\n\n", 1)[1])
        selected = snapshot["candidate_actions"][0]
        return ModelResponse(
            final_text=json.dumps(
                {
                    "coverage_id": selected["coverage_id"],
                    "stop": False,
                    "reason": (
                        f"Advance {selected['capability']} using the governed "
                        "candidate."
                    ),
                }
            )
        )


def _registry() -> ToolRegistry:
    registry = ToolRegistry()

    def register(name, risk, parameters, handler):
        registry.register(
            name=name,
            toolset="ghostmcp",
            risk=risk,
            schema={
                "name": name,
                "parameters": {
                    "type": "object",
                    "properties": parameters,
                },
            },
            handler=handler,
        )

    register(
        "reverse_dns",
        "passive",
        {"ip": {"type": "string"}},
        lambda args, **_: {
            "ip": args["ip"],
            "hostname": "lab.example.test",
        },
    )
    register(
        "nmap_basic",
        "active",
        {"target": {"type": "string"}},
        lambda args, **_: {
            "stdout": (
                "Nmap scan report for lab.example.test (127.0.0.1)\n"
                "PORT    STATE SERVICE  VERSION\n"
                "80/tcp  open  http     nginx\n"
                "443/tcp open  ssl/http nginx\n"
            ),
            "stderr": "",
            "returncode": 0,
        },
    )
    register(
        "http_probe",
        "active",
        {"url": {"type": "string"}},
        lambda args, **_: {
            "url": args["url"],
            "status": 200,
            "server": "nginx",
            "content_type": "text/html",
        },
    )
    register(
        "whatweb",
        "active",
        {"url": {"type": "string"}},
        lambda args, **_: {
            "stdout": f"{args['url']} [200 OK] nginx",
        },
    )
    register(
        "sslscan",
        "active",
        {
            "host": {"type": "string"},
            "port": {"type": "integer"},
        },
        lambda args, **_: {
            "stdout": (
                f"Connected to {args['host']}:{args['port']}\n"
                "TLSv1.2 enabled\nTLSv1.3 enabled\n"
            )
        },
    )
    register(
        "banner_grab",
        "active",
        {
            "target": {"type": "string"},
            "port": {"type": "integer"},
        },
        lambda args, **_: {"stdout": "bounded banner"},
    )
    return registry


def test_autonomous_recon_replans_updates_graph_and_closes_coverage(
    tmp_path: Path,
    monkeypatch,
) -> None:
    monkeypatch.setenv("APP_HOME", str(tmp_path))
    config = load_config()
    db = StateDB(tmp_path / "state.db")
    mission = MissionRun(
        id="m_autonomous",
        profile_id="autonomous-recon",
        scope=MissionScope(
            target="127.0.0.1",
            allowed_hosts=["127.0.0.1"],
            max_risk="active",
        ),
        metadata={"port_scope": "1-1000,8000"},
    )
    model = _FirstCoverageModel()

    report = MissionCoordinator(mission).run_agentic(
        config=config,
        state_db=db,
        model=model,
        registry=_registry(),
        max_tasks=10,
    )

    stored = db.get_mission(mission.id)
    assert stored is not None
    assert stored["status"] == "completed"
    assert stored["phase"] == "report"

    tasks = db.list_mission_tasks(mission.id)
    assert len(tasks) == 7
    assert {task["status"] for task in tasks} == {"completed"}
    assert len(model.calls) == 7
    assert all(call["tools"] == [] for call in model.calls)
    nmap_task = next(
        task for task in tasks if task["tool_name"] == "nmap_basic"
    )
    assert nmap_task["args"]["ports"] == "1-1000,8000"

    nodes = db.list_attack_surface_nodes(mission.id)
    assert {"host", "domain", "service", "endpoint", "technology"} <= {
        node["kind"] for node in nodes
    }
    services = [node for node in nodes if node["kind"] == "service"]
    assert {node["attributes"]["port"] for node in services} == {80, 443}

    coverage = db.list_mission_coverage(mission.id)
    assert coverage
    assert all(
        item["status"] == "complete" for item in coverage
    )
    assert all(
        item["status"] not in {"pending", "planned", "running"}
        for item in coverage
    )
    assert len(db.list_planner_cycles(mission.id)) == 8

    assert "## Attack Surface" in report
    assert "## Coverage Ledger" in report
    assert "## Planner Provenance" in report
    assert "Autonomous execution was limited" in report


def test_autonomous_recon_resumes_persistent_graph_and_coverage(
    tmp_path: Path,
    monkeypatch,
) -> None:
    monkeypatch.setenv("APP_HOME", str(tmp_path))
    config = load_config()
    db = StateDB(tmp_path / "state.db")
    mission = MissionRun(
        id="m_autonomous_resume",
        profile_id="autonomous-recon",
        scope=MissionScope(
            target="127.0.0.1",
            allowed_hosts=["127.0.0.1"],
            max_risk="active",
        ),
        metadata={"port_scope": "1-1000,8000"},
    )
    model = _FirstCoverageModel()
    coordinator = MissionCoordinator(mission)

    first_report = coordinator.run_agentic(
        config=config,
        state_db=db,
        model=model,
        registry=_registry(),
        max_tasks=1,
    )

    assert db.get_mission(mission.id)["status"] == "blocked"
    assert db.list_mission_coverage(mission.id)
    assert "Status: blocked" in first_report
    assert db.list_planner_cycles(mission.id)[0]["cycle"] == 1

    second_report = coordinator.run_agentic(
        config=config,
        state_db=db,
        model=model,
        registry=_registry(),
        max_tasks=10,
    )

    assert db.get_mission(mission.id)["status"] == "completed"
    cycles = db.list_planner_cycles(mission.id)
    assert [cycle["cycle"] for cycle in cycles] == list(range(1, 9))
    assert len(db.list_mission_tasks(mission.id)) == 7
    assert "Status: completed" in second_report
    assert "reverse_dns" in second_report

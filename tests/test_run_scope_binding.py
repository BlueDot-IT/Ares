from __future__ import annotations

from pathlib import Path

from ares.agent.runtime import ModelResponse, ToolCall
from ares.config.loader import AppConfig, LLMConfig, PolicyConfig
from ares.mission.tools import register_mission_tools
from ares.run import run_once
from ares.state.db import StateDB
from ares.tools.registry import ToolRegistry


class _FakeModel:
    def __init__(self, root: Path, paths: list[str]) -> None:
        self.responses = [
            ModelResponse(
                tool_calls=[
                    ToolCall(
                        name="redteam_secret_scan",
                        args={"root": str(root), "paths": paths},
                    )
                ]
            ),
            ModelResponse(final_text="done"),
        ]

    def complete(self, messages, tools):
        return self.responses.pop(0)


def _run_scan(*, home: Path, declared_target: Path, requested_root: Path, paths: list[str]):
    config = AppConfig(
        home=home,
        llm=LLMConfig(model="unit-model"),
        policy=PolicyConfig(max_risk="scan"),
    )
    registry = ToolRegistry()
    register_mission_tools(registry)
    return run_once(
        prompt="scan authorized source files",
        target=str(declared_target),
        config=config,
        model=_FakeModel(requested_root, paths),
        registry=registry,
        state_db=StateDB(home / "state.db"),
        max_iterations=2,
    )


def test_run_once_rejects_model_path_outside_declared_target(tmp_path: Path):
    scoped = tmp_path / "scoped"
    outside = tmp_path / "outside"
    (scoped / "src").mkdir(parents=True)
    (outside / "src").mkdir(parents=True)
    (outside / "src" / "secret.py").write_text(
        'api_key = "must-not-be-read"\n',
        encoding="utf-8",
    )

    result = _run_scan(
        home=tmp_path / "home-denied",
        declared_target=scoped,
        requested_root=outside,
        paths=["src"],
    )

    assert result.tool_results[0].status == "error"
    assert "scope policy violation" in result.tool_results[0].error


def test_run_once_allows_path_inside_declared_target(tmp_path: Path):
    scoped = tmp_path / "scoped"
    (scoped / "src").mkdir(parents=True)
    (scoped / "src" / "example.py").write_text(
        'api_key = "redacted-by-tool"\n',
        encoding="utf-8",
    )

    result = _run_scan(
        home=tmp_path / "home-allowed",
        declared_target=scoped,
        requested_root=scoped,
        paths=["src"],
    )

    assert result.tool_results[0].status == "ok"
    assert result.tool_results[0].result["summary"] == "Found 1 possible secret pattern."


def test_run_once_rejects_relative_path_traversal(tmp_path: Path):
    scoped = tmp_path / "scoped"
    outside = tmp_path / "outside"
    scoped.mkdir()
    outside.mkdir()
    (outside / "secret.py").write_text(
        'token = "must-not-be-read"\n',
        encoding="utf-8",
    )

    result = _run_scan(
        home=tmp_path / "home-traversal",
        declared_target=scoped,
        requested_root=scoped,
        paths=["../outside"],
    )

    assert result.tool_results[0].status == "error"
    assert "scope policy violation" in result.tool_results[0].error

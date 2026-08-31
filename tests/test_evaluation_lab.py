from __future__ import annotations

import json
import os
import socket
import sqlite3
from pathlib import Path
from unittest.mock import patch

from typer.testing import CliRunner

from ares.cli import app
from ares.evaluation import run_evaluation, serialize_evaluation_result


def test_bundled_evaluation_is_deterministic_and_passes() -> None:
    first = run_evaluation()
    second = run_evaluation()

    assert first == second
    assert first["schema"] == "ares.evaluation.result.v1"
    assert first["result"] == "pass"
    assert first["summary"] == {
        "passed": 12,
        "failed": 0,
        "total": 12,
        "fixture_pass_rate": 1.0,
    }
    assert len(first["corpus"]["sha256"]) == 64
    assert first["execution"] == {
        "mode": "offline",
        "deterministic": True,
        "uses_model": False,
        "uses_network": False,
    }


def test_scope_fixtures_report_bounded_reason_codes() -> None:
    result = run_evaluation()
    scope_suite = next(
        suite for suite in result["suites"] if suite["id"] == "scope_policy"
    )

    assert [case["observed"]["reason_code"] for case in scope_suite["cases"]] == [
        "allowed",
        "outside_allowed_paths",
        "outside_allowed_hosts",
        "forbidden_action",
        "exceeds_mission_risk",
    ]


def test_serialized_result_excludes_fixture_inputs_and_runtime_details() -> None:
    serialized = serialize_evaluation_result(run_evaluation())

    assert serialized == serialize_evaluation_result(run_evaluation())
    assert "/ares-evaluation/" not in serialized
    assert "192.0.2.10" not in serialized
    assert "198.51.100.20" not in serialized
    assert "timestamp" not in serialized
    assert "environment" not in serialized
    assert "intentional offline fixture failure" not in serialized


def test_evaluation_blocks_network_and_does_not_read_app_home(
    tmp_path, monkeypatch
) -> None:
    app_home = (tmp_path / "poisoned-app-home").resolve()
    app_home.mkdir()
    canary = app_home / "engagement-secret.txt"
    canary.write_text("must-not-be-read", encoding="utf-8")
    before = {
        path.relative_to(app_home): path.read_bytes()
        for path in app_home.rglob("*")
        if path.is_file()
    }
    monkeypatch.setenv("APP_HOME", str(app_home))

    original_path_open = Path.open
    original_sqlite_connect = sqlite3.connect

    def reject_app_home_open(path: Path, *args, **kwargs):
        try:
            path.resolve().relative_to(app_home)
        except ValueError:
            return original_path_open(path, *args, **kwargs)
        raise AssertionError(f"evaluation accessed APP_HOME: {path.name}")

    def reject_app_home_sqlite(database, *args, **kwargs):
        try:
            Path(database).resolve().relative_to(app_home)
        except (TypeError, ValueError):
            return original_sqlite_connect(database, *args, **kwargs)
        raise AssertionError("evaluation opened APP_HOME SQLite state")

    def reject_network(*_args, **_kwargs):
        raise AssertionError("evaluation attempted network access")

    monkeypatch.setattr(Path, "open", reject_app_home_open)
    monkeypatch.setattr(sqlite3, "connect", reject_app_home_sqlite)
    monkeypatch.setattr(socket, "socket", reject_network)
    monkeypatch.setattr(socket, "create_connection", reject_network)

    result = run_evaluation()

    assert result["result"] == "pass"
    after = {}
    for path in app_home.rglob("*"):
        if path.is_file():
            with original_path_open(path, "rb") as handle:
                after[path.relative_to(app_home)] = handle.read()
    assert after == before


def test_evaluate_cli_prints_plain_summary_and_writes_json(tmp_path) -> None:
    output_path = tmp_path / "evaluation.json"
    result = CliRunner().invoke(app, ["evaluate", "--out", str(output_path)])

    assert result.exit_code == 0, result.output
    assert "Ares Evaluation Lab v1" in result.output
    assert "Result: PASS" in result.output
    assert "Fixtures: 12/12 passed" in result.output
    assert "Not measured: model quality" in result.output
    payload = json.loads(output_path.read_text(encoding="utf-8"))
    assert payload["result"] == "pass"
    if os.name == "posix":
        assert output_path.stat().st_mode & 0o777 == 0o600


def test_evaluate_cli_json_stdout_is_machine_readable() -> None:
    result = CliRunner().invoke(app, ["evaluate", "--json"])

    assert result.exit_code == 0, result.output
    payload = json.loads(result.output)
    assert payload["schema"] == "ares.evaluation.result.v1"
    assert payload["summary"]["failed"] == 0


def test_evaluate_cli_returns_one_and_writes_bounded_json_on_failure(
    tmp_path,
) -> None:
    failure = run_evaluation()
    failure["result"] = "fail"
    failure["summary"] = {
        "passed": 11,
        "failed": 1,
        "total": 12,
        "fixture_pass_rate": 11 / 12,
    }
    output_path = tmp_path / "failed-evaluation.json"

    with patch("ares.cli.run_evaluation", return_value=failure):
        result = CliRunner().invoke(app, ["evaluate", "--out", str(output_path)])

    assert result.exit_code == 1
    assert "Result: FAIL" in result.output
    assert "Fixtures: 11/12 passed (1 failed)" in result.output
    payload = json.loads(output_path.read_text(encoding="utf-8"))
    assert payload["result"] == "fail"
    assert payload["summary"]["failed"] == 1

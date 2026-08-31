from __future__ import annotations

import json
import os

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

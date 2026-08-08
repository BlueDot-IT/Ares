import json
import re
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from typer.testing import CliRunner

from ares.cli import app


_ANSI_ESCAPE = re.compile(r"\x1b\[[0-9;]*m")


class ProductizationCliTests(unittest.TestCase):
    def setUp(self) -> None:
        self.runner = CliRunner()

    def test_doctor_json_is_machine_readable(self):
        with tempfile.TemporaryDirectory() as tmp:
            result = self.runner.invoke(
                app,
                ["doctor", "--json"],
                env={"APP_HOME": tmp},
            )

        self.assertEqual(result.exit_code, 0, result.output)
        payload = json.loads(result.output)
        self.assertEqual(payload["ares_version"], "1.1.0")
        self.assertEqual(payload["distribution"], "bluedot-ares")
        self.assertIn("registered_tools", payload)
        self.assertNotIn("api_key", payload)
        self.assertNotIn("operator_token", payload)

    def test_support_bundle_is_valid_and_excludes_engagement_data(self):
        with tempfile.TemporaryDirectory() as tmp:
            output = Path(tmp) / "support.json"
            result = self.runner.invoke(
                app,
                ["support-bundle", "--out", str(output)],
                env={"APP_HOME": tmp},
            )
            self.assertEqual(result.exit_code, 0, result.output)
            payload = json.loads(output.read_text(encoding="utf-8"))

        self.assertEqual(payload["schema_version"], 1)
        self.assertEqual(payload["runtime"]["ares_version"], "1.1.0")
        self.assertEqual(payload["runtime"]["distribution"], "bluedot-ares")
        self.assertIn("doctor", payload)
        self.assertNotIn("sessions", payload)
        self.assertNotIn("messages", payload)
        self.assertNotIn("tool_calls", payload)
        self.assertNotIn("evidence", payload)
        serialized = json.dumps(payload).lower()
        self.assertNotIn("api_key", serialized)
        self.assertNotIn("operator_token", serialized)
        self.assertNotIn("approval_receipt", serialized)

    def test_nested_mission_run_exposes_approval_receipts(self):
        result = self.runner.invoke(
            app,
            ["mission", "run", "--help"],
            env={"NO_COLOR": "1", "TERM": "dumb"},
        )

        self.assertEqual(result.exit_code, 0, result.output)
        normalized = _ANSI_ESCAPE.sub("", result.output)
        self.assertIn("--approval-receipts", normalized)


if __name__ == "__main__":
    unittest.main()

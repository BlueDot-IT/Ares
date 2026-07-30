import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))


class TrainingExportTests(unittest.TestCase):
    def test_export_valid_jsonl(self):
        from ares.agent.runtime import ModelResponse
        from ares.config.loader import AppConfig, LLMConfig, PolicyConfig, HooksConfig
        from ares.run import run_once
        from ares.state.db import StateDB
        from ares.tools.registry import ToolRegistry

        class FakeModel:
            def complete(self, messages, tools):
                return ModelResponse(final_text="done")

        with tempfile.TemporaryDirectory() as tmp:
            home = Path(tmp)
            config = AppConfig(
                home=home,
                llm=LLMConfig(model="unit-model"),
                policy=PolicyConfig(max_risk="passive"),
                hooks=HooksConfig(auto_report_on_finish=True),
            )

            run_once(
                prompt="Use api_key=sk-test123 and token=secret123",
                target="127.0.0.1",
                model=FakeModel(),
                config=config,
                registry=ToolRegistry(),
                max_iterations=2,
            )

            db = StateDB(home / "state.db")
            output_path = home / "data" / "ares-sft.jsonl"

            from ares.training.export import export_training_data

            count = export_training_data(db, output_path, min_status="final_response")
            self.assertEqual(count, 1)
            self.assertEqual(output_path.stat().st_mode & 0o777, 0o600)

            lines = output_path.read_text(encoding="utf-8").strip().split("\n")
            self.assertEqual(len(lines), 1)
            example = json.loads(lines[0])
            self.assertIn("instruction", example)
            self.assertIn("input", example)
            self.assertIn("output", example)
            self.assertIn("metadata", example)
            self.assertEqual(example["metadata"]["session_id"], 1)
            self.assertEqual(example["metadata"]["target"], "127.0.0.1")
            self.assertTrue(example["metadata"]["approved"])

    def test_does_not_export_failed_sessions(self):
        from ares.agent.runtime import ModelResponse
        from ares.config.loader import AppConfig, LLMConfig, PolicyConfig, HooksConfig
        from ares.run import run_once
        from ares.state.db import StateDB
        from ares.tools.registry import ToolRegistry

        class FakeModel:
            def complete(self, messages, tools):
                raise RuntimeError("model failed")

        with tempfile.TemporaryDirectory() as tmp:
            home = Path(tmp)
            config = AppConfig(
                home=home,
                llm=LLMConfig(model="unit-model"),
                policy=PolicyConfig(max_risk="passive"),
                hooks=HooksConfig(auto_report_on_finish=True),
            )

            with self.assertRaises(RuntimeError):
                run_once(
                    prompt="Use api_key=sk-test123 and token=secret123",
                    target="127.0.0.1",
                    model=FakeModel(),
                    config=config,
                    registry=ToolRegistry(),
                    max_iterations=2,
                )

            db = StateDB(home / "state.db")
            output_path = home / "data" / "ares-sft.jsonl"

            from ares.training.export import export_training_data

            count = export_training_data(db, output_path, min_status="final_response")
            self.assertEqual(count, 0)

    def test_does_not_export_sessions_with_policy_violations(self):
        from ares.agent.runtime import ModelResponse, ToolCall
        from ares.config.loader import AppConfig, LLMConfig, PolicyConfig, HooksConfig
        from ares.run import run_once
        from ares.state.db import StateDB
        from ares.tools.registry import ToolRegistry

        class FakeModel:
            def __init__(self):
                self.responses = [
                    ModelResponse(tool_calls=[ToolCall(name="exploit_tool", args={})]),
                    ModelResponse(final_text="done"),
                ]

            def complete(self, messages, tools):
                return self.responses.pop(0)

        with tempfile.TemporaryDirectory() as tmp:
            home = Path(tmp)
            config = AppConfig(
                home=home,
                llm=LLMConfig(model="unit-model"),
                policy=PolicyConfig(max_risk="exploit"),
                hooks=HooksConfig(auto_report_on_finish=True),
            )

            # This will fail due to policy enforcement (no approval)
            try:
                run_once(
                    prompt="Use api_key=sk-test123 and token=secret123",
                    target="127.0.0.1",
                    model=FakeModel(),
                    config=config,
                    registry=ToolRegistry(),
                    max_iterations=2,
                )
            except Exception:
                pass

            db = StateDB(home / "state.db")
            output_path = home / "data" / "ares-sft.jsonl"

            from ares.training.export import export_training_data

            count = export_training_data(db, output_path, min_status="final_response")
            # Session status should be error, so not exported
            self.assertEqual(count, 0)

    def test_redacts_secrets(self):
        from ares.agent.runtime import ModelResponse
        from ares.config.loader import AppConfig, LLMConfig, PolicyConfig, HooksConfig
        from ares.run import run_once
        from ares.state.db import StateDB
        from ares.tools.registry import ToolRegistry

        class FakeModel:
            def complete(self, messages, tools):
                return ModelResponse(final_text="The API key is sk-abc123secret and token=secret123")

        with tempfile.TemporaryDirectory() as tmp:
            home = Path(tmp)
            config = AppConfig(
                home=home,
                llm=LLMConfig(model="unit-model"),
                policy=PolicyConfig(max_risk="passive"),
                hooks=HooksConfig(auto_report_on_finish=True),
            )

            run_once(
                prompt="Use api_key=sk-test123 and token=secret123",
                target="127.0.0.1",
                model=FakeModel(),
                config=config,
                registry=ToolRegistry(),
                max_iterations=2,
            )

            db = StateDB(home / "state.db")
            output_path = home / "data" / "ares-sft.jsonl"

            from ares.training.export import export_training_data

            count = export_training_data(db, output_path, min_status="final_response")
            self.assertEqual(count, 1)

            lines = output_path.read_text(encoding="utf-8").strip().split("\n")
            example = json.loads(lines[0])
            self.assertNotIn("sk-test123", example["input"])
            self.assertNotIn("secret123", example["input"])
            self.assertNotIn("sk-test123", example["output"])
            self.assertNotIn("secret123", example["output"])
            self.assertIn("[REDACTED]", example["output"])

    def test_includes_session_metadata(self):
        from ares.agent.runtime import ModelResponse
        from ares.config.loader import AppConfig, LLMConfig, PolicyConfig, HooksConfig
        from ares.run import run_once
        from ares.state.db import StateDB
        from ares.tools.registry import ToolRegistry

        class FakeModel:
            def complete(self, messages, tools):
                return ModelResponse(final_text="done")

        with tempfile.TemporaryDirectory() as tmp:
            home = Path(tmp)
            config = AppConfig(
                home=home,
                llm=LLMConfig(model="test-model"),
                policy=PolicyConfig(max_risk="passive"),
                hooks=HooksConfig(auto_report_on_finish=True),
            )

            run_once(
                prompt="Use api_key=sk-test123 and token=secret123",
                target="127.0.0.1",
                model=FakeModel(),
                config=config,
                registry=ToolRegistry(),
                max_iterations=2,
            )

            db = StateDB(home / "state.db")
            output_path = home / "data" / "ares-sft.jsonl"

            from ares.training.export import export_training_data

            count = export_training_data(db, output_path, min_status="final_response")
            self.assertEqual(count, 1)

            lines = output_path.read_text(encoding="utf-8").strip().split("\n")
            example = json.loads(lines[0])
            metadata = example["metadata"]
            self.assertEqual(metadata["target"], "127.0.0.1")
            self.assertEqual(metadata["agent"], "default")
            self.assertEqual(metadata["model"], "test-model")
            self.assertTrue(metadata["approved"])
            self.assertIsInstance(metadata["tool_calls"], list)


if __name__ == "__main__":
    unittest.main()

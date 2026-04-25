import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))


class AresCliModelTests(unittest.TestCase):
    def _run_cli(self, *args: str, env: dict[str, str]) -> str:
        repo = Path(__file__).resolve().parents[1]
        python_bin = repo / ".venv" / "bin" / "python"
        result = subprocess.run(
            [str(python_bin), "-m", "ares.cli", *args],
            cwd=repo,
            env=env,
            check=True,
            capture_output=True,
            text=True,
        )
        return result.stdout

    def test_model_command_shows_current_settings_and_persists_updates(self):
        repo = Path(__file__).resolve().parents[1]
        with tempfile.TemporaryDirectory() as tmp:
            env = dict(os.environ)
            env["PYTHONPATH"] = str(repo / "src")
            env["ARES_HOME"] = tmp
            env.pop("ARES_LLM_PROVIDER", None)
            env.pop("ARES_LLM_MODEL", None)
            env.pop("ARES_OPENAI_BASE_URL", None)

            initial = self._run_cli("model", env=env)
            self.assertIn("provider: openai", initial)
            self.assertIn("model: local-model", initial)

            updated = self._run_cli(
                "model",
                "--provider",
                "openrouter",
                "--model",
                "redteam-model",
                "--base-url",
                "http://127.0.0.1:9000/v1",
                env=env,
            )
            self.assertIn("provider: openrouter", updated)
            self.assertIn("model: redteam-model", updated)
            self.assertIn("base_url: http://127.0.0.1:9000/v1", updated)

            config_path = Path(tmp) / "config.json"
            saved = json.loads(config_path.read_text(encoding="utf-8"))
            self.assertEqual(saved["llm"]["provider"], "openrouter")
            self.assertEqual(saved["llm"]["model"], "redteam-model")
            self.assertEqual(saved["llm"]["openai_base_url"], "http://127.0.0.1:9000/v1")

    def test_model_command_can_apply_named_profile(self):
        repo = Path(__file__).resolve().parents[1]
        with tempfile.TemporaryDirectory() as tmp:
            env = dict(os.environ)
            env["PYTHONPATH"] = str(repo / "src")
            env["ARES_HOME"] = tmp
            env.pop("ARES_LLM_PROVIDER", None)
            env.pop("ARES_LLM_MODEL", None)
            env.pop("ARES_OPENAI_BASE_URL", None)

            updated = self._run_cli("model", "--profile", "openrouter", env=env)

            self.assertIn("profile: openrouter", updated)
            self.assertIn("provider: openrouter", updated)
            self.assertIn("base_url: https://openrouter.ai/api/v1", updated)
            saved = json.loads((Path(tmp) / "config.json").read_text(encoding="utf-8"))
            self.assertEqual(saved["llm"]["provider"], "openrouter")
            self.assertEqual(saved["llm"]["openai_base_url"], "https://openrouter.ai/api/v1")


if __name__ == "__main__":
    unittest.main()

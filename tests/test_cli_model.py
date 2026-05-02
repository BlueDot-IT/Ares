import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))


class AresCliModelTests(unittest.TestCase):
    def _run_cli(self, *args: str, env: dict[str, str], input_text: str = "") -> str:
        repo = Path(__file__).resolve().parents[1]
        result = subprocess.run(
            [sys.executable, "-m", "ares.cli", *args],
            cwd=repo,
            env=env,
            input=input_text,
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
            env["APP_HOME"] = tmp
            env.pop("LLM_PROVIDER", None)
            env.pop("LLM_MODEL", None)
            env.pop("OPENAI_BASE_URL", None)

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
            env["APP_HOME"] = tmp
            env.pop("LLM_PROVIDER", None)
            env.pop("LLM_MODEL", None)
            env.pop("OPENAI_BASE_URL", None)

            updated = self._run_cli("model", "--profile", "openrouter", env=env)

            self.assertIn("profile: openrouter", updated)
            self.assertIn("provider: openrouter", updated)
            self.assertIn("base_url: https://openrouter.ai/api/v1", updated)
            saved = json.loads((Path(tmp) / "config.json").read_text(encoding="utf-8"))
            self.assertEqual(saved["llm"]["provider"], "openrouter")
            self.assertEqual(saved["llm"]["openai_base_url"], "https://openrouter.ai/api/v1")

    def test_model_command_can_persist_openai_oauth_settings(self):
        repo = Path(__file__).resolve().parents[1]
        with tempfile.TemporaryDirectory() as tmp:
            env = dict(os.environ)
            env["PYTHONPATH"] = str(repo / "src")
            env["APP_HOME"] = tmp
            env.pop("LLM_PROVIDER", None)
            env.pop("LLM_MODEL", None)
            env.pop("OPENAI_BASE_URL", None)

            updated = self._run_cli(
                "model",
                "--provider",
                "openai",
                "--model",
                "gpt-4.1-mini",
                "--auth-mode",
                "oauth",
                env=env,
            )

            self.assertIn("auth_mode: oauth", updated)
            saved = json.loads((Path(tmp) / "config.json").read_text(encoding="utf-8"))
            self.assertEqual(saved["llm"]["auth_mode"], "oauth")
            self.assertEqual(saved["llm"].get("oauth_token_command", ""), "")

    def test_model_command_can_run_interactive_wizard_for_local_profile(self):
        repo = Path(__file__).resolve().parents[1]
        with tempfile.TemporaryDirectory() as tmp:
            env = dict(os.environ)
            env["PYTHONPATH"] = str(repo / "src")
            env["APP_HOME"] = tmp
            env.pop("LLM_PROVIDER", None)
            env.pop("LLM_MODEL", None)
            env.pop("OPENAI_BASE_URL", None)

            output = self._run_cli(
                "model",
                "--interactive",
                env=env,
                input_text="\n".join(
                    [
                        "1",
                        "llama-3.1-local",
                        "n",
                    ]
                )
                + "\n",
            )

            saved = json.loads((Path(tmp) / "config.json").read_text(encoding="utf-8"))

        self.assertIn("Model setup complete.", output)
        self.assertIn("profile: local", output)
        self.assertIn("provider: openai", output)
        self.assertEqual(saved["llm"]["profile"], "local")
        self.assertEqual(saved["llm"]["provider"], "openai")
        self.assertEqual(saved["llm"]["model"], "llama-3.1-local")
        self.assertEqual(saved["llm"]["openai_base_url"], "http://127.0.0.1:1234/v1")

    def test_model_command_interactive_wizard_can_configure_gemini_oauth(self):
        repo = Path(__file__).resolve().parents[1]
        with tempfile.TemporaryDirectory() as tmp:
            env = dict(os.environ)
            env["PYTHONPATH"] = str(repo / "src")
            env["APP_HOME"] = tmp
            env.pop("LLM_PROVIDER", None)
            env.pop("LLM_MODEL", None)
            env.pop("OPENAI_BASE_URL", None)

            output = self._run_cli(
                "model",
                "--interactive",
                env=env,
                input_text="\n".join(
                    [
                        "5",
                        "gemini-2.5-pro",
                        "2",
                        "demo-project",
                        "us-central1",
                        "n",
                    ]
                )
                + "\n",
            )

            saved = json.loads((Path(tmp) / "config.json").read_text(encoding="utf-8"))

        self.assertIn("Model setup complete.", output)
        self.assertIn("auth_mode: oauth", output)
        self.assertEqual(saved["llm"]["profile"], "gemini")
        self.assertEqual(saved["llm"]["provider"], "gemini")
        self.assertEqual(saved["llm"]["auth_mode"], "oauth")
        self.assertEqual(saved["llm"].get("oauth_token_command", ""), "")
        self.assertEqual(saved["llm"]["oauth_project"], "demo-project")
        self.assertEqual(saved["llm"]["oauth_location"], "us-central1")


if __name__ == "__main__":
    unittest.main()

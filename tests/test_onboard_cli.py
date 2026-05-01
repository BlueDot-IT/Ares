import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))


class AresCliOnboardTests(unittest.TestCase):
    def _run_cli(self, *args: str, env: dict[str, str], input_text: str = "") -> str:
        repo = Path(__file__).resolve().parents[1]
        python_bin = repo / ".venv" / "bin" / "python"
        result = subprocess.run(
            [str(python_bin), "-m", "ares.cli", *args],
            cwd=repo,
            env=env,
            input=input_text,
            check=True,
            capture_output=True,
            text=True,
        )
        return result.stdout

    def test_onboard_command_persists_local_profile_theme_gateway_and_hooks(self):
        repo = Path(__file__).resolve().parents[1]
        with tempfile.TemporaryDirectory() as tmp:
            env = dict(os.environ)
            env["PYTHONPATH"] = str(repo / "src")
            env["APP_HOME"] = tmp
            env.pop("LLM_PROVIDER", None)
            env.pop("LLM_MODEL", None)
            env.pop("OPENAI_BASE_URL", None)

            output = self._run_cli(
                "onboard",
                env=env,
                input_text="\n".join(
                    [
                        "1",
                        "llama-3.1-local",
                        "ember",
                        "1",
                        "n",
                    ]
                )
                + "\n",
            )

            saved = json.loads((Path(tmp) / "config.json").read_text(encoding="utf-8"))

        self.assertIn("Ares onboarding complete.", output)
        self.assertIn("provider: openai", output)
        self.assertIn("theme: ember", output)
        self.assertEqual(saved["llm"]["profile"], "local")
        self.assertEqual(saved["llm"]["provider"], "openai")
        self.assertEqual(saved["llm"]["model"], "llama-3.1-local")
        self.assertEqual(saved["llm"]["openai_base_url"], "http://127.0.0.1:1234/v1")
        self.assertEqual(saved["ui"]["theme"], "ember")
        self.assertEqual(saved["gateway"]["mode"], "loopback")
        self.assertNotIn("auth_enabled", saved.get("gateway", {}))
        self.assertEqual(saved["hooks"]["auto_report_on_finish"], False)

    def test_onboard_command_can_configure_openrouter_and_exposed_gateway_auth(self):
        repo = Path(__file__).resolve().parents[1]
        with tempfile.TemporaryDirectory() as tmp:
            env = dict(os.environ)
            env["PYTHONPATH"] = str(repo / "src")
            env["APP_HOME"] = tmp
            env.pop("LLM_PROVIDER", None)
            env.pop("LLM_MODEL", None)
            env.pop("OPENAI_BASE_URL", None)

            output = self._run_cli(
                "onboard",
                env=env,
                input_text="\n".join(
                    [
                        "3",
                        "openai/gpt-4o-mini",
                        "n",
                        "ember",
                        "3",
                        "y",
                        "operator-secret",
                        "127.0.0.1/32,10.0.0.0/8",
                        "y",
                    ]
                )
                + "\n",
            )

            saved = json.loads((Path(tmp) / "config.json").read_text(encoding="utf-8"))

        self.assertIn("gateway auth: enabled", output)
        self.assertEqual(saved["llm"]["profile"], "openrouter")
        self.assertEqual(saved["llm"]["provider"], "openrouter")
        self.assertEqual(saved["llm"]["model"], "openai/gpt-4o-mini")
        self.assertEqual(saved["llm"]["openai_base_url"], "https://openrouter.ai/api/v1")
        self.assertEqual(saved["gateway"]["mode"], "exposed")
        self.assertTrue(saved["gateway"]["auth_enabled"])
        self.assertEqual(saved["gateway"]["operator_token"], "operator-secret")
        self.assertEqual(saved["gateway"]["allow_cidrs"], ["127.0.0.1/32", "10.0.0.0/8"])
        self.assertEqual(saved["hooks"]["auto_report_on_finish"], True)

    def test_onboard_command_accepts_openai_cloud_profile_without_endpoint_prompt(self):
        repo = Path(__file__).resolve().parents[1]
        with tempfile.TemporaryDirectory() as tmp:
            env = dict(os.environ)
            env["PYTHONPATH"] = str(repo / "src")
            env["APP_HOME"] = tmp
            env.pop("LLM_PROVIDER", None)
            env.pop("LLM_MODEL", None)
            env.pop("OPENAI_BASE_URL", None)

            output = self._run_cli(
                "onboard",
                env=env,
                input_text="\n".join(
                    [
                        "2",
                        "gpt-4.1-mini",
                        "1",
                        "n",
                        "ember",
                        "1",
                        "n",
                    ]
                )
                + "\n",
            )

            saved = json.loads((Path(tmp) / "config.json").read_text(encoding="utf-8"))

        self.assertIn("profile: openai", output)
        self.assertEqual(saved["llm"]["profile"], "openai")
        self.assertEqual(saved["llm"]["provider"], "openai")
        self.assertEqual(saved["llm"]["model"], "gpt-4.1-mini")
        self.assertEqual(saved["llm"]["openai_base_url"], "https://api.openai.com/v1")
        self.assertEqual(saved["llm"]["auth_mode"], "api-key")

    def test_onboard_command_can_configure_gemini_oauth_without_token_command(self):
        repo = Path(__file__).resolve().parents[1]
        with tempfile.TemporaryDirectory() as tmp:
            env = dict(os.environ)
            env["PYTHONPATH"] = str(repo / "src")
            env["APP_HOME"] = tmp
            env.pop("LLM_PROVIDER", None)
            env.pop("LLM_MODEL", None)
            env.pop("OPENAI_BASE_URL", None)

            output = self._run_cli(
                "onboard",
                env=env,
                input_text="\n".join(
                    [
                        "5",
                        "gemini-2.5-pro",
                        "2",
                        "demo-project",
                        "us-central1",
                        "n",
                        "ember",
                        "1",
                        "n",
                    ]
                )
                + "\n",
            )

            saved = json.loads((Path(tmp) / "config.json").read_text(encoding="utf-8"))

        self.assertIn("auth_mode: oauth", output)
        self.assertEqual(saved["llm"]["provider"], "gemini")
        self.assertEqual(saved["llm"]["auth_mode"], "oauth")
        self.assertEqual(saved["llm"].get("oauth_token_command", ""), "")
        self.assertEqual(saved["llm"]["oauth_project"], "demo-project")
        self.assertEqual(saved["llm"]["oauth_location"], "us-central1")


if __name__ == "__main__":
    unittest.main()

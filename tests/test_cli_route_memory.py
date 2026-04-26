import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))


class AresCliRouteMemoryTests(unittest.TestCase):
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

    def test_route_command_previews_selected_profile_and_reason(self):
        repo = Path(__file__).resolve().parents[1]
        with tempfile.TemporaryDirectory() as tmp:
            env = dict(os.environ)
            env["PYTHONPATH"] = str(repo / "src")
            env["ARES_HOME"] = tmp
            config_path = Path(tmp) / "config.json"
            config_path.write_text(
                json.dumps(
                    {
                        "agents": {
                            "default_agent": "default",
                            "profiles": {
                                "default": {"name": "default"},
                                "web": {
                                    "name": "web",
                                    "provider": "openrouter",
                                    "model": "web-model",
                                    "prompt_prefix": "[web-recon] ",
                                    "memory_tags": ["recon", "external"],
                                },
                            },
                            "routes": [
                                {
                                    "agent": "web",
                                    "prompt_contains": ["recon"],
                                    "roe_profiles": ["safe-active"],
                                }
                            ],
                        }
                    }
                ),
                encoding="utf-8",
            )

            output = self._run_cli("route", "--prompt", "recon target", "--target", "https://corp.example", env=env)

        self.assertIn("agent: web", output)
        self.assertIn("reason: route", output)
        self.assertIn("provider: openrouter", output)
        self.assertIn("prompt_prefix: [web-recon]", output)
        self.assertIn("memory_tags: recon, external", output)

    def test_memory_command_lists_matching_engagement_entries(self):
        repo = Path(__file__).resolve().parents[1]
        with tempfile.TemporaryDirectory() as tmp:
            env = dict(os.environ)
            env["PYTHONPATH"] = str(repo / "src")
            env["ARES_HOME"] = tmp
            memory_dir = Path(tmp) / "memory" / "engagements"
            memory_dir.mkdir(parents=True, exist_ok=True)
            (memory_dir / "session-2.json").write_text(
                json.dumps(
                    {
                        "session_id": 2,
                        "target": "https://corp.example",
                        "agent": "web",
                        "status": "completed",
                        "memory_tags": ["recon"],
                        "summary": "Matched login surface.",
                    }
                ),
                encoding="utf-8",
            )
            (memory_dir / "session-3.json").write_text(
                json.dumps(
                    {
                        "session_id": 3,
                        "target": "https://other.example",
                        "agent": "default",
                        "status": "completed",
                        "memory_tags": ["internal"],
                        "summary": "Ignore me.",
                    }
                ),
                encoding="utf-8",
            )

            output = self._run_cli("memory", "--target", "corp.example", "--tag", "recon", env=env)

        self.assertIn("session_id: 2", output)
        self.assertIn("target: https://corp.example", output)
        self.assertIn("Matched login surface.", output)
        self.assertNotIn("Ignore me.", output)


if __name__ == "__main__":
    unittest.main()

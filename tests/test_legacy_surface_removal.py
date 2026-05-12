import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))


class LegacySurfaceRemovalTests(unittest.TestCase):
    def test_legacy_entrypoints_are_removed(self):
        repo = Path(__file__).resolve().parents[1]
        self.assertFalse((repo / "src" / "cli.py").exists(), "legacy root CLI should be removed")
        self.assertFalse((repo / "src" / "main.py").exists(), "legacy GUI entrypoint should be removed")
        self.assertFalse((repo / "src" / "lib" / "orchestrator.py").exists(), "legacy orchestrator should be removed")
        self.assertFalse((repo / "src" / "ui").exists(), "legacy PySide6 UI package should be removed")

    def test_modern_cli_exposes_supported_commands_only(self):
        from ares.cli import app

        command_names = {command.name for command in app.registered_commands}
        self.assertIn("run", command_names)
        self.assertIn("tui", command_names)
        self.assertIn("gateway", command_names)
        self.assertNotIn("scan", command_names)
        self.assertNotIn("replay", command_names)
        self.assertNotIn("legacy", command_names)


if __name__ == "__main__":
    unittest.main()

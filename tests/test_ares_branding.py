import os
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))


class AresBrandingTests(unittest.TestCase):
    def test_ares_package_exposes_version_and_app_name(self):
        import ares

        self.assertEqual(ares.APP_NAME, "Ares")
        self.assertEqual(ares.__version__, "1.1.1")

    def test_load_config_uses_ares_environment_names(self):
        from ares.config.loader import load_config

        old_values = {key: os.environ.get(key) for key in ["APP_HOME", "LLM_MODEL"]}
        try:
            with tempfile.TemporaryDirectory() as ares_tmp:
                os.environ["APP_HOME"] = ares_tmp
                os.environ["LLM_MODEL"] = "ares-model"

                cfg = load_config()

                self.assertEqual(cfg.home, Path(ares_tmp))
                self.assertEqual(cfg.llm.model, "ares-model")
        finally:
            for key, value in old_values.items():
                if value is None:
                    os.environ.pop(key, None)
                else:
                    os.environ[key] = value

    def test_session_report_uses_ares_branding(self):
        from ares.reporting.markdown import render_session_report
        from ares.state.db import StateDB

        with tempfile.TemporaryDirectory() as tmp:
            db = StateDB(Path(tmp) / "state.db")
            session_id = db.create_session(prompt="enumerate", target="127.0.0.1", model="unit", mode="safe-active")
            db.finish_session(session_id, "completed")

            report = render_session_report(db, session_id)

        self.assertIn("# Ares Session Report", report)


if __name__ == "__main__":
    unittest.main()

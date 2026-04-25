import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))


class SessionReportHelperTests(unittest.TestCase):
    def test_list_sessions_summary_and_write_report_file(self):
        from ares.run import list_session_summaries, write_session_report
        from ares.state.db import StateDB

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            db = StateDB(root / "state.db")
            session_id = db.create_session(prompt="enumerate", target="127.0.0.1", model="unit", mode="safe-active")
            db.record_host(session_id, "127.0.0.1")
            db.finish_session(session_id, "final")

            summaries = list_session_summaries(db)
            output_path = write_session_report(db, session_id, root / "reports")

            self.assertEqual(summaries[0]["id"], session_id)
            self.assertEqual(summaries[0]["target"], "127.0.0.1")
            self.assertEqual(summaries[0]["status"], "final")
            self.assertTrue(output_path.exists())
            self.assertIn("Ares Session Report", output_path.read_text())


if __name__ == "__main__":
    unittest.main()

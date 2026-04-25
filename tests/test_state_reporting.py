import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))


class StateReportTests(unittest.TestCase):
    def test_markdown_report_contains_session_tool_calls_and_evidence(self):
        from ares.reporting.markdown import render_session_report
        from ares.state.db import StateDB

        with tempfile.TemporaryDirectory() as tmp:
            db = StateDB(Path(tmp) / "state.db")
            session_id = db.create_session(target="127.0.0.1", prompt="enumerate")
            db.record_message(session_id, "user", "enumerate")
            db.record_tool_call(
                session_id,
                tool_name="nmap_scan",
                args={"target": "127.0.0.1"},
                status="ok",
                result={"stdout": "22/tcp open ssh"},
                duration_ms=15,
            )
            db.record_host(session_id, "127.0.0.1")
            db.record_service(session_id, "127.0.0.1", port=22, protocol="tcp", state="open", service="ssh")
            db.finish_session(session_id, status="final")

            report = render_session_report(db, session_id)

        self.assertIn("# Ares Session Report", report)
        self.assertIn("Target: 127.0.0.1", report)
        self.assertIn("nmap_scan", report)
        self.assertIn("127.0.0.1", report)
        self.assertIn("22/tcp", report)
        self.assertIn("ssh", report)


if __name__ == "__main__":
    unittest.main()

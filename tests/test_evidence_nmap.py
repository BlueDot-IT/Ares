import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))


NMAP_SAMPLE = """
Nmap scan report for 127.0.0.1
Host is up (0.00012s latency).
PORT    STATE SERVICE VERSION
80/tcp  open  http    nginx 1.24
443/tcp open  https   nginx 1.24
"""


class EvidenceParserTests(unittest.TestCase):
    def test_parse_nmap_stdout_records_hosts_and_services(self):
        from ares.evidence.nmap import parse_nmap_stdout_into_state
        from ares.state.db import StateDB

        with tempfile.TemporaryDirectory() as tmp:
            db = StateDB(Path(tmp) / "state.db")
            session_id = db.create_session(prompt="scan", target="127.0.0.1", model="unit", mode="safe-active")

            parse_nmap_stdout_into_state(db, session_id=session_id, stdout=NMAP_SAMPLE)

            hosts = db.list_hosts(session_id)
            services = db.list_services(session_id)

            self.assertEqual(hosts[0]["address"], "127.0.0.1")
            self.assertEqual([(s["port"], s["proto"], s["service"]) for s in services], [(80, "tcp", "http"), (443, "tcp", "https")])


if __name__ == "__main__":
    unittest.main()

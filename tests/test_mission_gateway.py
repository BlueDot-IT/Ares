from __future__ import annotations

import json
import tempfile
import threading
import unittest
import urllib.request
from pathlib import Path

from ares.gateway import AresGateway, start_gateway_server
from ares.state.db import StateDB
from ares.mission.model import MissionRun, MissionScope, MissionStatus, MissionPhase
from ares.mission.tasks import MissionTask, TaskStatus
from ares.mission.findings import MissionFinding, Severity, FindingState


class MissionGatewayApiTests(unittest.TestCase):
    def test_mission_gateway_endpoints(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp).resolve()
            
            # Initialize gateway and state db
            gateway = AresGateway(home=tmp_path)
            state_db = StateDB(tmp_path / "state.db")

            # Seed a dummy completed mission to test GET endpoints
            scope = MissionScope(target="src", allowed_paths=["src"])
            mission = MissionRun(
                id="m_gw_test",
                profile_id="secrets-audit",
                scope=scope,
                status=MissionStatus.COMPLETED,
                phase=MissionPhase.REPORT,
            )
            state_db.create_mission(mission)

            task = MissionTask(
                id="t_gw_comp",
                mission_id="m_gw_test",
                role_id="scanner",
                phase="scan",
                tool_name="redteam_secret_scan",
                toolset="redteam_secrets",
                target="src",
                description="Scan secrets",
                status=TaskStatus.COMPLETED,
            )
            state_db.record_mission_task(task)

            finding = MissionFinding(
                id="f_gw_val",
                mission_id="m_gw_test",
                title="API Key",
                severity=Severity.HIGH,
                state=FindingState.VALIDATED,
                affected_component="src/config.py",
                confidence=0.8,
                validator_note="Valid",
                recommendation="Rotate",
                redacted="api_key = ***",
            )
            state_db.record_mission_finding(finding)

            # Start server
            server = start_gateway_server(gateway, host="127.0.0.1", port=0, mode="loopback")
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()

            try:
                base = f"http://127.0.0.1:{server.server_address[1]}"

                # 1. Test POST /api/mission/run (dry-run)
                payload = {
                    "profile_id": "secrets-audit",
                    "target": "src",
                    "allowed_paths": ["src"],
                    "dry_run": True,
                }
                request = urllib.request.Request(
                    base + "/api/mission/run",
                    data=json.dumps(payload).encode("utf-8"),
                    headers={"Content-Type": "application/json"},
                    method="POST",
                )
                res_post = json.loads(urllib.request.urlopen(request, timeout=2).read().decode("utf-8"))
                self.assertTrue(res_post["dry_run"])
                self.assertEqual(res_post["profile_id"], "secrets-audit")
                self.assertEqual(len(res_post["tasks"]), 3)

                # Advanced profiles accept only an explicit, validated graph.
                advanced_payload = {
                    "mission_id": "engagement-gateway-test",
                    "profile_id": "authorized-operator-validation",
                    "target": "127.0.0.1",
                    "allowed_hosts": ["127.0.0.1"],
                    "max_risk": "post-exploitation",
                    "dry_run": True,
                    "initial_tasks": [
                        {
                            "id": "bounded-smb-check",
                            "role_id": "infiltrator",
                            "phase": "post-exploitation",
                            "tool_name": "smbmap",
                            "toolset": "ghostmcp",
                            "target": "127.0.0.1",
                            "description": "Validate one authorized boundary.",
                            "args": {"host": "127.0.0.1"},
                        }
                    ],
                }
                advanced_request = urllib.request.Request(
                    base + "/api/mission/run",
                    data=json.dumps(advanced_payload).encode("utf-8"),
                    headers={"Content-Type": "application/json"},
                    method="POST",
                )
                advanced = json.loads(
                    urllib.request.urlopen(
                        advanced_request,
                        timeout=2,
                    ).read().decode("utf-8")
                )
                self.assertTrue(advanced["dry_run"])
                self.assertEqual(
                    advanced["mission_id"],
                    "engagement-gateway-test",
                )
                self.assertEqual(len(advanced["tasks"]), 1)

                # 2. Test GET /api/mission/list
                res_list = json.loads(urllib.request.urlopen(base + "/api/mission/list", timeout=2).read().decode("utf-8"))
                self.assertGreaterEqual(len(res_list), 1)
                self.assertEqual(res_list[0]["id"], "m_gw_test")

                # 3. Test GET /api/mission/{id}
                res_detail = json.loads(urllib.request.urlopen(base + "/api/mission/m_gw_test", timeout=2).read().decode("utf-8"))
                self.assertEqual(res_detail["profile_id"], "secrets-audit")
                self.assertEqual(res_detail["status"], "completed")

                # 4. Test GET /api/mission/{id}/report
                res_report = json.loads(urllib.request.urlopen(base + "/api/mission/m_gw_test/report", timeout=2).read().decode("utf-8"))
                self.assertEqual(res_report["mission_id"], "m_gw_test")
                self.assertIn("# ARES Mission Report", res_report["report"])
                self.assertIn("api_key = ***", res_report["report"])

            finally:
                server.shutdown()
                server.server_close()
                thread.join(timeout=2)


if __name__ == "__main__":
    unittest.main()

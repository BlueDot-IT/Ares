import json
import sys
import tempfile
import threading
import time
import types
import unittest
import urllib.request
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))


class GatewayControlPlaneTests(unittest.TestCase):
    def test_gateway_tracks_background_runs_and_event_stream(self):
        from ares.gateway import AresGateway

        events_seen = []

        def fake_runner(**kwargs):
            kwargs["session_started_callback"](73)
            kwargs["event_callback"]({"type": "tool_call", "tool": "echo_tool", "message": "echo_tool {}"})
            kwargs["event_callback"]({"type": "final_response", "final_response": "done", "message": "done"})
            events_seen.append(kwargs["prompt"])
            return types.SimpleNamespace(final_response="done", stop_reason="final_response")

        with tempfile.TemporaryDirectory() as tmp:
            gateway = AresGateway(home=Path(tmp), runner=fake_runner)
            created = gateway.submit_run(prompt="enumerate localhost", target="127.0.0.1", requested_agent="local-recon")
            finished = gateway.wait_for_run(created["id"], timeout=2.0)
            stream = gateway.get_events(after=0)

        self.assertEqual(events_seen, ["enumerate localhost"])
        self.assertEqual(finished["status"], "completed")
        self.assertEqual(finished["session_id"], 73)
        self.assertEqual(finished["requested_agent"], "local-recon")
        self.assertEqual([event["type"] for event in stream], ["session_started", "tool_call", "final_response", "session_finished"])
        self.assertEqual(stream[-1]["run_id"], created["id"])

    def test_http_gateway_exposes_health_runs_and_events(self):
        from ares.gateway import AresGateway, start_gateway_server

        def fake_runner(**kwargs):
            kwargs["session_started_callback"](11)
            kwargs["event_callback"]({"type": "final_response", "final_response": "ok", "message": "ok"})
            return types.SimpleNamespace(final_response="ok", stop_reason="final_response")

        with tempfile.TemporaryDirectory() as tmp:
            gateway = AresGateway(home=Path(tmp), runner=fake_runner)
            server = start_gateway_server(gateway, host="127.0.0.1", port=0)
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            try:
                base = f"http://127.0.0.1:{server.server_address[1]}"
                health = json.loads(urllib.request.urlopen(base + "/health", timeout=2).read().decode("utf-8"))
                request = urllib.request.Request(
                    base + "/api/runs",
                    data=json.dumps({"prompt": "scan target", "target": "127.0.0.1"}).encode("utf-8"),
                    headers={"Content-Type": "application/json"},
                    method="POST",
                )
                created = json.loads(urllib.request.urlopen(request, timeout=2).read().decode("utf-8"))
                gateway.wait_for_run(created["id"], timeout=2.0)
                run_payload = json.loads(urllib.request.urlopen(base + f"/api/runs/{created['id']}", timeout=2).read().decode("utf-8"))
                events = json.loads(urllib.request.urlopen(base + "/api/events?after=0", timeout=2).read().decode("utf-8"))
            finally:
                server.shutdown()
                server.server_close()
                thread.join(timeout=2)

        self.assertEqual(health["status"], "ok")
        self.assertEqual(run_payload["status"], "completed")
        self.assertEqual(run_payload["final_response"], "ok")
        self.assertGreaterEqual(events["count"], 2)
        self.assertTrue(any(event["type"] == "session_finished" for event in events["events"]))


if __name__ == "__main__":
    unittest.main()

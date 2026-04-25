import json
import sys
import tempfile
import threading
import types
import unittest
import urllib.request
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))


class GatewayWebUiTests(unittest.TestCase):
    def test_http_gateway_serves_web_ui_shell_and_assets(self):
        from ares.gateway import AresGateway, start_gateway_server

        def fake_runner(**kwargs):
            kwargs["session_started_callback"](21)
            kwargs["event_callback"]({"type": "final_response", "final_response": "ok", "message": "ok"})
            return types.SimpleNamespace(final_response="ok", stop_reason="final_response")

        with tempfile.TemporaryDirectory() as tmp:
            gateway = AresGateway(home=Path(tmp), runner=fake_runner)
            server = start_gateway_server(gateway, host="127.0.0.1", port=0)
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            try:
                base = f"http://127.0.0.1:{server.server_address[1]}"
                index = urllib.request.urlopen(base + "/", timeout=2)
                html = index.read().decode("utf-8")
                app_js = urllib.request.urlopen(base + "/app.js", timeout=2)
                js = app_js.read().decode("utf-8")
                app_css = urllib.request.urlopen(base + "/app.css", timeout=2)
                css = app_css.read().decode("utf-8")
            finally:
                server.shutdown()
                server.server_close()
                thread.join(timeout=2)

        self.assertEqual(index.headers.get_content_type(), "text/html")
        self.assertEqual(app_js.headers.get_content_type(), "application/javascript")
        self.assertEqual(app_css.headers.get_content_type(), "text/css")
        self.assertIn("<title>Ares Web UI</title>", html)
        self.assertIn('<body data-theme="ember">', html)
        self.assertIn('id="run-form"', html)
        self.assertIn('id="runs-panel"', html)
        self.assertIn('id="events-panel"', html)
        self.assertIn('id="transcript-panel"', html)
        self.assertIn("/api/runs", js)
        self.assertIn("/api/events", js)
        self.assertIn("submitRun", js)
        self.assertIn("refreshRuns", js)
        self.assertIn("background: #160d09", css)
        self.assertIn(".panel", css)

    def test_web_ui_shell_preserves_existing_run_submission_api(self):
        from ares.gateway import AresGateway, start_gateway_server

        def fake_runner(**kwargs):
            kwargs["session_started_callback"](34)
            kwargs["event_callback"]({"type": "tool_call", "tool": "echo", "message": "echo {}"})
            kwargs["event_callback"]({"type": "final_response", "final_response": "complete", "message": "complete"})
            return types.SimpleNamespace(final_response="complete", stop_reason="final_response")

        with tempfile.TemporaryDirectory() as tmp:
            gateway = AresGateway(home=Path(tmp), runner=fake_runner)
            server = start_gateway_server(gateway, host="127.0.0.1", port=0)
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            try:
                base = f"http://127.0.0.1:{server.server_address[1]}"
                request = urllib.request.Request(
                    base + "/api/runs",
                    data=json.dumps(
                        {
                            "prompt": "enumerate target",
                            "target": "127.0.0.1",
                            "agent": "web-console",
                            "approve_dangerous": False,
                        }
                    ).encode("utf-8"),
                    headers={"Content-Type": "application/json"},
                    method="POST",
                )
                created = json.loads(urllib.request.urlopen(request, timeout=2).read().decode("utf-8"))
                gateway.wait_for_run(created["id"], timeout=2.0)
                events = json.loads(urllib.request.urlopen(base + "/api/events?after=0", timeout=2).read().decode("utf-8"))
                run_payload = json.loads(urllib.request.urlopen(base + f"/api/runs/{created['id']}", timeout=2).read().decode("utf-8"))
            finally:
                server.shutdown()
                server.server_close()
                thread.join(timeout=2)

        self.assertEqual(run_payload["status"], "completed")
        self.assertEqual(run_payload["requested_agent"], "web-console")
        self.assertTrue(any(event["type"] == "tool_call" for event in events["events"]))
        self.assertTrue(any(event["type"] == "session_finished" for event in events["events"]))


if __name__ == "__main__":
    unittest.main()

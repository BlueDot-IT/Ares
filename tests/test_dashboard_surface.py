import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))


class DashboardSurfaceTests(unittest.TestCase):
    def test_dashboard_assets_are_separate_from_gateway_control_plane(self):
        from ares.dashboard import build_dashboard_css, build_dashboard_html, build_dashboard_js

        html = build_dashboard_html(auth_required=True)
        css = build_dashboard_css()
        js = build_dashboard_js(auth_required=True)

        self.assertIn("Ares Dashboard", html)
        self.assertIn("Browser operator surface backed by the Ares gateway API/control plane.", html)
        self.assertIn('data-auth-required="true"', html)
        self.assertIn("/api/runs", js)
        self.assertIn("/api/events", js)
        self.assertIn(".panel", css)

    def test_dashboard_url_uses_loopback_for_wildcard_binds(self):
        from ares.dashboard import dashboard_url

        self.assertEqual(dashboard_url("0.0.0.0", 8765), "http://127.0.0.1:8765/")
        self.assertEqual(dashboard_url("::", 8765), "http://127.0.0.1:8765/")
        self.assertEqual(dashboard_url("127.0.0.1", 9000), "http://127.0.0.1:9000/")


if __name__ == "__main__":
    unittest.main()

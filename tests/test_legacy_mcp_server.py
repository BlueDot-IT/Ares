import sys
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))


class LegacyMCPServerTests(unittest.TestCase):
    def test_tool_inventory_includes_useful_schemas(self) -> None:
        from lib import mcp_server

        inventory = {tool["name"]: tool for tool in mcp_server._tool_inventory()}
        nmap_basic = inventory["nmap_basic"]["inputSchema"]
        http_probe = inventory["http_probe"]["inputSchema"]
        dns_lookup = inventory["dns_lookup"]["inputSchema"]

        self.assertIn("target", nmap_basic["properties"])
        self.assertIn("targets", nmap_basic["properties"])
        self.assertIn("ports", nmap_basic["properties"])
        self.assertIn("target", http_probe["properties"])
        self.assertIn("targets", http_probe["properties"])
        self.assertIn("url", http_probe["properties"])
        self.assertIn("domain", dns_lookup["properties"])
        self.assertIn("target", dns_lookup["properties"])

    def test_ping_sweep_accepts_targets_list(self) -> None:
        from lib import mcp_server

        with patch.object(mcp_server, "_run", return_value={"ok": True}) as mock_run:
            result = mcp_server.tool_ping_sweep({"targets": ["127.0.0.1", "localhost"]})

        self.assertEqual(result, {"ok": True})
        self.assertEqual(mock_run.call_args.args[0], ["nmap", "-sn", "127.0.0.1", "localhost"])

    def test_nmap_basic_accepts_targets_list_and_ports_string(self) -> None:
        from lib import mcp_server

        with patch.object(mcp_server, "_run", return_value={"ok": True}) as mock_run:
            result = mcp_server.tool_nmap_basic({"targets": ["127.0.0.1", "localhost"], "ports": "80,443"})

        self.assertEqual(result, {"ok": True})
        self.assertEqual(mock_run.call_args.args[0], ["nmap", "-sS", "-sV", "-Pn", "-p", "80,443", "127.0.0.1", "localhost"])

    def test_http_probe_accepts_single_target_alias(self) -> None:
        from lib import mcp_server

        with patch.object(mcp_server, "_run", return_value={"ok": True}) as mock_run:
            result = mcp_server.tool_http_probe({"target": "172.235.158.51"})

        self.assertEqual(result, {"ok": True})
        self.assertEqual(
            mock_run.call_args.args[0],
            ["httpx", "-silent", "-status-code", "-title", "http://172.235.158.51", "https://172.235.158.51"],
        )

    def test_dns_lookup_accepts_ip_alias_and_uses_reverse_dns(self) -> None:
        from lib import mcp_server

        with patch.object(mcp_server, "_run", return_value={"cmd": ["dig", "-x", "172.235.158.51", "+short"], "returncode": 0, "stdout": "mail.bluedot.it.com.\n", "stderr": ""}):
            result = mcp_server.tool_dns_lookup({"target": "172.235.158.51"})

        self.assertEqual(result["cmd"], ["dig", "-x", "172.235.158.51", "+short"])

    def test_subdomain_enum_falls_back_to_amass_and_parent_domain(self) -> None:
        from lib import mcp_server

        with patch.object(mcp_server, "_reverse_dns_name", return_value="mail.bluedot.it.com"):
            with patch.object(mcp_server.shutil, "which", side_effect=lambda name: "/usr/bin/amass" if name == "amass" else None):
                with patch.object(mcp_server, "_run", return_value={"ok": True}) as mock_run:
                    result = mcp_server.tool_subdomain_enum({"target": "172.235.158.51"})

        self.assertEqual(result, {"ok": True})
        self.assertEqual(mock_run.call_args.args[0], ["/usr/bin/amass", "enum", "-passive", "-d", "bluedot.it.com"])

    def test_banner_grab_defaults_port_to_443(self) -> None:
        from lib import mcp_server

        with patch.object(mcp_server, "_run", return_value={"ok": True}) as mock_run:
            result = mcp_server.tool_banner_grab({"target": "127.0.0.1"})

        self.assertEqual(result, {"ok": True})
        self.assertEqual(mock_run.call_args.args[0], ["nc", "-w", "3", "127.0.0.1", "443"])


if __name__ == "__main__":
    unittest.main()

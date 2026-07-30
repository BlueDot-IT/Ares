from __future__ import annotations

import ipaddress
import json
import re
from typing import Any
from urllib.parse import urlparse

from ares.autonomy.graph import AttackSurfaceGraph, NodeKind
from ares.state.db import StateDB


class AttackSurfaceProjector:
    """Project normalized and raw tool evidence into the mission graph."""

    def __init__(
        self,
        state_db: StateDB,
        mission_id: str,
        session_id: int,
        graph: AttackSurfaceGraph,
    ) -> None:
        self.state_db = state_db
        self.mission_id = mission_id
        self.session_id = session_id
        self.graph = graph

    def project_tool_call(self, tool_call_id: int) -> None:
        with self.state_db._connection() as conn:
            row = conn.execute(
                """
                SELECT * FROM tool_calls
                WHERE id = ? AND session_id = ?
                """,
                (tool_call_id, self.session_id),
            ).fetchone()
        if row is None or row["status"] != "ok":
            return
        args = self._decode(row["args_json"], {})
        result = self._decode(row["result_json"], {})
        tool = str(row["tool"])
        evidence_ids = [int(tool_call_id)]

        if "nmap" in tool.lower():
            self._project_session_inventory(evidence_ids)
            self._project_nmap_hostname(result, evidence_ids)
        elif tool == "reverse_dns":
            self._project_reverse_dns(result, evidence_ids)
        elif tool in {"http_probe", "whatweb", "web_surface_assessment"}:
            self._project_web(args, result, evidence_ids)
        elif tool in {"sslscan", "sslyze", "tls_posture_assessment"}:
            self._project_tls(args, evidence_ids)

    def _project_session_inventory(self, evidence_ids: list[int]) -> None:
        host_nodes: dict[str, str] = {}
        for host in self.state_db.list_hosts(self.session_id):
            address = str(host["address"])
            host_nodes[address] = self.graph.upsert_node(
                kind=NodeKind.HOST,
                key=address,
                label=host.get("hostname") or address,
                attributes={
                    "address": address,
                    "hostname": host.get("hostname"),
                },
                evidence_tool_call_ids=evidence_ids,
            )

        for service in self.state_db.list_services(self.session_id):
            address = str(service["host_address"])
            host_node_id = host_nodes.get(address) or self.graph.upsert_node(
                kind=NodeKind.HOST,
                key=address,
                attributes={"address": address},
                evidence_tool_call_ids=evidence_ids,
            )
            port = int(service["port"])
            proto = str(service["proto"])
            service_key = f"{address}:{port}/{proto}"
            service_node_id = self.graph.upsert_node(
                kind=NodeKind.SERVICE,
                key=service_key,
                label=service_key,
                attributes={
                    "host_address": address,
                    "port": port,
                    "proto": proto,
                    "service": service.get("service"),
                    "product": service.get("product"),
                },
                evidence_tool_call_ids=evidence_ids,
            )
            self.graph.connect(
                host_node_id,
                service_node_id,
                "exposes",
                evidence_tool_call_ids=evidence_ids,
            )
            product = str(service.get("product") or "").strip()
            if product:
                technology_id = self.graph.upsert_node(
                    kind=NodeKind.TECHNOLOGY,
                    key=product,
                    label=product,
                    attributes={"observed_from": "service_fingerprint"},
                    evidence_tool_call_ids=evidence_ids,
                )
                self.graph.connect(
                    service_node_id,
                    technology_id,
                    "runs",
                    evidence_tool_call_ids=evidence_ids,
                )

    def _project_nmap_hostname(
        self,
        result: dict[str, Any],
        evidence_ids: list[int],
    ) -> None:
        stdout = str(result.get("stdout") or "")
        match = re.search(
            r"^Nmap scan report for\s+(?P<name>\S+)\s+\((?P<ip>[^)]+)\)",
            stdout,
            re.MULTILINE,
        )
        if not match:
            return
        self._link_domain_to_host(
            hostname=match.group("name"),
            address=match.group("ip"),
            evidence_ids=evidence_ids,
        )

    def _project_reverse_dns(
        self,
        result: dict[str, Any],
        evidence_ids: list[int],
    ) -> None:
        hostname = str(result.get("hostname") or "").strip().rstrip(".")
        address = str(result.get("ip") or "").strip()
        if hostname and address:
            self._link_domain_to_host(
                hostname=hostname,
                address=address,
                evidence_ids=evidence_ids,
            )

    def _link_domain_to_host(
        self,
        *,
        hostname: str,
        address: str,
        evidence_ids: list[int],
    ) -> None:
        host_id = self.graph.upsert_node(
            kind=NodeKind.HOST,
            key=address,
            label=hostname,
            attributes={"address": address, "hostname": hostname},
            evidence_tool_call_ids=evidence_ids,
        )
        domain_id = self.graph.upsert_node(
            kind=NodeKind.DOMAIN,
            key=hostname,
            label=hostname,
            attributes={"hostname": hostname},
            evidence_tool_call_ids=evidence_ids,
        )
        self.graph.connect(
            domain_id,
            host_id,
            "resolves_to",
            evidence_tool_call_ids=evidence_ids,
        )

    def _project_web(
        self,
        args: dict[str, Any],
        result: dict[str, Any],
        evidence_ids: list[int],
    ) -> None:
        url = str(
            args.get("url")
            or result.get("url")
            or args.get("target")
            or ""
        ).strip()
        parsed = urlparse(url)
        if not parsed.hostname:
            return
        scheme = parsed.scheme or "http"
        port = parsed.port or (443 if scheme == "https" else 80)
        address = parsed.hostname
        host_id = self.graph.upsert_node(
            kind=NodeKind.HOST,
            key=address,
            attributes={"address": address},
            evidence_tool_call_ids=evidence_ids,
        )
        service_key = f"{address}:{port}/tcp"
        service_id = self.graph.upsert_node(
            kind=NodeKind.SERVICE,
            key=service_key,
            attributes={
                "host_address": address,
                "port": port,
                "proto": "tcp",
                "service": f"{'ssl/' if scheme == 'https' else ''}http",
            },
            evidence_tool_call_ids=evidence_ids,
        )
        endpoint_id = self.graph.upsert_node(
            kind=NodeKind.ENDPOINT,
            key=url,
            label=url,
            attributes={
                "url": url,
                "status": result.get("status"),
                "server": result.get("server"),
                "content_type": result.get("content_type"),
            },
            evidence_tool_call_ids=evidence_ids,
        )
        self.graph.connect(
            host_id,
            service_id,
            "exposes",
            evidence_tool_call_ids=evidence_ids,
        )
        self.graph.connect(
            service_id,
            endpoint_id,
            "serves",
            evidence_tool_call_ids=evidence_ids,
        )
        server = str(result.get("server") or "").strip()
        if server:
            technology_id = self.graph.upsert_node(
                kind=NodeKind.TECHNOLOGY,
                key=server,
                label=server,
                attributes={"observed_from": "http_server_header"},
                evidence_tool_call_ids=evidence_ids,
            )
            self.graph.connect(
                endpoint_id,
                technology_id,
                "uses",
                evidence_tool_call_ids=evidence_ids,
            )

    def _project_tls(
        self,
        args: dict[str, Any],
        evidence_ids: list[int],
    ) -> None:
        host, port_value = self._tls_target(args)
        if not host:
            return
        try:
            port = int(port_value or 443)
        except (TypeError, ValueError):
            return
        host_id = self.graph.upsert_node(
            kind=NodeKind.HOST,
            key=host,
            attributes={"address": host},
            evidence_tool_call_ids=evidence_ids,
        )
        service_id = self.graph.upsert_node(
            kind=NodeKind.SERVICE,
            key=f"{host}:{port}/tcp",
            attributes={
                "host_address": host,
                "port": port,
                "proto": "tcp",
                "tls_assessed": True,
            },
            evidence_tool_call_ids=evidence_ids,
        )
        self.graph.connect(
            host_id,
            service_id,
            "exposes",
            evidence_tool_call_ids=evidence_ids,
        )

    @staticmethod
    def _tls_target(args: dict[str, Any]) -> tuple[str, Any]:
        explicit_host = str(args.get("host") or "").strip()
        if explicit_host:
            return explicit_host.removeprefix("[").removesuffix("]"), args.get(
                "port"
            )

        target = str(args.get("target") or "").strip()
        if not target:
            return "", args.get("port")
        try:
            ipaddress.ip_address(target)
        except ValueError:
            pass
        else:
            return target, args.get("port")

        if target.startswith("["):
            parsed = urlparse(f"//{target}")
            return parsed.hostname or "", args.get("port") or parsed.port

        host, separator, candidate_port = target.rpartition(":")
        if separator and host and candidate_port.isdigit():
            return host, args.get("port") or int(candidate_port)
        return target, args.get("port")

    @staticmethod
    def _decode(raw: str | None, default: dict[str, Any]) -> dict[str, Any]:
        if not raw:
            return dict(default)
        try:
            value = json.loads(raw)
        except (TypeError, json.JSONDecodeError):
            return dict(default)
        return value if isinstance(value, dict) else dict(default)

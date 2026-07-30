from __future__ import annotations

import json
import re
from dataclasses import dataclass
from typing import Any, Callable

from ares.mission.tasks import MissionTask
from ares.state.db import StateDB


@dataclass(frozen=True)
class RecoveryDecision:
    strategy: str
    reason: str
    task: MissionTask | None


class ReconRecoveryPolicy:
    """Trusted, deterministic, one-attempt recovery for recon capabilities."""

    def __init__(
        self,
        *,
        state_db: StateDB,
        mission_id: str,
        target_allowed: Callable[[str], bool],
    ) -> None:
        self.state_db = state_db
        self.mission_id = mission_id
        self.target_allowed = target_allowed

    def decide(
        self,
        *,
        original_task: MissionTask,
        coverage_item: dict[str, Any],
        original_tool_call_id: int | None,
    ) -> RecoveryDecision:
        # The UNIQUE(mission_id, coverage_id) persistence constraint is the
        # final concurrency guard. This check makes the normal path clearer.
        existing = {
            row["coverage_id"]
            for row in self.state_db.list_recovery_attempts(self.mission_id)
        }
        coverage_id = str(coverage_item["id"])
        if coverage_id in existing:
            return RecoveryDecision(
                "none", "bounded recovery already attempted", None
            )

        persisted = self._persisted_tool_call(original_tool_call_id)
        error = str((persisted or {}).get("error") or "")
        result = self._decode((persisted or {}).get("result_json"))
        capability = str(coverage_item["capability"])
        subject = coverage_item.get("subject") or {}
        attributes = subject.get("attributes") or {}
        host = str(attributes.get("host_address") or original_task.target)
        port = int(attributes.get("port") or 0)

        # An HTTP 404 is evidence, not a failed probe. Preserve the persisted
        # response and close coverage without retrying.
        status = result.get("status")
        if capability == "web.probe" and (
            status == 404
            or re.search(r"\bHTTP(?:\s+Error)?\s+404\b", error, re.I)
        ):
            return RecoveryDecision(
                "preserve_http_response",
                "HTTP 404 is a valid observed response; preserved as evidence",
                None,
            )

        if capability == "web.probe" and port:
            return self._task(
                original_task,
                strategy="http_banner_fallback",
                reason=f"http_probe failed ({error or 'unknown error'}); "
                "try one bounded banner read",
                tool_name="banner_grab",
                args={"target": host, "port": port},
            )

        if capability == "tls.assessment" and port:
            sni_host = self._allowed_sni_hostname(host)
            fallback_host = sni_host or host
            strategy = (
                "tls_sni_fallback" if sni_host else "tls_certificate_fallback"
            )
            return self._task(
                original_task,
                strategy=strategy,
                reason=f"sslscan failed ({error or 'unknown error'}); "
                "try one certificate retrieval"
                + (f" with authorized SNI {sni_host}" if sni_host else ""),
                tool_name="tls_certificate",
                args={"host": fallback_host, "port": port},
                target=fallback_host,
            )

        if capability == "service.fingerprint" and port:
            return self._task(
                original_task,
                strategy="service_detection_fallback",
                reason=f"banner read failed ({error or 'unknown error'}); "
                "try one bounded service-detection scan",
                tool_name="nmap_basic",
                args={"target": host, "ports": str(port)},
            )

        return RecoveryDecision(
            "none",
            "no trusted equivalent capability is defined",
            None,
        )

    def _allowed_sni_hostname(self, address: str) -> str | None:
        for edge in self.state_db.list_attack_surface_edges(self.mission_id):
            if edge["relationship"] != "resolves_to":
                continue
            nodes = {
                node["id"]: node
                for node in self.state_db.list_attack_surface_nodes(
                    self.mission_id
                )
            }
            source = nodes.get(edge["source_node_id"])
            target = nodes.get(edge["target_node_id"])
            if (
                source
                and target
                and source["kind"] == "domain"
                and target["node_key"] == address
                and self.target_allowed(str(source["node_key"]))
            ):
                return str(source["node_key"])
        return None

    def _persisted_tool_call(
        self, tool_call_id: int | None
    ) -> dict[str, Any] | None:
        if tool_call_id is None:
            return None
        with self.state_db._connection() as conn:
            row = conn.execute(
                "SELECT * FROM tool_calls WHERE id = ?",
                (int(tool_call_id),),
            ).fetchone()
        return dict(row) if row is not None else None

    @staticmethod
    def _decode(raw: str | None) -> dict[str, Any]:
        try:
            value = json.loads(raw or "{}")
        except json.JSONDecodeError:
            return {}
        return value if isinstance(value, dict) else {}

    @staticmethod
    def _task(
        original: MissionTask,
        *,
        strategy: str,
        reason: str,
        tool_name: str,
        args: dict[str, Any],
        target: str | None = None,
    ) -> RecoveryDecision:
        return RecoveryDecision(
            strategy,
            reason,
            MissionTask(
                id=f"{original.id}-recovery",
                mission_id=original.mission_id,
                role_id="recon",
                phase="recon",
                tool_name=tool_name,
                toolset="ghostmcp",
                target=target or original.target,
                description=f"Trusted bounded recovery: {reason}",
                args=args,
            ),
        )

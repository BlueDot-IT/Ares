from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from ares.mission.tasks import MissionTask


@dataclass(frozen=True)
class CapabilityAction:
    capability: str
    tool_name: str
    description: str
    target: str
    args: dict[str, Any]


class ReconCapabilityCatalog:
    """Compile trusted coverage capabilities into fixed, scoped tool calls."""

    SUPPORTED = {
        "host.identity",
        "service.fingerprint",
        "web.probe",
        "web.fingerprint",
        "tls.assessment",
    }

    def compile(
        self,
        *,
        mission_id: str,
        cycle: int,
        coverage_item: dict[str, Any],
    ) -> MissionTask:
        capability = str(coverage_item["capability"])
        if (
            capability not in self.SUPPORTED
            and not capability.startswith("network.port_scan:")
        ):
            raise ValueError(f"unsupported autonomous capability: {capability}")
        subject = coverage_item.get("subject")
        if not isinstance(subject, dict):
            raise ValueError("coverage item has no attack-surface subject")

        action = self._action_for(capability, subject)
        short_coverage_id = str(coverage_item["id"]).removeprefix("cov_")[:12]
        return MissionTask(
            id=f"{mission_id}-auto-{cycle:03d}-{short_coverage_id}",
            mission_id=mission_id,
            role_id="recon",
            phase="recon",
            tool_name=action.tool_name,
            toolset="ghostmcp",
            target=action.target,
            description=action.description,
            args=action.args,
        )

    def _action_for(
        self,
        capability: str,
        subject: dict[str, Any],
    ) -> CapabilityAction:
        kind = str(subject.get("kind") or "")
        attributes = subject.get("attributes") or {}
        key = str(subject.get("node_key") or "")

        if capability == "host.identity":
            self._require_kind(kind, "host", capability)
            return CapabilityAction(
                capability=capability,
                tool_name="reverse_dns",
                description=f"Resolve the authorized host identity for {key}.",
                target=key,
                args={"ip": key},
            )

        if capability.startswith("network.port_scan:"):
            self._require_kind(kind, "host", capability)
            ports = capability.split(":", 1)[1]
            return CapabilityAction(
                capability=capability,
                tool_name="nmap_basic",
                description=(
                    f"Inventory TCP ports {ports} on authorized host {key}."
                ),
                target=key,
                args={"target": key, "ports": ports},
            )

        host = str(attributes.get("host_address") or "").strip()
        port = int(attributes.get("port") or 0)
        if not host or not port:
            raise ValueError(
                f"service subject for {capability} lacks host_address or port"
            )
        self._require_kind(kind, "service", capability)

        if capability == "service.fingerprint":
            return CapabilityAction(
                capability=capability,
                tool_name="banner_grab",
                description=f"Collect a bounded service banner from {host}:{port}.",
                target=host,
                args={"target": host, "port": port},
            )

        if capability in {"web.probe", "web.fingerprint"}:
            url = self._service_url(host, port, attributes)
            tool_name = (
                "http_probe"
                if capability == "web.probe"
                else "whatweb"
            )
            description = (
                f"Probe HTTP behavior at {url}."
                if capability == "web.probe"
                else f"Fingerprint the web surface at {url}."
            )
            return CapabilityAction(
                capability=capability,
                tool_name=tool_name,
                description=description,
                target=host,
                args={"url": url},
            )

        if capability == "tls.assessment":
            return CapabilityAction(
                capability=capability,
                tool_name="sslscan",
                description=f"Assess TLS posture at {host}:{port}.",
                target=host,
                args={"host": host, "port": port},
            )

        raise ValueError(f"unsupported autonomous capability: {capability}")

    @staticmethod
    def _require_kind(kind: str, expected: str, capability: str) -> None:
        if kind != expected:
            raise ValueError(
                f"capability {capability} requires {expected} subject, got {kind}"
            )

    @staticmethod
    def _service_url(
        host: str,
        port: int,
        attributes: dict[str, Any],
    ) -> str:
        service = str(attributes.get("service") or "").lower()
        scheme = (
            "https"
            if "ssl" in service
            or "tls" in service
            or port in {443, 8443}
            else "http"
        )
        rendered_host = f"[{host}]" if ":" in host and not host.startswith("[") else host
        default_port = 443 if scheme == "https" else 80
        suffix = "" if port == default_port else f":{port}"
        return f"{scheme}://{rendered_host}{suffix}/"

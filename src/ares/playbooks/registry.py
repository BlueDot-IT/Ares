from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class Playbook:
    name: str
    triggers: tuple[str, ...]
    content: str


class PlaybookRegistry:
    def __init__(self, playbooks: list[Playbook]) -> None:
        self.playbooks = playbooks

    @classmethod
    def builtin(cls) -> "PlaybookRegistry":
        return cls(
            [
                Playbook(
                    name="external-perimeter-enum",
                    triggers=("default", "domain", "ip"),
                    content=(
                        "1. Confirm scope and route policy.\n"
                        "2. Start with passive DNS/WHOIS/TLS where applicable.\n"
                        "3. Move to safe active service enumeration only within risk ceiling.\n"
                        "4. Store evidence and keep enumerating until coverage is exhausted."
                    ),
                ),
                Playbook(
                    name="web-application-enum",
                    triggers=("http", "https", "url", "web"),
                    content=(
                        "1. Probe HTTP service status, title, headers, and redirects.\n"
                        "2. Inspect TLS certificate and security.txt when available.\n"
                        "3. Fingerprint technologies with safe active tools.\n"
                        "4. Use light content discovery only when intrusive actions are allowed.\n"
                        "5. Summarize findings with evidence references."
                    ),
                ),
            ]
        )

    def select_for_context(
        self,
        *,
        target: str | None = None,
        services: list[dict[str, Any]] | None = None,
    ) -> list[Playbook]:
        haystack = " ".join(
            [target or ""]
            + [str(service.get("service", "")) for service in (services or [])]
        ).lower()
        selected = [
            playbook
            for playbook in self.playbooks
            if any(trigger != "default" and trigger in haystack for trigger in playbook.triggers)
        ]
        if selected:
            return selected
        return [playbook for playbook in self.playbooks if "default" in playbook.triggers]

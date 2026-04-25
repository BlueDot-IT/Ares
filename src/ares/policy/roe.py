from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True)
class ROEProfile:
    name: str
    max_risk: str
    allowed_toolsets: tuple[str, ...] = field(default_factory=tuple)
    approval_required_risks: tuple[str, ...] = ("exploit", "post-exploitation")
    description: str = ""


class ROEProfileRegistry:
    def __init__(self, profiles: dict[str, ROEProfile]) -> None:
        self._profiles = dict(profiles)

    @classmethod
    def builtin(cls) -> "ROEProfileRegistry":
        profiles = {
            "passive": ROEProfile(
                name="passive",
                max_risk="passive",
                allowed_toolsets=("recon", "web", "dns", "unit"),
                approval_required_risks=("active", "intrusive", "exploit", "post-exploitation"),
                description="Passive reconnaissance only; no packets intended to probe services aggressively.",
            ),
            "safe-active": ROEProfile(
                name="safe-active",
                max_risk="active",
                allowed_toolsets=("recon", "web", "network", "unit"),
                approval_required_risks=("intrusive", "exploit", "post-exploitation"),
                description="Safe active enumeration and validation without exploit attempts.",
            ),
            "intrusive": ROEProfile(
                name="intrusive",
                max_risk="intrusive",
                allowed_toolsets=("recon", "web", "network", "vuln", "unit"),
                approval_required_risks=("exploit", "post-exploitation"),
                description="Authorized intrusive checks; exploit and post-exploitation still require approval.",
            ),
            "exploit-validate": ROEProfile(
                name="exploit-validate",
                max_risk="exploit",
                allowed_toolsets=("recon", "web", "network", "vuln", "exploit", "unit"),
                approval_required_risks=("exploit", "post-exploitation"),
                description="Exploit validation allowed only through explicit approval gates.",
            ),
        }
        return cls(profiles)

    def get(self, name: str) -> ROEProfile:
        try:
            return self._profiles[name]
        except KeyError as exc:
            known = ", ".join(sorted(self._profiles))
            raise KeyError(f"unknown ROE profile: {name}. Known profiles: {known}") from exc

    def names(self) -> list[str]:
        return sorted(self._profiles)

from __future__ import annotations

from dataclasses import dataclass

from ares.mission.model import MissionPhase


@dataclass(frozen=True)
class MissionProfile:
    id: str
    name: str
    phases: tuple[MissionPhase, ...]
    enabled_toolsets: tuple[str, ...]
    max_risk: str
    description: str


PROFILES: dict[str, MissionProfile] = {
    "source-code-audit": MissionProfile(
        id="source-code-audit",
        name="Source Code Audit",
        phases=(MissionPhase.PLAN, MissionPhase.SCAN, MissionPhase.VALIDATE, MissionPhase.REPORT),
        enabled_toolsets=("redteam_static", "redteam_secrets", "redteam_deps"),
        max_risk="scan",
        description="White-box review of local source files.",
    ),
    "secrets-audit": MissionProfile(
        id="secrets-audit",
        name="Secrets Audit",
        phases=(MissionPhase.PLAN, MissionPhase.SCAN, MissionPhase.VALIDATE, MissionPhase.REPORT),
        enabled_toolsets=("redteam_secrets",),
        max_risk="scan",
        description="Local secret-pattern review with redaction.",
    ),
    "dependency-audit": MissionProfile(
        id="dependency-audit",
        name="Dependency Audit",
        phases=(MissionPhase.PLAN, MissionPhase.SCAN, MissionPhase.ANALYZE, MissionPhase.REPORT),
        enabled_toolsets=("redteam_deps",),
        max_risk="scan",
        description="Local dependency manifest review.",
    ),
    "report-only": MissionProfile(
        id="report-only",
        name="Report Only",
        phases=(MissionPhase.REPORT,),
        enabled_toolsets=("redteam_report",),
        max_risk="safe",
        description="Generate a report from existing mission state.",
    ),
    "authorized-operator-validation": MissionProfile(
        id="authorized-operator-validation",
        name="Authorized Operator Validation",
        phases=(
            MissionPhase.PLAN,
            MissionPhase.RECON,
            MissionPhase.SCAN,
            MissionPhase.WEAPONIZE,
            MissionPhase.DELIVER,
            MissionPhase.EXPLOIT,
            MissionPhase.VALIDATE,
            MissionPhase.POST_EXPLOITATION,
            MissionPhase.PERSISTENCE,
            MissionPhase.ACTIONS,
            MissionPhase.ANALYZE,
            MissionPhase.REPORT,
        ),
        enabled_toolsets=("ghostmcp",),
        max_risk="post-exploitation",
        description=(
            "Explicitly authorized validation tasks using imported T3MP3ST "
            "operator roles, Ares scope controls, and out-of-model approvals."
        ),
    ),
}


def get_profile(profile_id: str) -> MissionProfile:
    try:
        return PROFILES[profile_id]
    except KeyError as exc:
        raise ValueError(f"unknown mission profile: {profile_id}") from exc

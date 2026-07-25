from __future__ import annotations

from ares.agent.context_budget import ContextBudgeter
from ares.mission.model import MissionRun
from ares.mission.profiles import get_profile
from ares.mission.operators import get_operator


def build_mission_context_pack(
    mission: MissionRun,
    *,
    role_id: str,
    tasks: list[dict] | None = None,
    findings: list[dict] | None = None,
    memory_chunks: list[dict] | None = None,
    max_tokens: int = 4000,
) -> str:
    budgeter = ContextBudgeter(max_tokens)
    
    try:
        profile = get_profile(mission.profile_id)
        profile_desc = profile.description
    except Exception:
        profile_desc = "Unknown Profile"

    tasks_list = tasks or []
    findings_list = findings or []
    memory_list = memory_chunks or []

    if role_id == "coordinator":
        budgeter.add_section("Mission ID", mission.id)
        budgeter.add_section("Profile", f"{mission.profile_id}: {profile_desc}")
        budgeter.add_section("Phase", str(mission.phase))
        budgeter.add_section("Scope", f"Target: {mission.scope.target}\nAllowed: {mission.scope.allowed_paths}")
        
        open_tasks = [t for t in tasks_list if t.get("status") in ("pending", "approved", "running")]
        open_text = "\n".join(f"- {t['id']}: {t['description']} ({t['status']})" for t in open_tasks)
        budgeter.add_section("Open Tasks", open_text or "None")

        blocked_tasks = [t for t in tasks_list if t.get("status") == "blocked"]
        blocked_text = "\n".join(f"- {t['id']}: {t['description']} (Reason: {t.get('block_reason', '')})" for t in blocked_tasks)
        budgeter.add_section("Blocked Tasks", blocked_text or "None")

    elif role_id == "recon":
        budgeter.add_section("Target Scope", f"Target: {mission.scope.target}")
        budgeter.add_section("Allowed Paths", ", ".join(mission.scope.allowed_paths) or "All")
        
        recon_tasks = [t for t in tasks_list if t.get("role_id") == "recon"]
        recon_text = "\n".join(f"- {t['id']}: {t['description']} ({t['status']})" for t in recon_tasks)
        budgeter.add_section("Current Recon Tasks", recon_text or "None")

        memory_text = "\n".join(f"- Chunk {m.get('id')}: {m.get('content')}" for m in memory_list)
        budgeter.add_section("Prior Memory", memory_text or "None")

    elif role_id == "scanner":
        budgeter.add_section("Target Scope", f"Target: {mission.scope.target}")
        budgeter.add_section("Allowed Paths", ", ".join(mission.scope.allowed_paths) or "All")
        
        scan_tasks = [t for t in tasks_list if t.get("role_id") == "scanner"]
        scan_text = "\n".join(f"- {t['id']}: {t['description']} ({t['status']})" for t in scan_tasks)
        budgeter.add_section("Current Scanning Tasks", scan_text or "None")

        memory_text = "\n".join(f"- Chunk {m.get('id')}: {m.get('content')}" for m in memory_list)
        budgeter.add_section("Prior Memory", memory_text or "None")

    elif role_id == "validator":
        candidate = [f for f in findings_list if f.get("state") in ("hypothesis", "observed")]
        cand_text = "\n".join(f"- {f['id']}: {f['title']} ({f['severity']})" for f in candidate)
        budgeter.add_section("Candidate Findings", cand_text or "None")

        evidence_text = "\n".join(f"- Finding {f['id']} evidence chunk IDs: {f.get('evidence_chunk_ids', [])}" for f in findings_list)
        budgeter.add_section("Evidence Chunks", evidence_text or "None")

        checklist = (
            "- Verify finding is not a false positive\n"
            "- Check evidence details\n"
            "- Confirm confidence is >= 0.7\n"
            "- Write validator note"
        )
        budgeter.add_section("Missing Proof Checklist", checklist)

    elif role_id in {"exploiter", "infiltrator", "exfiltrator", "ghost"}:
        operator = get_operator(role_id)
        role_tasks = [t for t in tasks_list if t.get("role_id") == role_id]
        role_text = "\n".join(
            f"- {t['id']}: {t['description']} ({t['status']})" for t in role_tasks
        )
        evidence_text = "\n".join(
            f"- {f['id']}: {f['title']} ({f.get('state', 'unknown')})"
            for f in findings_list
        )
        budgeter.add_section("Operator", f"{operator.name}: {operator.purpose}")
        budgeter.add_section("Target Scope", f"Target: {mission.scope.target}")
        budgeter.add_section("Allowed Paths", ", ".join(mission.scope.allowed_paths) or "None")
        budgeter.add_section("Mission Risk Ceiling", mission.scope.max_risk)
        budgeter.add_section("Current Tasks", role_text or "None")
        budgeter.add_section("Evidence Ledger", evidence_text or "None")
        budgeter.add_section(
            "Hard Boundaries",
            (
                "- Use only explicitly allowlisted tools and targets\n"
                "- Use the minimum proof needed; do not damage or disrupt\n"
                "- Do not collect secrets or bulk data\n"
                "- Do not install persistence or conceal activity\n"
                "- Stop when authorization, scope, or evidence is insufficient"
            ),
        )

    elif role_id == "analyst":
        validated = [f for f in findings_list if f.get("state") == "validated"]
        val_text = "\n".join(f"- {f['id']}: {f['title']} ({f['severity']})" for f in validated)
        budgeter.add_section("Validated Findings", val_text or "None")

        refuted = [f for f in findings_list if f.get("state") == "refuted"]
        ref_text = "\n".join(f"- {f['id']}: {f['title']} ({f['validator_note']})" for f in refuted)
        budgeter.add_section("Refuted Findings", ref_text or "None")

        limitation = "Analysis only covers scoped targets. Excludes dynamic, local, or configuration exceptions."
        budgeter.add_section("Limitation Statement", limitation)
        budgeter.add_section("Target Scope", f"Target: {mission.scope.target}")

    else:
        budgeter.add_section("Mission ID", mission.id)

    return budgeter.render()

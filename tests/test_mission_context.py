from __future__ import annotations

from ares.mission.context import build_mission_context_pack
from ares.mission.model import MissionRun, MissionScope, MissionStatus, MissionPhase


def test_role_contexts():
    scope = MissionScope(target="src", allowed_paths=["src"])
    mission = MissionRun(
        id="m1",
        profile_id="source-code-audit",
        scope=scope,
        status=MissionStatus.RUNNING,
        phase=MissionPhase.SCAN,
    )

    tasks = [
        {"id": "t1", "role_id": "scanner", "phase": "scan", "description": "Scan secrets", "status": "pending"},
        {"id": "t2", "role_id": "analyst", "phase": "report", "description": "Report", "status": "blocked", "block_reason": "waiting"},
    ]
    findings = [
        {"id": "f1", "title": "Leak", "severity": "medium", "state": "hypothesis", "evidence_chunk_ids": [1]},
        {"id": "f2", "title": "Invalid", "severity": "low", "state": "refuted", "validator_note": "not true"},
    ]
    memory = [{"id": 1, "content": "api_key = 123", "tags": ["secrets"]}]

    # 1. Coordinator context
    ctx_coord = build_mission_context_pack(mission, role_id="coordinator", tasks=tasks)
    assert "Open Tasks" in ctx_coord
    assert "Blocked Tasks" in ctx_coord
    assert "Scan secrets" in ctx_coord

    # 2. Scanner context
    ctx_scan = build_mission_context_pack(mission, role_id="scanner", tasks=tasks, memory_chunks=memory)
    assert "Current Scanning Tasks" in ctx_scan
    assert "Prior Memory" in ctx_scan
    assert "api_key = 123" in ctx_scan

    # 3. Validator context includes missing proof
    ctx_val = build_mission_context_pack(mission, role_id="validator", findings=findings)
    assert "Candidate Findings" in ctx_val
    assert "Missing Proof Checklist" in ctx_val

    # 4. Analyst context includes limitations
    ctx_an = build_mission_context_pack(mission, role_id="analyst", findings=findings)
    assert "Limitation Statement" in ctx_an
    assert "Refuted Findings" in ctx_an


def test_token_budget():
    scope = MissionScope(target="src")
    mission = MissionRun(id="m1", profile_id="source-code-audit", scope=scope)
    
    # Very large content to trigger truncation
    large_memory = [{"id": 1, "content": "A" * 8000, "tags": []}]
    
    ctx = build_mission_context_pack(mission, role_id="scanner", memory_chunks=large_memory, max_tokens=1000)
    # Estimate of tokens should be within budget, so it should be truncated
    # 1000 tokens * 4 = 4000 characters limit. So a length > 4000 should be truncated.
    assert len(ctx) <= 4050
    assert "truncated" in ctx


def test_imported_operator_context_keeps_authorization_boundaries_visible():
    scope = MissionScope(
        target="lab.local",
        allowed_paths=["/srv/lab"],
        max_risk="post-exploitation",
    )
    mission = MissionRun(
        id="m_advanced",
        profile_id="authorized-operator-validation",
        scope=scope,
        phase=MissionPhase.POST_EXPLOITATION,
    )
    tasks = [{
        "id": "t_lateral",
        "role_id": "infiltrator",
        "description": "Validate one approved lateral-access path.",
        "status": "pending",
    }]
    context = build_mission_context_pack(
        mission,
        role_id="infiltrator",
        tasks=tasks,
    )
    assert "Lateral-Movement Validator" in context
    assert "post-exploitation" in context
    assert "Do not collect secrets or bulk data" in context
    assert "Do not install persistence or conceal activity" in context

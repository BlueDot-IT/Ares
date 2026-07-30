from __future__ import annotations

from ares.mission.model import MissionRun


def render_mission_report(
    *,
    mission: MissionRun,
    tasks: list[dict],
    findings: list[dict],
    evidence_chunks: list[dict],
    attack_surface_nodes: list[dict] | None = None,
    attack_surface_edges: list[dict] | None = None,
    coverage_items: list[dict] | None = None,
    planner_cycles: list[dict] | None = None,
    recovery_attempts: list[dict] | None = None,
) -> str:
    attack_surface_nodes = attack_surface_nodes or []
    attack_surface_edges = attack_surface_edges or []
    coverage_items = coverage_items or []
    planner_cycles = planner_cycles or []
    recovery_attempts = recovery_attempts or []
    lines = []
    lines.append("# ARES Mission Report")
    lines.append("")

    lines.append("## Recovery Provenance")
    if not recovery_attempts:
        lines.append("No bounded recovery attempts recorded.")
    else:
        for attempt in recovery_attempts:
            lines.append(
                f"- **{attempt.get('strategy')}** for "
                f"`{attempt.get('coverage_id')}`: {attempt.get('status')}"
            )
            lines.append(
                "  Evidence tool calls: "
                f"{attempt.get('original_tool_call_id') or '-'} → "
                f"{attempt.get('recovery_tool_call_id') or '-'}"
            )
            if attempt.get("reason"):
                lines.append(f"  Reason: {attempt.get('reason')}")
    lines.append("")

    # Attack surface
    lines.append("## Attack Surface")
    if not attack_surface_nodes:
        lines.append("No structured attack-surface nodes recorded.")
    else:
        nodes_by_kind: dict[str, list[dict]] = {}
        for node in attack_surface_nodes:
            nodes_by_kind.setdefault(str(node.get("kind")), []).append(node)
        for kind, nodes in sorted(nodes_by_kind.items()):
            lines.append(f"### {kind.title()} Nodes")
            for node in nodes:
                attributes = node.get("attributes") or {}
                evidence_ids = node.get("evidence_tool_call_ids") or []
                lines.append(
                    f"- **{node.get('label')}** (`{node.get('id')}`)"
                )
                if attributes:
                    lines.append(
                        f"  Attributes: `{attributes}`"
                    )
                if evidence_ids:
                    lines.append(
                        "  Evidence tool calls: "
                        + ", ".join(str(value) for value in evidence_ids)
                    )
        if attack_surface_edges:
            lines.append("### Relationships")
            for edge in attack_surface_edges:
                lines.append(
                    f"- `{edge.get('source_node_id')}` "
                    f"—{edge.get('relationship')}→ "
                    f"`{edge.get('target_node_id')}`"
                )
    lines.append("")

    # Coverage ledger
    lines.append("## Coverage Ledger")
    if not coverage_items:
        lines.append("No coverage entries recorded.")
    else:
        for item in coverage_items:
            subject = item.get("subject") or {}
            lines.append(
                f"- **{item.get('capability')}** on "
                f"`{subject.get('label') or item.get('subject_node_id')}`: "
                f"{item.get('status')} "
                f"(attempts: {item.get('attempts')})"
            )
            if item.get("last_error"):
                lines.append(f"  Limitation: {item.get('last_error')}")
            if item.get("evidence_tool_call_ids"):
                lines.append(
                    "  Evidence tool calls: "
                    + ", ".join(
                        str(value)
                        for value in item["evidence_tool_call_ids"]
                    )
                )
    lines.append("")

    # Planner provenance
    lines.append("## Planner Provenance")
    if not planner_cycles:
        lines.append("No model planning cycles recorded.")
    else:
        for cycle in planner_cycles:
            decision = cycle.get("decision") or {}
            lines.append(
                f"- Cycle {cycle.get('cycle')}: "
                f"{decision.get('source')} selected "
                f"`{decision.get('coverage_id')}` — "
                f"{decision.get('reason')}"
            )
    lines.append("")
    
    # Summary
    lines.append("## Summary")
    completed_tasks = [t for t in tasks if t.get("status") == "completed"]
    failed_tasks = [t for t in tasks if t.get("status") == "failed"]
    blocked_tasks = [t for t in tasks if t.get("status") == "blocked"]
    confirmed_findings = [
        f for f in findings
        if f.get("state") in {"safely_validated", "reported"}
    ]
    reported_findings = [
        f for f in findings if f.get("state") == "reported"
    ]
    refuted_findings = [f for f in findings if f.get("state") == "refuted"]
    hypothesis_findings = [
        f for f in findings
        if f.get("state") in {"observed", "hypothesized", "corroborated"}
    ]
    
    lines.append(f"Mission ID: {mission.id}")
    lines.append(f"Profile: {mission.profile_id}")
    lines.append(f"Status: {mission.status.value if hasattr(mission.status, 'value') else str(mission.status)}")
    lines.append(f"Phase: {mission.phase.value if hasattr(mission.phase, 'value') else str(mission.phase)}")
    lines.append(f"Tasks: {len(completed_tasks)} completed, {len(failed_tasks)} failed, {len(blocked_tasks)} blocked.")
    lines.append(
        f"Findings: {len(confirmed_findings)} confirmed "
        f"({len(reported_findings)} reported), "
        f"{len(hypothesis_findings)} unresolved, "
        f"{len(refuted_findings)} refuted."
    )
    lines.append("")
    
    # Scope
    lines.append("## Scope")
    lines.append(f"Target: {mission.scope.target}")
    lines.append(f"Allowed Paths: {', '.join(mission.scope.allowed_paths) or 'None'}")
    lines.append(f"Forbidden Paths: {', '.join(mission.scope.forbidden_paths) or 'None'}")
    lines.append(f"Allowed Hosts: {', '.join(mission.scope.allowed_hosts) or 'None'}")
    lines.append(f"Forbidden Actions: {', '.join(mission.scope.forbidden_actions) or 'None'}")
    lines.append(f"Max Risk: {mission.scope.max_risk}")
    lines.append("")
    
    # Tasks
    lines.append("## Tasks")
    if not tasks:
        lines.append("No tasks recorded.")
    else:
        for t in tasks:
            lines.append(f"- **{t.get('id')}** ({t.get('role_id')} / {t.get('phase')}): {t.get('description')}")
            lines.append(f"  Status: {t.get('status')}")
            if t.get("supporting_evidence_tool_call_ids"):
                lines.append(
                    "  Supporting Evidence Tool Calls: "
                    + ", ".join(
                        str(value) for value in
                        t["supporting_evidence_tool_call_ids"]
                    )
                )
            if t.get("approval_receipt_id"):
                lines.append(
                    f"  Approval Receipt: {t['approval_receipt_id']}"
                )
            if t.get("block_reason"):
                lines.append(f"  Block Reason: {t.get('block_reason')}")
    lines.append("")
    
    # Safely validated findings
    lines.append("## Confirmed and Reported Findings")
    if not confirmed_findings:
        lines.append("No safely validated or reported findings.")
    else:
        for f in confirmed_findings:
            lines.append(f"### {f.get('title')} ({f.get('severity')})")
            lines.append(f"- **ID**: {f.get('id')}")
            lines.append(f"- **State**: {f.get('state')}")
            if f.get("affected_component"):
                lines.append(f"- **Affected Component**: {f.get('affected_component')}")
            lines.append(f"- **Confidence**: {f.get('confidence')}")
            lines.append(
                f"- **Confidence Rationale**: "
                f"{f.get('confidence_rationale') or '-'}"
            )
            lines.append(
                f"- **Severity Rationale**: "
                f"{f.get('severity_rationale') or '-'}"
            )
            lines.append(f"- **Validator Note**: {f.get('validator_note')}")
            lines.append(
                "- **Evidence Tool Calls**: "
                + ", ".join(
                    str(value)
                    for value in f.get("evidence_tool_call_ids") or []
                )
            )
            if f.get("contradictory_evidence_tool_call_ids"):
                lines.append(
                    "- **Contradictory Evidence**: "
                    + ", ".join(
                        str(value) for value in
                        f["contradictory_evidence_tool_call_ids"]
                    )
                )
                lines.append(
                    f"- **Contradiction Resolution**: "
                    f"{f.get('contradiction_resolution') or '-'}"
                )
            if f.get("recommendation"):
                lines.append(f"- **Recommendation**: {f.get('recommendation')}")
            if f.get("redacted"):
                lines.append(f"- **Evidence Preview**: `{f.get('redacted')}`")
    lines.append("")

    lines.append("## Unresolved Finding Hypotheses")
    if not hypothesis_findings:
        lines.append("No unresolved finding hypotheses.")
    else:
        for finding in hypothesis_findings:
            lines.append(
                f"### {finding.get('title')} ({finding.get('severity')})"
            )
            lines.append(f"- **State**: {finding.get('state')}")
            lines.append(
                f"- **Version-only**: "
                f"{'yes' if finding.get('version_only') else 'no'}"
            )
            lines.append(
                "- **Supporting Evidence**: "
                + (
                    ", ".join(
                        str(value) for value in
                        finding.get("evidence_tool_call_ids") or []
                    )
                    or "None"
                )
            )
            lines.append(
                "- **Contradictory Evidence**: "
                + (
                    ", ".join(
                        str(value) for value in
                        finding.get(
                            "contradictory_evidence_tool_call_ids"
                        ) or []
                    )
                    or "None"
                )
            )
            if finding.get("contradiction_resolution"):
                lines.append(
                    f"- **Contradiction Resolution**: "
                    f"{finding.get('contradiction_resolution')}"
                )
            lines.append(
                f"- **Confidence Rationale**: "
                f"{finding.get('confidence_rationale') or '-'}"
            )
            lines.append(
                f"- **Severity Rationale**: "
                f"{finding.get('severity_rationale') or '-'}"
            )
            if finding.get("redacted"):
                lines.append(
                    f"- **Evidence Preview**: `{finding.get('redacted')}`"
                )
    lines.append("")
    
    # Refuted Findings
    lines.append("## Refuted Findings")
    if not refuted_findings:
        lines.append("No refuted findings.")
    else:
        for f in refuted_findings:
            lines.append(f"### {f.get('title')}")
            lines.append(f"- **ID**: {f.get('id')}")
            lines.append(f"- **Validator Note**: {f.get('validator_note')}")
    lines.append("")
    
    # Evidence
    lines.append("## Evidence")
    if not evidence_chunks:
        lines.append("No evidence memory chunks recorded.")
    else:
        for chunk in evidence_chunks:
            lines.append(f"### Memory Chunk {chunk.get('id')}")
            lines.append(f"- **Source**: {chunk.get('source_type')} / {chunk.get('source_id')}")
            lines.append(f"- **Tags**: {chunk.get('tags')}")
            lines.append(f"- **Content Preview**:")
            lines.append("```")
            lines.append(chunk.get("content", ""))
            lines.append("```")
    lines.append("")
    
    # Limitations
    lines.append("## Limitations")
    if mission.profile_id == "autonomous-recon":
        lines.append(
            "Analysis is limited to the defined target scope and toolsets."
        )
        lines.append(
            "Autonomous execution was limited to passive and safe-active "
            "reconnaissance; no exploitation or credential attacks were performed."
        )
    elif mission.profile_id == "authorized-operator-validation":
        lines.append(
            "This mission may include active, exploit, or post-exploitation "
            "validation explicitly authorized by its engagement policy and "
            "approval receipts."
        )
        lines.append(
            "Results remain limited to the supplied task graph, evidence "
            "prerequisites, declared scope, and completed tool actions."
        )
    else:
        lines.append(
            "Analysis is static and limited to the defined target scope and toolsets."
        )
        lines.append("Dynamic analysis or active verification was not performed.")
    lines.append("")
    
    # Recommendations
    lines.append("## Recommendations")
    inconclusive_coverage = [
        item for item in coverage_items
        if item.get("status") in {"inconclusive", "blocked", "failed"}
    ]
    if not confirmed_findings and (
        hypothesis_findings or inconclusive_coverage
    ):
        lines.append(
            "No remediation recommendation is finalized. Review unresolved "
            "finding hypotheses and inconclusive coverage before drawing a "
            "scope-level conclusion."
        )
    elif not confirmed_findings:
        lines.append(
            "No safely validated findings were recorded; this is not an "
            "assertion that the entire scope is clean."
        )
    else:
        for f in confirmed_findings:
            lines.append(f"- **{f.get('title')}**: {f.get('recommendation') or 'Mitigate the issue.'}")
            
    return "\n".join(lines).strip()

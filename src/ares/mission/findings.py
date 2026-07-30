from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum


class FindingState(str, Enum):
    # Legacy persisted states remain readable while new production paths use
    # the explicit lifecycle below.
    HYPOTHESIS = "hypothesis"
    VALIDATED = "validated"
    OBSERVED = "observed"
    HYPOTHESIZED = "hypothesized"
    CORROBORATED = "corroborated"
    SAFELY_VALIDATED = "safely_validated"
    REPORTED = "reported"
    REFUTED = "refuted"



class Severity(str, Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class MissionFinding:
    id: str
    mission_id: str
    title: str
    severity: Severity
    state: FindingState = FindingState.OBSERVED
    affected_component: str = ""
    evidence_chunk_ids: list[int] = field(default_factory=list)
    evidence_tool_call_ids: list[int] = field(default_factory=list)
    contradictory_evidence_tool_call_ids: list[int] = field(default_factory=list)
    contradiction_resolution: str = ""
    reproduction_steps: list[str] = field(default_factory=list)
    confidence: float = 0.0
    confidence_rationale: str = ""
    severity_rationale: str = ""
    validator_note: str = ""
    recommendation: str = ""
    redacted: str = ""
    version_only: bool = False

    def add_evidence_chunk(self, chunk_id: int) -> None:
        if chunk_id not in self.evidence_chunk_ids:
            self.evidence_chunk_ids.append(chunk_id)

    def add_evidence_tool_call(self, tool_call_id: int) -> None:
        if tool_call_id not in self.evidence_tool_call_ids:
            self.evidence_tool_call_ids.append(tool_call_id)

    def add_contradictory_evidence(self, tool_call_id: int) -> None:
        if tool_call_id not in self.contradictory_evidence_tool_call_ids:
            self.contradictory_evidence_tool_call_ids.append(tool_call_id)

    def hypothesize(self) -> None:
        if self.state != FindingState.OBSERVED:
            raise ValueError("only observed findings can be hypothesized")
        if not self.evidence_tool_call_ids and not self.evidence_chunk_ids:
            raise ValueError("hypothesis requires persisted evidence")
        self.state = FindingState.HYPOTHESIZED

    def corroborate(self) -> None:
        if self.state != FindingState.HYPOTHESIZED:
            raise ValueError("only hypothesized findings can be corroborated")
        if len(self.evidence_tool_call_ids) < 2:
            raise ValueError(
                "corroboration requires at least two persisted tool-call evidence IDs"
            )
        if not self.confidence_rationale.strip():
            raise ValueError("corroboration requires a confidence rationale")
        self.state = FindingState.CORROBORATED

    def can_validate(self) -> bool:
        return (
            self.state == FindingState.CORROBORATED
            and not self.version_only
            and bool(self.evidence_tool_call_ids or self.evidence_chunk_ids)
            and bool(self.reproduction_steps)
            and bool(self.validator_note.strip())
            and bool(self.confidence_rationale.strip())
            and bool(self.severity_rationale.strip())
            and (
                not self.contradictory_evidence_tool_call_ids
                or bool(self.contradiction_resolution.strip())
            )
            and self.confidence >= 0.7
        )

    def validate(self) -> None:
        if self.version_only:
            raise ValueError(
                "version-only observations cannot be safely validated"
            )
        if not self.can_validate():
            raise ValueError(
                "finding requires evidence and, for the explicit lifecycle, "
                "corroboration, persisted evidence, "
                "reproduction steps, rationales, validator note, and "
                "confidence >= 0.7"
            )
        self.state = FindingState.SAFELY_VALIDATED

    def refute(self, note: str) -> None:
        if not note.strip():
            raise ValueError("refute note is required")
        self.validator_note = note
        self.state = FindingState.REFUTED

    def report(self) -> None:
        if self.state != FindingState.SAFELY_VALIDATED:
            raise ValueError("only validated findings can be reported")
        self.state = FindingState.REPORTED

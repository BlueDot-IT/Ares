from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum


class FindingState(str, Enum):
    HYPOTHESIS = "hypothesis"
    OBSERVED = "observed"
    VALIDATED = "validated"
    REFUTED = "refuted"
    REPORTED = "reported"


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
    state: FindingState = FindingState.HYPOTHESIS
    affected_component: str = ""
    evidence_chunk_ids: list[int] = field(default_factory=list)
    confidence: float = 0.0
    validator_note: str = ""
    recommendation: str = ""
    redacted: str = ""

    def add_evidence_chunk(self, chunk_id: int) -> None:
        if chunk_id not in self.evidence_chunk_ids:
            self.evidence_chunk_ids.append(chunk_id)

    def can_validate(self) -> bool:
        return bool(self.evidence_chunk_ids) and bool(self.validator_note.strip()) and self.confidence >= 0.7

    def validate(self) -> None:
        if not self.can_validate():
            raise ValueError("finding requires evidence, validator note, and confidence >= 0.7")
        self.state = FindingState.VALIDATED

    def refute(self, note: str) -> None:
        if not note.strip():
            raise ValueError("refute note is required")
        self.validator_note = note
        self.state = FindingState.REFUTED

    def report(self) -> None:
        if self.state != FindingState.VALIDATED:
            raise ValueError("only validated findings can be reported")
        self.state = FindingState.REPORTED

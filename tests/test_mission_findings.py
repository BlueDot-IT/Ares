from __future__ import annotations

import pytest
from ares.mission.findings import MissionFinding, FindingState, Severity


def test_cannot_validate_without_evidence():
    finding = MissionFinding(id="f1", mission_id="m1", title="Leak", severity=Severity.MEDIUM)
    finding.validator_note = "Looks valid."
    finding.confidence = 0.8
    assert finding.can_validate() is False
    with pytest.raises(ValueError, match="finding requires evidence"):
        finding.validate()


def test_cannot_validate_without_validator_note():
    finding = MissionFinding(id="f1", mission_id="m1", title="Leak", severity=Severity.MEDIUM)
    finding.add_evidence_chunk(42)
    finding.confidence = 0.8
    assert finding.can_validate() is False
    with pytest.raises(ValueError, match="finding requires evidence"):
        finding.validate()


def test_cannot_validate_below_confidence():
    finding = MissionFinding(id="f1", mission_id="m1", title="Leak", severity=Severity.MEDIUM)
    finding.add_evidence_chunk(42)
    finding.validator_note = "Verified."
    finding.confidence = 0.69
    assert finding.can_validate() is False
    with pytest.raises(ValueError, match="finding requires evidence"):
        finding.validate()


def test_can_validate_with_all_requirements():
    finding = MissionFinding(id="f1", mission_id="m1", title="Leak", severity=Severity.MEDIUM)
    finding.add_evidence_chunk(42)
    finding.validator_note = "Verified."
    finding.confidence = 0.7
    assert finding.can_validate() is True
    finding.validate()
    assert finding.state == FindingState.VALIDATED


def test_cannot_report_unvalidated():
    finding = MissionFinding(id="f1", mission_id="m1", title="Leak", severity=Severity.MEDIUM)
    with pytest.raises(ValueError, match="only validated findings can be reported"):
        finding.report()
    
    # Even if observed, cannot report directly
    finding.state = FindingState.OBSERVED
    with pytest.raises(ValueError, match="only validated findings can be reported"):
        finding.report()


def test_refute_requires_note():
    finding = MissionFinding(id="f1", mission_id="m1", title="Leak", severity=Severity.MEDIUM)
    with pytest.raises(ValueError, match="refute note is required"):
        finding.refute("")
    with pytest.raises(ValueError, match="refute note is required"):
        finding.refute("   ")
    
    finding.refute("False positive because of X.")
    assert finding.state == FindingState.REFUTED
    assert finding.validator_note == "False positive because of X."

# ARES Mission Training Export

ARES supports exporting completed mission traces for offline training, trace debugging, or tuning custom LLM models.

## Usage
The training data module provides a Python helper to serialize mission execution traces:

```python
from ares.state.db import StateDB
from ares.training.export import export_mission_traces

db = StateDB("~/.ares/state.db")
count = export_mission_traces(db, "data/mission-traces.jsonl")
print(f"Exported {count} completed mission traces.")
```

## Record Shape
Each line of the exported JSONL conforms to the `mission_trace` schema:

```json
{
  "type": "mission_trace",
  "mission_id": "m_a1b2c3d4",
  "profile_id": "secrets-audit",
  "target": "bench/redteam/secrets-basic",
  "tasks": [
    {
      "id": "m_a1b2c3d4-scan-secrets",
      "role_id": "scanner",
      "phase": "scan",
      "description": "Scan scoped files for secrets.",
      "status": "completed"
    }
  ],
  "findings": [
    {
      "id": "m_a1b2c3d4-finding-1",
      "title": "Possible hardcoded secret",
      "severity": "medium",
      "state": "validated",
      "affected_component": "src/config.py",
      "confidence": 0.75,
      "validator_note": "Validated as scoped static evidence. Manual review still required."
    }
  ],
  "evidence_chunk_ids": [1],
  "report_summary": "# ARES Mission Report\n\n## Summary\n..."
}
```

## Exclusions & Redactions
- All potential secret values are fully redacted.
- Forbidden paths are checked and excluded.
- Blocked/pending tasks and refuted findings are fully preserved to train models on bounds and negative paths.

# Ares Mission CLI

Ares missions provide repeatable, policy-bound assessment workflows. A mission can use a named deterministic profile, an explicit operator task graph, or the governed autonomous reconnaissance profile.

## Commands

```bash
ares mission run [options]
ares mission list
ares mission report <mission-id> --out <report-path>
```

Compatibility aliases remain available:

```bash
ares mission-run
ares mission-list
ares mission-report
```

## Common run options

```text
--profile <profile>
--target <target>
--allowed-path <path>
--forbidden-path <path>
--allowed-host <host-or-cidr>
--forbidden-action <phrase>
--max-risk <risk>
--mission-id <engagement-id>
--initial-tasks <tasks.json>
--ghostmcp-policy <engagement-policy.json>
--approval-receipts <receipts.json>
--approve-high-risk
--autonomous
--max-tasks <count>
--ports <port-scope>
--out <report.md>
--dry-run
```

Options that accept multiple values may be supplied more than once.

## Deterministic profiles

Supported deterministic profiles include:

- `secrets-audit`
- `dependency-audit`
- `source-code-audit`
- `report-only`
- `authorized-operator-validation`

Example source assessment:

```bash
ares mission run \
  --profile source-code-audit \
  --target /srv/authorized-project \
  --allowed-path /srv/authorized-project \
  --forbidden-path /srv/authorized-project/.git \
  --max-risk scan \
  --out source-audit.md
```

A deterministic profile uses fixed role and tool contracts. It does not ask a model to invent the task graph.

## Governed autonomous reconnaissance

The `autonomous-recon` profile supports model-prioritized passive and safe-active reconnaissance while keeping tool and target construction inside Ares.

```bash
ares mission run \
  --profile autonomous-recon \
  --target 192.0.2.10 \
  --allowed-host 192.0.2.10 \
  --max-risk active \
  --ports 22,80,443,8000 \
  --max-tasks 16 \
  --autonomous \
  --out autonomous-recon.md
```

Required controls:

- `--profile autonomous-recon`
- at least one explicit `--allowed-host`
- `--max-risk active`
- a valid TCP port list or range covering no more than 4096 ports
- a positive `--max-tasks` budget

The planner receives no callable tools. It selects only exact coverage IDs from the persistent ledger. Ares compiles the selected ID into a fixed capability, tool, target, and argument set before mission and dispatcher validation.

Each graph node, graph edge, coverage decision, planner cycle, tool result, bounded recovery attempt, finding hypothesis, and limitation is persisted for resume and reporting.

Autonomous reconnaissance does not perform exploitation, authentication attempts, persistence, exfiltration, or arbitrary command execution.

Preview the governed setup without dispatching a tool:

```bash
ares mission run \
  --profile autonomous-recon \
  --target 192.0.2.10 \
  --allowed-host 192.0.2.10 \
  --max-risk active \
  --ports 80,443 \
  --max-tasks 8 \
  --autonomous \
  --dry-run
```

## Authorized operator validation

The advanced validation path requires an explicit operator task graph. Ares never infers advanced tasks and the model never selects them.

A typical sequence has two stages.

### 1. Acquire evidence

Run a recon-only graph with a stable mission ID. Successful, non-empty tool-call IDs from this stage can be referenced by later validation tasks.

```bash
ares mission run \
  --profile authorized-operator-validation \
  --mission-id engagement-2026-001 \
  --target 192.0.2.10 \
  --allowed-host 192.0.2.10 \
  --max-risk active \
  --initial-tasks recon-tasks.json \
  --ghostmcp-policy engagement-policy.json
```

### 2. Bind approval to the exact advanced task

The advanced task JSON must include `supporting_evidence_tool_call_ids` from the same mission and target. Run a dry run to obtain the exact approval digest:

```bash
ares mission run \
  --profile authorized-operator-validation \
  --mission-id engagement-2026-001 \
  --target 192.0.2.10 \
  --allowed-host 192.0.2.10 \
  --max-risk post-exploitation \
  --initial-tasks validation-tasks.json \
  --dry-run
```

Issue a mode-`0600` receipt bound to the exact mission, task, role, tool, target, arguments, supporting-evidence digest, approver, and expiry. Add the receipt ID to the task and execute:

```bash
ares mission run \
  --profile authorized-operator-validation \
  --mission-id engagement-2026-001 \
  --target 192.0.2.10 \
  --allowed-host 192.0.2.10 \
  --max-risk post-exploitation \
  --initial-tasks validation-tasks.json \
  --ghostmcp-policy engagement-policy.json \
  --approval-receipts approval-receipts.json \
  --approve-high-risk \
  --out validation-report.md
```

The receipt is consumed before the single dispatch attempt and cannot be reused or replaced. Failed, empty, cross-target, cross-mission, expired, replayed, or contract-mismatched evidence and receipts fail closed.

The GhostMCP policy remains the authoritative effective-argument boundary for protected GhostMCP operations. Ares supplies the mission ID and overwrites any engagement identity included in task arguments.

## Bounded recovery and findings

Reconnaissance capabilities may use one trusted equivalent recovery attempt when the primary operation fails. Recovery tools and arguments come from an Ares-owned catalog, not model output. HTTP 404 responses are preserved as evidence rather than treated as a failed probe.

Findings progress through:

```text
observed -> hypothesized -> corroborated -> safely_validated -> reported
```

Product and version banners may create hypotheses but do not prove vulnerability impact. Safe validation requires independent behavioral evidence.

## Resume and reports

Use a stable `--mission-id` to resume a compatible mission. Resumed missions remain bound to their original profile, scope, port scope, and execution metadata.

List stored missions:

```bash
ares mission list
```

Render an existing mission report:

```bash
ares mission report engagement-2026-001 --out report.md
```

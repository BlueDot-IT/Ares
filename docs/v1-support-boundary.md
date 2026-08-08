# Ares 1.x Support Boundary

This document defines the supported product surface for the stable Ares 1.x line. Patch releases preserve this contract. Minor releases may add supported behavior but must not silently weaken policy, evidence, or authorization boundaries.

## Supported commands

The supported operator commands are:

- `ares doctor`
- `ares doctor --json`
- `ares support-bundle`
- `ares model`
- `ares onboard`
- `ares auth login/status/logout`
- `ares route`
- `ares run`
- `ares sessions`
- `ares report`
- `ares tools`
- `ares memory`
- `ares training`
- `ares theme`
- `ares gateway-config`
- `ares gateway`
- `ares dashboard`
- `ares gateway-pair`
- `ares tui`
- `ares mission run/list/report`
- `ares mission-run/mission-list/mission-report`
- `ares-dashboard`
- `ares-tui`

## Supported runtime surface

The supported 1.x runtime surface includes:

- runtime wiring in `src/ares/run.py`
- agent runtime, dispatcher, context builder, context budgeter, and result indexing in `src/ares/agent/`
- policy enforcement in `src/ares/policy/`
- model adapters, fallback, and OAuth helpers in `src/ares/llm/`
- SQLite state and schema migrations in `src/ares/state/`
- attack-surface graph, coverage ledger, governed planner, finding manager, and bounded recovery in `src/ares/autonomy/`
- deterministic mission profiles, task contracts, approval receipts, coordinator behavior, and mission reporting in `src/ares/mission/`
- report rendering in `src/ares/reporting/`
- central tool registry plus GhostMCP, OnionClaw, mission, and evidence-memory adapters in `src/ares/tools/`
- gateway API/control-plane behavior in `src/ares/gateway.py` and `src/ares/gateway_auth.py`
- browser dashboard behavior in `src/ares/dashboard.py` and compatibility asset builders in `src/ares/webui.py`
- terminal operator UI behavior in `src/ares/tui.py`
- redacted training-data export in `src/ares/training/export.py`
- editable and built-wheel install paths documented in `README.md` and `INSTALL.md`
- the main test suite in `tests/` plus the vendored GhostMCP tree when installed editable from `vendor/ghostmcp`

## Operator surface separation

Ares uses three distinct operator surfaces:

- `gateway`: backend API and control plane for auth, pairing, allowlists, run submission, run status, event polling, and audit logging
- `dashboard`: browser frontend backed by the gateway API
- `tui`: terminal frontend for interactive operator work

The gateway may serve bundled dashboard assets, but that does not merge the gateway and dashboard product boundaries.

## Supported execution paths

### Supervised runtime

`ares run` supports a model and tool loop where the model may request registered tools. Every call is revalidated by the dispatcher for scope, risk, approval, route, duplicate, and timeout policy before execution.

### Deterministic missions

Named deterministic mission profiles and explicit operator task graphs are supported. Task identity, phase, role, toolset, tool, target, scope, dependency, and risk contracts are validated outside the model.

### Governed autonomous reconnaissance

The `autonomous-recon` profile is supported for authorized passive and safe-active reconnaissance.

The model planner:

- receives bounded, untrusted evidence summaries
- may choose only exact pending coverage IDs issued by Ares
- cannot invent a tool, target, argument, role, or task ID
- cannot select exploitation, authentication, persistence, exfiltration, or post-exploitation work

Ares compiles the selected coverage ID into a fixed capability, tool, target, and argument set before ordinary mission and dispatcher validation. The mission requires explicit allowed-host scope, an active-risk ceiling, a bounded port scope, and a task budget.

### Authorized operator validation

The `authorized-operator-validation` profile is supported for explicit operator-supplied task graphs. Advanced roles are never model-selected.

An advanced dispatch requires all applicable controls:

- successful non-empty evidence from the same mission and target
- an exact supported role, phase, toolset, tool, target, argument, and risk contract
- a digest-bound, expiring, single-use approval receipt
- a matching GhostMCP engagement policy for protected GhostMCP operations
- explicit out-of-model high-risk approval

Failed, empty, cross-target, cross-mission, expired, replayed, or contract-mismatched evidence and receipts fail closed.

## Stable behavior expectations

- Session, message, tool-call, host, service, memory, mission, graph, coverage, finding, recovery, planner, and approval-receipt records remain migration-safe across patch releases.
- `ares_schema_meta` records the stable StateDB schema version.
- Existing supported databases are upgraded in place when StateDB opens them.
- Scope, risk, approval, duplicate, route, timeout, mission contract, and receipt checks remain outside the model.
- Tool output, target content, and recalled evidence remain untrusted data, not operator instructions.
- Long-context mode remains opt-in through `ARES_CONTEXT_MODE=long`.
- Raw tool excerpts remain excluded from model context unless `ARES_CONTEXT_INCLUDE_RAW=true`.
- Gateway auth, pairing, allowlist, and access-mode behavior remain stable across CLI, browser, and API flows.
- Dangerous gateway approvals require authenticated session provenance.
- Evidence recall may span prior sessions only when their engagement target matches the current target.
- Reports preserve evidence and limitation provenance.
- Training export remains offline, explicit, redacted, and operator-triggered.
- The `bluedot-ares` distribution continues to install the `ares`, `ares-dashboard`, and `ares-tui` commands and the `ares` import package.

## Experimental or non-contract behavior

The following remain available but are not patch-stable contracts unless promoted later:

- exact prompt wording and section ordering inside context assembly
- exact ranking among otherwise valid coverage items
- exact planner explanation wording
- exact memory search ranking when FTS5 is available versus LIKE fallback
- provider-specific OAuth internals beyond the documented command behavior
- exact long-context vLLM model and tuning recommendations
- OnionClaw internals outside the bounded Ares adapter surface
- browser visual styling that does not change API or operator control semantics

## Unsupported behavior

The following are not supported product behavior:

- unattended exploitation
- model-selected advanced validation
- arbitrary shell or raw command construction by the model
- target expansion outside the declared engagement scope
- bypassing approval receipts or GhostMCP policy with CLI flags
- multi-tenant hosted operation without an external isolation architecture
- the removed PySide6 GUI and root-level legacy entrypoints

## Release rule

Do not break a supported item in a patch release. If a supported contract must change, document it as a minor or major release and provide migration guidance. Experimental behavior must remain contained and fail closed even when its exact output is not compatibility-guaranteed.

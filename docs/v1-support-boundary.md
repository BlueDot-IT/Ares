# Ares v1 Support Boundary

This document defines the supported surface for the stable v1 line.

## Supported in v1

The supported v1 operator commands are:

- `ares doctor`
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
- `ares-dashboard`
- `ares-tui`

The supported v1 runtime surface is:

- runtime wiring in `src/ares/run.py`
- agent runtime, dispatcher, context builder, context budgeter, and context config in `src/ares/agent/`
- policy enforcement in `src/ares/policy/`
- model adapters, model fallback, and OAuth helpers in `src/ares/llm/`
- SQLite state persistence in `src/ares/state/`
- report rendering in `src/ares/reporting/`
- central tool registry plus GhostMCP, OnionClaw, and evidence-memory adapters in `src/ares/tools/`
- gateway API/control-plane behavior in `src/ares/gateway.py` and `src/ares/gateway_auth.py`
- browser dashboard behavior in `src/ares/dashboard.py` and compatibility asset builders in `src/ares/webui.py`
- terminal operator UI behavior in `src/ares/tui.py`
- redacted training-data export in `src/ares/training/export.py`
- editable install and built-wheel install paths documented in `README.md`
- the main test suite in `tests/` plus the vendored GhostMCP tree when installed editable from `vendor/ghostmcp`

## Operator surface separation

Ares v1 uses three distinct operator surfaces:

- `gateway`: backend API/control plane for auth, pairing, allowlists, run submission, run status, event polling, and audit logging.
- `dashboard`: browser frontend backed by the gateway API. It may be served by the gateway process, but the dashboard owns the browser UI assets and browser-facing launcher.
- `tui`: terminal frontend for interactive operator work. It is separate from the browser dashboard.

## Stable behavior expectations

- Session, message, tool-call, host, service, and memory-chunk persistence stay backward-compatible across patch releases.
- The `ares_schema_meta` table records the stable StateDB schema version.
- Existing beta databases without v1 metadata are upgraded in place when `StateDB` opens them.
- Scope, risk, approval, duplicate suppression, target route policy, and tool timeout checks are enforced outside the model.
- Tool output and recalled evidence are treated as untrusted data, not operator instructions.
- Long-context mode remains opt-in through `ARES_CONTEXT_MODE=long`.
- Raw tool excerpts remain excluded from model context unless `ARES_CONTEXT_INCLUDE_RAW=true`.
- Gateway auth, pairing, allowlist, and access-mode behavior remain stable in CLI, browser, and API flows.
- Dangerous gateway approvals require authenticated session provenance even when safe gateway endpoints do not require authentication.
- Evidence recall may span prior sessions only when their target matches the current engagement target.
- Markdown reports remain backward-compatible across patch releases.
- Training export remains offline, explicit, redacted, and operator-triggered.

## Experimental or non-stable behavior

The following are available but not guaranteed as a patch-stable contract unless promoted in a later minor release:

- exact prompt wording and section ordering inside long-context assembly
- exact ranking behavior for memory recall when FTS5 is available versus LIKE fallback
- exact long-context vLLM model choice and server tuning values in `docs/long-context-vllm.md`
- provider-specific OAuth implementation details beyond the documented CLI contract
- model-driven mission planning; `run_agentic()` intentionally fails closed until such a planner is implemented and contained
- OnionClaw internals outside the bounded Ares-facing adapter surface

## Unsupported legacy surfaces

None. The old PySide6 GUI and root-level legacy CLI/main entrypoints were removed from the repository.

## Release rule of thumb

If a feature is listed as supported here, do not break it in a patch release. If behavior must change, document it as a minor or major release change.

If a feature is listed as experimental, keep it safe and tested but do not promise exact compatibility across patch releases.

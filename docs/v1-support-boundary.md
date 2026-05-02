# Ares v1 Support Boundary

This document defines the supported surface for the planned stable v1 line.

## Supported in v1

- `ares` CLI commands: `doctor`, `model`, `onboard`, `gateway`, `gateway-pair`, `run`, `sessions`, `report`, `tools`, `auth`, and `tui`
- the runtime stack in `src/ares/run.py`, `src/ares/agent/`, `src/ares/policy/`, `src/ares/state/`, and `src/ares/reporting/`
- the lightweight gateway and browser UI in `src/ares/gateway.py`, `src/ares/gateway_auth.py`, and `src/ares/webui.py`
- the editable install path documented in `README.md`
- the main test suite in `tests/` plus the vendored GhostMCP tree when installed editable from `vendor/ghostmcp`

## Stable behavior expectations

- session/event ordering remains stable unless a release note says otherwise
- scope, risk, approval, and routing policy are enforced outside the model
- gateway auth and pairing behave the same in CLI, browser, and API flows
- session persistence and Markdown reporting remain backward-compatible across patch releases

## Legacy or transitional surfaces

- `src/main.py` and the PySide6 GUI under `src/ui/`
- any ad hoc integration hooks or extra surfaces that are not listed above as part of the supported v1 path

## Release rule of thumb

If a feature is listed as supported here, do not break it in a patch release.
If a feature is not listed here, it can remain transitional until the v1 line explicitly adopts it.

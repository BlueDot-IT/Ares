# Ares v1 Release Checklist

This checklist is the release gate for the stable `v1.0.0` line.

## Phase 1: Release engineering and install hygiene

- [x] Align declared dependencies with the documented install path.
- [x] Add CI to run install smoke checks, `pytest`, and `compileall`.
- [x] Add CI to build wheel and sdist artifacts.
- [x] Add CI smoke checks against the built wheel.
- [x] Add tag-triggered release artifact workflow.
- [x] Bump package metadata and runtime version to `1.0.0`.
- [x] Add the `ares-dashboard` console script beside `ares` and `ares-tui`.

## Phase 2: Runtime, policy, and gateway hardening

- [x] Keep the runtime/session/event lifecycle stable.
- [x] Keep gateway auth, pairing, and allowlist behavior reliable.
- [x] Add gateway auth matrix tests for exposed mode, bearer parsing, pairing reuse, TTL handling, failed-login windows, and CIDR allowlists.
- [x] Keep routing and policy enforcement deterministic.
- [x] Keep high-risk approval gates outside the model.
- [x] Keep the gateway defined as the API/control plane, not the browser dashboard.

## Phase 3: StateDB and evidence-memory stability

- [x] Add stable StateDB schema metadata through `ares_schema_meta`.
- [x] Upgrade beta databases in place when missing v1 columns.
- [x] Preserve legacy sessions and tool calls during schema initialization.
- [x] Rebuild memory FTS state for existing `memory_chunks` rows.
- [x] Preserve LIKE fallback behavior when FTS5 is unavailable.

## Phase 4: CLI/TUI/dashboard onboarding and operator UX

- [x] Make startup and help text consistent.
- [x] Keep onboarding flows predictable in TTY and non-TTY use.
- [x] Make operator-facing errors actionable.
- [x] Document the full supported command surface.
- [x] Separate gateway, dashboard, and TUI as distinct operator surfaces.
- [x] Add `ares dashboard` and `ares-dashboard` as browser-facing launchers.

## Phase 5: Documentation and release boundary

- [x] Define v1 support expectations clearly.
- [x] Split supported v1 behavior from experimental behavior.
- [x] Update release and install docs so they match the code.
- [x] Update long-context docs so the training command matches the CLI.
- [x] Keep README release language aligned with package metadata.
- [x] Document the gateway/dashboard/TUI separation.
- [x] Add `CHANGELOG.md`.
- [x] Add `docs/releases/v1.0.0.md` release notes.

## Phase 6: Legacy removal

- [x] Remove the PySide6 GUI path and root-level legacy CLI/main entrypoints.
- [x] Make the main Ares CLI/TUI/Gateway/Dashboard surfaces obvious.
- [x] Ensure release docs no longer describe removed legacy surfaces as supported.

## Final local gate before tagging

Run this from a clean checkout before creating the release tag:

```bash
git checkout main
git pull origin main

python -m venv .venv-v1
. .venv-v1/bin/activate
python -m pip install --upgrade pip build
python -m pip install -e . -e vendor/ghostmcp -e '.[dev]' '.[anthropic]' '.[gemini]' '.[ghostmcp]'

python -m pytest tests -q
python -m compileall src/ares

python -m build
python -m pip uninstall -y ares
python -m pip install dist/*.whl

ares --version
ares doctor
ares tools
ares dashboard --help
ares-dashboard --help
ares route --target 127.0.0.1 --prompt "safe local smoke test"
ares training --out /tmp/ares-sft-smoke.jsonl --min-status final_response
```

## Tag command

After the final local gate passes:

```bash
git tag -a v1.0.0 -m "Ares v1.0.0"
git push origin v1.0.0
```

The tag push triggers `.github/workflows/release.yml` to build and upload release artifacts.

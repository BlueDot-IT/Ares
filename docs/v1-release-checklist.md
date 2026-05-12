# Ares v1 Release Checklist

> Working checklist for moving Ares from strong beta toward a stable v1 release.

## Phase 1: Release engineering and install hygiene

- [x] Align declared dependencies with the documented install path.
- [x] Add CI to run install smoke checks, `pytest`, and `compileall`.
- [x] Verify the repo can be installed and exercised from a clean environment.

## Phase 2: Runtime, policy, and gateway hardening

- [x] Keep the runtime/session/event lifecycle stable.
- [x] Keep gateway auth, pairing, and allowlist behavior reliable.
- [x] Keep routing and policy enforcement deterministic.

## Phase 3: CLI/TUI onboarding and operator UX

- [x] Make startup and help text consistent.
- [x] Keep onboarding flows predictable in TTY and non-TTY use.
- [x] Make operator-facing errors actionable.

## Phase 4: Documentation and release boundary

- [x] Define v1 support expectations clearly.
- [x] Split supported v1 behavior from experimental or legacy behavior.
- [x] Update release and install docs so they match the code.

## Phase 5: Legacy removal

- [x] Remove the PySide6 GUI path and root-level legacy CLI/main entrypoints.
- [x] Make the main Ares CLI/TUI/Gateway surfaces obvious.
- [x] Ensure release docs no longer describe removed legacy surfaces as supported.

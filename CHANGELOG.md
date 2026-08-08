# Changelog

All notable changes to Ares are documented here.

## 1.1.0 - Unreleased

### Added

- Added governed autonomous reconnaissance with a persistent attack-surface graph, explicit coverage ledger, and model planning restricted to exact Ares-issued coverage IDs.
- Added deterministic compilation from planner decisions into fixed tools, targets, and arguments before policy validation.
- Added the finding lifecycle `observed -> hypothesized -> corroborated -> safely_validated -> reported` with supporting and contradictory evidence, reproduction steps, and operator-visible rationales.
- Added bounded, single-attempt recovery for HTTP, TLS, and service fingerprint failures with persisted provenance and shared task-budget accounting.
- Added evidence-bound, digest-bound, expiring, single-use approval receipts for advanced operator validation.
- Added `ares doctor --json` for machine-readable preflight diagnostics.
- Added `ares support-bundle` for redacted runtime diagnostics without credentials or engagement evidence.
- Added end-user installation, quickstart, troubleshooting, architecture, support, contribution, and release-verification documentation.
- Added structured GitHub issue forms and a pull request checklist.

### Changed

- Changed the Python distribution name from `ares` to `bluedot-ares` while retaining the `ares` import package and command names.
- Bumped the product and runtime version to `1.1.0`.
- Reworked the README around operator outcomes, supported execution paths, and explicit safety boundaries.
- Promoted governed autonomous reconnaissance and deterministic authorized operator validation into the documented 1.1 support boundary.
- Made wheel discovery distribution-name agnostic throughout CI and release smoke tests.
- Updated the official release workflow to generate checksums, a CycloneDX SBOM, release metadata, GitHub provenance attestations, and SBOM attestations.
- Added an optional PyPI Trusted Publishing job gated by the `PYPI_PUBLISH_ENABLED` repository variable and the `pypi` GitHub environment.

### Fixed

- Fixed the nested `ares mission run` command so `--approval-receipts` is accepted and forwarded to advanced validation.
- Removed the stale PySide6 dependency from `requirements.txt` after the legacy GUI removal.
- Corrected documentation that still described model-planned reconnaissance as an unimplemented fail-closed placeholder.
- Corrected mission CLI documentation to include `autonomous-recon`, `--autonomous`, `--max-tasks`, `--ports`, and approval receipts.

### Security

- Kept model planning limited to reconnaissance coverage selection. The model cannot invent tools, targets, arguments, exploitation tasks, or post-exploitation tasks.
- Kept advanced validation dependent on same-mission evidence, exact task contracts, GhostMCP policy where applicable, immutable approval receipts, and out-of-model approval.
- Added release checksums, SBOM generation, build provenance, and attestation verification guidance without adding a long-lived package publishing token.

## 1.0.1 - Security and OAuth hardening

### Fixed

- Bound evidence-memory search to the current engagement target, preventing cross-target recall while preserving same-target history.
- Added non-interactive OpenAI OAuth refresh-token rotation and actionable reauthentication failures.
- Prevented background model execution from opening an interactive OAuth browser flow.
- Required authenticated, non-secret session provenance for gateway dangerous approvals.
- Removed internal engagement and authorization fields from model-visible GhostMCP schemas.
- Replaced the misleading deterministic `run_agentic()` behavior with a fail-closed API and an honestly named contextual deterministic path.
- Replaced gateway and dashboard port-collision tracebacks with concise operator errors.
- Restored Windows CLI startup by making curses UI loading lazy and installing `windows-curses` only on Windows.
- Made private-file and SQLite initialization tolerate Windows' lack of `os.fchmod` while retaining POSIX mode tightening where supported.

### Release engineering

- Moved package metadata and support links to the canonical `BlueDot-IT/Ares` repository.
- Made CI and release wheel smoke tests version-independent.
- Added tag/package-version verification and GitHub release publication with wheel and source artifacts.

## 1.0.0 - Stable v1

Ares v1.0.0 is the first stable release of the operator-supervised Ares security testing runtime for authorized engagements.

### Added

- Stable Typer CLI through `ares`.
- Dedicated browser dashboard command through `ares dashboard` and `ares-dashboard`.
- Dedicated terminal operator UI through `ares tui` and `ares-tui`.
- Gateway API/control plane with run submission, run status, event polling, auth, pairing, CIDR allowlists, and audit logging.
- Clear gateway/dashboard/TUI operator-surface separation.
- Multi-provider model execution through OpenAI-compatible endpoints plus native Anthropic and Gemini adapters.
- Model fallback chains.
- OpenAI and Gemini OAuth credential helpers.
- Central tool registry with model-visible schemas, availability checks, risk levels, and toolset metadata.
- Dispatcher-owned scope, ROE, risk, approval, duplicate suppression, target-route, and timeout enforcement.
- Compact and long-context modes controlled by `ARES_CONTEXT_*` settings.
- SQLite-backed sessions, messages, tool calls, hosts, services, and memory chunks.
- StateDB v1 schema metadata through `ares_schema_meta`.
- In-place upgrade handling for beta databases missing v1 columns.
- Memory chunk indexing with FTS5 search when available and LIKE fallback otherwise.
- Passive evidence recall tools: `ares.memory.search` and `ares.evidence.get_tool_call`.
- Redacted training-data export through `ares training`.
- Markdown report generation from stored sessions.
- GhostMCP integration.
- Bounded OnionClaw integration for Tor checks, search, fetch, offline analysis, keyword extraction, and export helpers.
- Security policy in `SECURITY.md`.
- v1 support boundary in `docs/v1-support-boundary.md`.
- v1 release gate in `docs/v1-release-checklist.md`.
- CI package smoke job that builds wheel/sdist, installs the wheel, and checks CLI entrypoints.

### Changed

- Package metadata now declares `1.0.0` and stable classifier metadata.
- Gemini optional dependencies now include OAuth support packages used by the documented Gemini auth path.
- Browser UI branding is now `Ares Dashboard` instead of generic web UI naming.
- Gateway documentation now defines the gateway as an API/control plane, not the dashboard itself.

### Removed

- Legacy PySide6 GUI path.
- Root-level legacy CLI/main entrypoints.

### Security

- Gateway auth, pairing, allowlist, session TTL, failed-login window, and bearer parsing are covered by v1 tests.
- Tool output and recalled evidence are documented and treated as untrusted data, not operator instructions.
- Training export remains offline, explicit, redacted, and operator-triggered.

### Release validation

Before tagging, run the applicable release checklist from a clean checkout.

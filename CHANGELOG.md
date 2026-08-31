# Changelog

All notable changes to Ares are documented here.

## 1.1.1 - 2026-08-30

### Fixed

- Finalized every deterministic and contextual-deterministic operator run and backing session across completed, failed, blocked, and exception outcomes, including tasks that do not invoke a tool.
- Prevented completed mission work from leaving new operator-run and session records indefinitely marked as `running`.
- Migrated state databases to schema v4, correcting the FTS5 external-content column contract and rebuilding the complete memory index without changing stored memory rows.
- Added a dry-run-first `ares mission reconcile-state` command that repairs only explicitly named historical runs and sessions after verifying their completed mission/task relationships and exact allowlists.
- Made the release workflow select the release-notes document that matches the verified tag instead of reusing the v1.1.0 notes for later releases.

### Security and release engineering

- Added CodeQL analysis for pull requests, pushes to `main`, a weekly schedule, and manual runs.
- Enabled GitHub private vulnerability reporting, aligning repository settings with `SECURITY.md`.
- Moved the GhostMCP submodule to its maintained organization repository and advanced it to the audited TLS 1.2 floor and dependency-lock revisions.
- Advanced the optional and vendored GhostMCP dependency to 0.2.1 so the public extra resolves to the maintained release identity.
- Bound release tags to commits reachable from protected `main` and pinned every release-workflow action to an immutable commit.
- Clarified the OpenAI authorization URL constant name and added a regression proving that interactive login output contains no authorization code, PKCE verifier, or OAuth token.
- Removed the nonfunctional repository-local scheduled Codex Security workflow; durable organization-level scanning remains an operational follow-up.
- Bumped the Python distribution, runtime, documentation, and release-gate identity to `1.1.1`.
- Preserved optional PyPI publication through GitHub OIDC Trusted Publishing, gated by the `PYPI_PUBLISH_ENABLED` repository variable and the `pypi` environment.

## 1.1.0 - 2026-08-08

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

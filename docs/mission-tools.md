# ARES Mission Tools

The following redteam scanning tools are registered in the global Tool Registry for swarm testing missions:

## 1. Local Secret Scanner (`redteam_secret_scan`)
- **Toolset**: `redteam_secrets`
- **Risk**: `scan`
- **Description**: Scans files inside the target directory and subdirectories for obvious hardcoded secrets (API keys, tokens, credentials).
- **Redaction**: All secret values matching the patterns are automatically replaced with `***REDACTED***` in both the database record and the final markdown report.

## 2. Dependency Manifest Scanner (`redteam_dependency_manifest_scan`)
- **Toolset**: `redteam_deps`
- **Risk**: `scan`
- **Description**: Searches target directories for standard package files and dependencies configurations (e.g. `package.json`, `requirements.txt`, `Cargo.toml`).

## 3. External Tool Adapters
These are registered wrappers that execute local command line utilities if they are installed on the path:
- `redteam_semgrep_scan` (toolset: `redteam_static`): Runs Semgrep static analysis.
- `redteam_gitleaks_scan` (toolset: `redteam_secrets`): Runs Gitleaks secrets detection.
- `redteam_osv_scan` (toolset: `redteam_deps`): Runs OSV-Scanner for package vulnerabilities.

## 4. GhostMCP contract

Ares pins GhostMCP `v0.2.0` and consumes its tool manifest schema `1.0`.
Manifest risk, capability, availability, target-field, and route metadata are
preserved through both in-process and external-stdio transports.

The adapter maps sensitive capabilities conservatively:

- `remote_execution` becomes Ares `post-exploitation`
- `credential_access` or `collection` becomes at least Ares `exploit`
- `raw_execution` becomes at least Ares `intrusive`

Name-based classification remains only as a conservative secondary floor for
Ares fallback tools. Policy-backed GhostMCP tools receive an Ares-controlled
engagement ID and the manifest-declared engagement mode.

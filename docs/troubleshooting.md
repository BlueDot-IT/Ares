# Troubleshooting Ares

Start with:

```bash
ares --version
ares doctor
ares doctor --json
ares support-bundle --out ares-support-bundle.json
```

## The installed package is not this Ares

Symptom: `pip show ares` describes a Vulnerability-Lookup client or the installed command is `ares-cli`.

Cause: the PyPI project named `ares` is unrelated.

Fix in an isolated environment:

```bash
python -m pip uninstall -y ares
python -m pip install bluedot-ares
```

Verify:

```bash
python -m pip show bluedot-ares
ares --version
```

Do not uninstall a system package until you confirm which interpreter and environment are active.

## `ares` is not found after pipx installation

```bash
python -m pipx ensurepath
```

Restart the shell, then inspect:

```bash
pipx list
command -v ares
```

For `uv`:

```bash
uv tool list
```

## Python version is unsupported

Ares 1.1 supports Python 3.11, 3.12, and 3.13.

```bash
python --version
```

Create the environment with a supported interpreter instead of forcing installation with an unsupported version.

## `ares doctor` shows unavailable tools

Ares reports tool registry availability but does not silently install external assessment software. Install only the tools required for the authorized workflow and rerun:

```bash
ares doctor
```

Missing optional GhostMCP support may require:

```bash
pipx install 'bluedot-ares[ghostmcp]'
```

A source checkout also requires:

```bash
git submodule update --init --recursive
python -m pip install -e '.[ghostmcp]' -e vendor/ghostmcp
```

## Model authentication fails

Inspect effective model configuration:

```bash
ares model
```

For OAuth providers:

```bash
ares auth status --provider openai
ares auth status --provider gemini
```

Reauthenticate when the status is expired or refresh fails:

```bash
ares auth logout --provider <provider>
ares auth login --provider <provider>
```

Background runs do not open an interactive browser. Complete login in an interactive shell before starting a gateway or unattended operator surface.

Never attach token caches or environment files to a public issue.

## Local model server cannot be reached

Confirm the endpoint independently:

```bash
curl -fsS http://127.0.0.1:1234/v1/models
```

Inspect effective settings:

```bash
ares model
```

Typical local configuration:

```bash
export LLM_PROVIDER=local
export LLM_MODEL=local-model
export OPENAI_BASE_URL=http://127.0.0.1:1234/v1
export OPENAI_API_KEY=lm-studio
```

A containerized model server may not be reachable at `127.0.0.1` from another container. Use an explicitly authorized bridge address and keep gateway exposure separate from model-server exposure.

## Gateway or dashboard will not start

Ares reports bind collisions without a traceback. Check the configured bind:

```bash
ares gateway-config
ss -ltnp | grep 18791
```

Use another port when appropriate:

```bash
ares gateway --port 18792
```

Do not use exposed mode without authentication and an allowlist:

```bash
ares gateway-config \
  --mode exposed \
  --auth-enabled \
  --allow-cidr 203.0.113.0/24
```

## Dashboard opens but protected API calls fail

The dashboard assets and authentication bootstrap may load while protected endpoints reject unauthenticated requests. Complete login or pairing against the running gateway.

```bash
ares gateway-pair --label laptop
```

Confirm that the dashboard points to the intended gateway and that the gateway clock is correct for session and pairing expiry.

## Windows TUI or curses import fails

The official wheel installs `windows-curses` on Windows. Confirm the correct distribution is installed in the active interpreter:

```powershell
python -m pip show bluedot-ares
python -m pip show windows-curses
python -c "import curses, ares.tui"
```

Reinstall the official wheel in a clean virtual environment if another package overwrote the `ares` import.

## SQLite FTS5 is unavailable

Ares falls back to LIKE-based memory search when FTS5 is not present. This affects ranking and performance, not the evidence isolation boundary.

Use `ares doctor --json` and include the reviewed output in a support request if search behavior is materially degraded.

## A mission refuses to resume

Resumed missions remain bound to their original profile, scope, port scope, and execution metadata. Use the same `--mission-id` and compatible options.

Do not bypass a resume rejection by editing the SQLite database. Start a new mission ID when the authorized scope or profile intentionally changed.

## `--approval-receipts` is rejected or a receipt fails

Use the nested command on Ares 1.1 or newer:

```bash
ares mission run --help
```

A valid advanced task must reference a supplied receipt ID. The receipt must match the exact mission, task, role, tool, target, arguments, and supporting-evidence digest and must not be expired or consumed.

Receipt files and applicable GhostMCP policies must use restrictive file permissions on POSIX systems:

```bash
chmod 600 approval-receipts.json engagement-policy.json
```

Do not post receipt content publicly.

## A version banner did not become a validated finding

This is intentional. Product and version banners may create hypotheses, but they do not prove a vulnerability. Safe validation requires independent behavioral evidence.

## Release verification fails

Redownload the artifacts and `SHA256SUMS` from the same release. Then follow [verifying-releases.md](verifying-releases.md).

Do not install an artifact whose checksum or GitHub attestation fails.

## Opening a support issue

Review [SUPPORT.md](../SUPPORT.md), use the correct issue form, and attach only redacted material. A complete report includes the exact command, version, platform, expected behavior, actual behavior, and smallest authorized reproduction.

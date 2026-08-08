<p align="center">
  <img src="assets/ares-readme-banner.svg" alt="Ares - operator-supervised security assessment runtime" width="100%">
</p>

# Ares

Ares is an operator-supervised security assessment runtime for authorized engagements. It gives a model room to reason and request actions while keeping scope, risk, approvals, routing, persistence, evidence, and reporting under deterministic operator control.

Ares is designed for security practitioners who need more than a chat wrapper but do not want an unattended agent making arbitrary offensive decisions.

> Authorized testing only. Do not use Ares against systems you do not own or do not have explicit permission to assess.

## Product identity

- Product: `Ares`
- Python distribution: `bluedot-ares`
- Python import: `ares`
- Primary command: `ares`
- Current source version: `1.1.0`
- License: MIT
- Supported Python: 3.11, 3.12, and 3.13

The PyPI project named `ares` belongs to an unrelated package. Do not install it expecting this project. Install `bluedot-ares` in an isolated environment.

## What Ares provides

Ares combines four execution paths behind the same policy and evidence model:

| Path | Purpose | Model authority |
| --- | --- | --- |
| `ares run` | Supervised model and tool loop for a bounded task | May request registered tools, subject to dispatcher policy |
| Deterministic missions | Repeatable source, dependency, secret, and report workflows | No model-authored task graph |
| Governed autonomous reconnaissance | Evidence-driven attack-surface coverage | May select only exact Ares-issued coverage IDs |
| Authorized operator validation | Explicit advanced validation from an operator-supplied graph | Model cannot select advanced tasks |

The runtime includes:

- OpenAI-compatible, Anthropic, and Gemini model adapters
- provider fallback chains and OAuth helpers
- a central tool registry with availability, schema, risk, and toolset metadata
- dispatcher-owned scope, rules of engagement, risk, approval, duplicate, route, and timeout enforcement
- governed autonomous reconnaissance with a persistent attack-surface graph and coverage ledger
- a finding lifecycle from observation through corroboration, safe validation, and reporting
- evidence-bound, single-use approval receipts for advanced operator validation
- SQLite state for sessions, messages, tool calls, hosts, services, missions, findings, and memory
- GhostMCP and bounded OnionClaw integrations
- Markdown session and mission reports
- separate gateway, dashboard, and terminal operator surfaces

## Install

The recommended end-user installation is an isolated application environment:

```bash
pipx install bluedot-ares
# or
uv tool install bluedot-ares
```

Until the first `bluedot-ares` PyPI release is published, install the matching wheel from the GitHub release or use the source installation path in [INSTALL.md](INSTALL.md).

Verify the install:

```bash
ares --version
ares doctor
ares doctor --json
```

Optional provider and tool integrations remain extras:

```bash
pipx install 'bluedot-ares[anthropic]'
pipx install 'bluedot-ares[gemini]'
pipx install 'bluedot-ares[ghostmcp]'
```

See [INSTALL.md](INSTALL.md) for upgrades, source installs, Windows notes, and migration from the older GitHub wheel.

## Five-minute start

Run the guided setup:

```bash
ares onboard
```

For a local OpenAI-compatible model server:

```bash
export LLM_PROVIDER="local"
export LLM_MODEL="local-model"
export OPENAI_BASE_URL="http://127.0.0.1:1234/v1"
export OPENAI_API_KEY="lm-studio"
```

Check the selected route without executing tools:

```bash
ares route \
  --target 127.0.0.1 \
  --prompt "Enumerate the authorized loopback target and stop after useful initial findings."
```

Run a bounded loopback assessment:

```bash
ares run \
  --target 127.0.0.1 \
  --prompt "Enumerate the authorized loopback target and stop after useful initial findings." \
  --max-iterations 20
```

Higher-risk actions are denied by default. `--approve-dangerous` satisfies only the dispatcher approval gate. Scope, risk, route, and tool policy still run before execution.

The full walkthrough is in [docs/quickstart.md](docs/quickstart.md).

## Governed autonomous reconnaissance

The `autonomous-recon` mission profile allows a model to prioritize reconnaissance work without giving it arbitrary tool or target construction authority.

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

Ares persists each attack-surface node, relationship, coverage item, planner decision, tool result, recovery attempt, finding hypothesis, and limitation. The planner can choose only from exact coverage IDs compiled by Ares into fixed tools, targets, and arguments.

This path performs passive and safe-active reconnaissance. It does not perform exploitation, authentication attempts, persistence, or arbitrary command execution.

## Authorized operator validation

Advanced validation uses an explicit operator-supplied task graph. It requires same-mission evidence, a GhostMCP engagement policy where applicable, an immutable approval receipt bound to the exact task digest, and an out-of-model approval.

```bash
ares mission run \
  --profile authorized-operator-validation \
  --mission-id engagement-2026-001 \
  --target 192.0.2.10 \
  --allowed-host 192.0.2.10 \
  --max-risk post-exploitation \
  --initial-tasks tasks.json \
  --ghostmcp-policy engagement-policy.json \
  --approval-receipts approval-receipts.json \
  --approve-high-risk
```

The model never selects advanced-role tasks. Failed, empty, cross-target, cross-mission, expired, replayed, or contract-mismatched evidence and receipts fail closed.

## Operator surfaces

### Gateway

The gateway is the backend API and control plane for authentication, pairing, allowlists, run submission, run status, event polling, and audit logging.

```bash
ares gateway-config --mode loopback
ares gateway
```

Remote exposure should use bearer authentication and a CIDR allowlist:

```bash
ares gateway-config \
  --mode exposed \
  --auth-enabled \
  --allow-cidr 203.0.113.0/24
```

### Dashboard

The dashboard is the browser frontend backed by the gateway:

```bash
ares dashboard
# or
ares-dashboard
```

For a remote server:

```bash
ares dashboard --mode lan --no-open
```

### Terminal UI

```bash
ares tui
# or
ares-tui
```

The gateway, dashboard, and TUI are separate product surfaces even when the gateway serves bundled dashboard assets.

## Diagnostics and support

Machine-readable diagnostics:

```bash
ares doctor --json
```

Create a redacted support bundle that excludes credentials and engagement evidence:

```bash
ares support-bundle --out ares-support-bundle.json
```

Read [SUPPORT.md](SUPPORT.md) before opening an issue. Installation and runtime failures are covered in [docs/troubleshooting.md](docs/troubleshooting.md).

## Release verification

Official releases include:

- wheel and source distribution
- `SHA256SUMS`
- CycloneDX SBOM
- release metadata
- GitHub build provenance and SBOM attestations

Verification commands are documented in [docs/verifying-releases.md](docs/verifying-releases.md).

## Architecture

The model does not call tools directly. Ares converts a model request or mission decision into a dispatcher request, validates it against policy and authorization state, records the result, indexes evidence, and then renders operator-visible state and reports.

See [docs/architecture.md](docs/architecture.md) and [docs/v1-support-boundary.md](docs/v1-support-boundary.md) for the supported contract.

## Development

```bash
git clone https://github.com/BlueDot-IT/Ares.git
cd Ares
git submodule update --init --recursive

python -m venv .venv
. .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -e '.[dev,anthropic,gemini,ghostmcp]' -e vendor/ghostmcp

python -m pytest tests -q
python -m compileall src/ares
python -m build
python -m twine check dist/*
```

Contribution requirements are in [CONTRIBUTING.md](CONTRIBUTING.md).

## Documentation

- [Installation](INSTALL.md)
- [Quickstart](docs/quickstart.md)
- [Mission CLI](docs/mission-cli.md)
- [Architecture](docs/architecture.md)
- [Troubleshooting](docs/troubleshooting.md)
- [Release verification](docs/verifying-releases.md)
- [Support boundary](docs/v1-support-boundary.md)
- [Security policy](SECURITY.md)
- [Support policy](SUPPORT.md)
- [Changelog](CHANGELOG.md)

## License

Ares is released under the MIT License.

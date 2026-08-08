# Ares Quickstart

This walkthrough keeps the first run on an authorized loopback target.

## 1. Install

Use an isolated application environment:

```bash
pipx install bluedot-ares
# or
uv tool install bluedot-ares
```

The PyPI project named `ares` is unrelated. The official Ares distribution is `bluedot-ares`.

## 2. Run onboarding

```bash
ares onboard
```

The wizard configures a model provider, authentication path, UI theme, gateway exposure mode, and hook defaults under `~/.ares`.

For model-only setup:

```bash
ares model --interactive
```

## 3. Configure a local OpenAI-compatible server

A local server is the lowest-risk first test path:

```bash
export LLM_PROVIDER="local"
export LLM_MODEL="local-model"
export OPENAI_BASE_URL="http://127.0.0.1:1234/v1"
export OPENAI_API_KEY="lm-studio"
```

The placeholder API key is used only because OpenAI-compatible clients commonly require a non-empty value. Do not reuse a real cloud key for a local server.

## 4. Run preflight diagnostics

```bash
ares --version
ares doctor
ares doctor --json
```

`ares doctor` reports configuration and registered tool availability. It does not install missing external tools.

## 5. Preview routing

```bash
ares route \
  --target 127.0.0.1 \
  --prompt "Enumerate the authorized loopback target and stop after useful initial findings."
```

This previews the selected agent profile and model configuration without dispatching a security tool.

## 6. Run a bounded assessment

```bash
ares run \
  --target 127.0.0.1 \
  --prompt "Enumerate the authorized loopback target and stop after useful initial findings." \
  --max-iterations 20
```

The target is also the dispatcher scope boundary. Network arguments must remain inside the declared host scope. Filesystem arguments must remain beneath a declared path target. Opaque raw arguments fail closed.

Do not add `--approve-dangerous` to the first run.

## 7. Inspect state and produce a report

```bash
ares sessions
ares report <session-id>
```

Reports are written under `~/.ares/reports` unless an output directory is supplied.

## 8. Open an operator surface

Browser dashboard:

```bash
ares dashboard
```

Terminal UI:

```bash
ares tui
```

The dashboard and TUI are clients of the same runtime and state model. The gateway remains the API and control plane.

## 9. Try a dry-run mission

Use a local authorized source tree:

```bash
ares mission run \
  --profile source-code-audit \
  --target "$PWD" \
  --allowed-path "$PWD" \
  --max-risk scan \
  --dry-run
```

Dry run validates the mission and prints the planned tasks without executing them.

## 10. Create a support bundle when something fails

```bash
ares support-bundle --out ares-support-bundle.json
```

The bundle contains runtime and doctor diagnostics. It excludes credentials and engagement evidence. Review local paths and provider details before sharing it.

## Next steps

- [Mission CLI](mission-cli.md)
- [Architecture](architecture.md)
- [Troubleshooting](troubleshooting.md)
- [Support boundary](v1-support-boundary.md)
- [Release verification](verifying-releases.md)

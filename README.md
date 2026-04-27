# Ares

Ares is an autonomous pentesting runtime for authorized engagements that combines Hermes-style agent execution with OpenClaw-style operator control.

Concretely, the current system already includes:

- multi-provider agent execution with native Anthropic and Gemini adapters plus OpenAI-compatible endpoints under one shared runtime
- a central ToolRegistry and GhostMCP integration layer so tools are exposed through one model-facing contract instead of provider-specific glue
- dispatcher-owned policy enforcement for scope, ROE, risk, approval gates, duplicate suppression, timeouts, and route selection outside the model
- operator-facing control surfaces including a Typer CLI, Hermes-style prompt_toolkit/Rich TUI, lightweight HTTP gateway, event stream, session persistence, and report generation
- pentest-specific state handling for hosts, services, tool calls, evidence normalization, and Markdown reporting

That is the intended shape of Ares: the best operational ideas from Hermes and OpenClaw, narrowed onto authorized pentesting rather than general-purpose agent work.

Release status: `0.1.0a0` with git tag `v0.1.0-alpha`. This release is intended for controlled lab use and explicitly authorized testing. It is an alpha foundation for that direction, not yet a finished production pentest platform.

Repository layout:

- `src/ares` - primary package, runtime core, CLI, and TUI
- `src/lib`, `src/ui`, `src/main.py` - legacy GUI and compatibility components still present during cleanup

The runtime now lives directly under the `ares` package.

Authorized testing only. Do not use this against systems you do not own or do not have explicit permission to test.

## Current capabilities

Implemented and wired into the current runtime:

- OpenAI-compatible model adapter for LM Studio, llama.cpp server, vLLM, Ollama-compatible endpoints, OpenRouter, and OpenAI-style APIs
- Native Anthropic adapter with tool-use translation into the runtime's shared tool-call format
- Native Gemini adapter with function-calling translation into the runtime's shared tool-call format
- Central `ToolRegistry` with model-facing schemas, availability checks, risk levels, and toolset metadata
- GhostMCP adapter with legacy fallback runner support
- Dispatcher-enforced scope, risk, approval, duplicate-suppression, timeout, and route policy outside the model
- ROE profiles:
  - `passive`
  - `safe-active`
  - `intrusive`
  - `exploit-validate`
- SQLite persistence for sessions, messages, tool calls, hosts, and services
- Normalized Nmap evidence parsing into hosts and services
- Markdown report rendering from the StateDB
- Lightweight HTTP gateway for background runs, run status, event streaming, web operator views, exposed-mode auth, pairing codes, CIDR allowlists, and JSONL audit events
- Python hook loading for session automation, auto-report generation, built-in lifecycle hooks, and engagement-memory capture
- Multi-agent routing with agent profiles, route selection, prompt prefixes, memory tags, route preview, and per-agent tool visibility
- Guided onboarding for provider selection, auth mode, theme, gateway exposure, and hook defaults
- Cached OAuth helpers for supported model providers, currently Gemini/Google OAuth
- Hermes-style prompt_toolkit/Rich TUI with chat-first transcript, slash commands, theme colors, transcript scrollback, `/scope` public/private target toggling, and curses fallback when prompt_toolkit is unavailable

## Install

```bash
git clone https://github.com/jason-allen-oneal/ares.git
cd ares
git submodule update --init --recursive

python -m venv .venv
. .venv/bin/activate
python -m pip install -e .
```

Optional extras:

```bash
python -m pip install -e '.[gui]'
python -m pip install -e '.[anthropic]'
python -m pip install -e '.[gemini]'
python -m pip install -e '.[ghostmcp]'
```

## CLI

Primary commands:

```bash
ares --version
ares doctor
ares tools
ares sessions
ares tui
```

Compatibility alias still works:

```bash
ares --version
```

Run a safe-active task against an authorized local target:

```bash
export ARES_OPENAI_BASE_URL="http://127.0.0.1:1234/v1"
export ARES_LLM_MODEL="local-model"

ares run \
  --target 127.0.0.1 \
  --prompt "Enumerate the target and stop after useful initial findings." \
  --max-iterations 20
```

Render a stored report:

```bash
ares report <session-id>
```

Dangerous actions are denied by default. Inside an explicit authorized ROE, use:

```bash
ares run --target 127.0.0.1 --approve-dangerous --prompt "..."
```

`--approve-dangerous` only satisfies dispatcher approval gates. Scope and risk policy still run before execution.

## Onboarding and provider setup

Run the guided first-run setup when you want Ares to persist model, theme, gateway, and hook defaults without hand-editing config:

```bash
ares onboard
```

The onboarding flow uses a menu in a real terminal and numbered choices in scripted/non-TTY runs. It writes to `~/.ares/config.json` by default, or to `$ARES_HOME/config.json` when `ARES_HOME` is set.

For model-only setup, use the shared model wizard:

```bash
ares model --interactive
```

The current provider choices are:

- `local` - OpenAI-compatible local server, defaulting to `http://127.0.0.1:1234/v1`, with the endpoint editable
- `openai` - OpenAI cloud, defaulting to `gpt-4.1-mini` and `https://api.openai.com/v1`, with the endpoint hidden in normal setup
- `openrouter` - OpenRouter cloud, defaulting to `openai/gpt-4o-mini` and `https://openrouter.ai/api/v1`, with the endpoint hidden in normal setup
- `anthropic` - native Anthropic adapter, no OpenAI-compatible endpoint prompt
- `gemini` - native Gemini adapter, no OpenAI-compatible endpoint prompt, supports API key or OAuth
- `custom` - operator-provided OpenAI-compatible endpoint and model

Only Gemini currently has a built-in OAuth broker. OpenAI, OpenRouter, Anthropic, local, and custom OpenAI-compatible profiles remain API-key based unless a real provider-specific OAuth broker is added.

Manage cached OAuth credentials with:

```bash
ares auth login --provider gemini
ares auth status
ares auth status --provider gemini
ares auth logout --provider gemini
```

Gemini OAuth caches token metadata under `~/.ares/oauth/`. It uses an installed-app browser flow when `ARES_GOOGLE_OAUTH_CLIENT_SECRETS` or `GOOGLE_OAUTH_CLIENT_SECRETS` points to a Google client secrets file. Otherwise it falls back to Google application default credentials. See `docs/onboarding.md` for the full provider and auth matrix.

## TUI

Launch the terminal UI:

```bash
ares tui
```

The TUI is the primary operator shell. It now uses a Hermes-style `prompt_toolkit` input loop with Rich/prompt_toolkit styling and keeps the original curses loop only as an import-time fallback. The full ASCII Ares banner is preserved; the live transcript is chat-first and uses compact top chrome so tool calls, tool results, and model responses remain visible.

Inside the TUI, type normal instructions to launch a run, or use slash commands:

```text
/commands          show the full command list
/target <target>   set the default authorized target
/scope public      allow authorized public targets in this TUI process
/scope private     return to private/loopback target scope only
/yolo              toggle dangerous-tool approval for new runs
/model             show or update provider/model/base URL
/theme             list, preview, or switch themes
/live              show current background run events
/report [id]       write a Markdown report for a session
/quit              exit
```

Useful keys:

- `PageUp` / `PageDown` scroll transcript history so earlier tool errors remain inspectable
- `Home` jumps to the oldest visible transcript output
- `End` returns to live/latest output
- `Up` / `Down` move the selected stored session
- `Ctrl-C` or `Escape` exits the TUI

Scope defaults remain conservative. Public target scanning is opt-in and process-local from the TUI:

```text
/scope public
/target 203.0.113.10
Run safe-active enumeration against this authorized VPS. Do not brute force, exploit, fuzz, or run intrusive scans.
```

Use `/scope private` when done. To make public-target scope persistent across restarts, set `ARES_ALLOW_PRIVATE_ONLY=false` in the process environment or `~/.ares/.env`.

## Config

Ares-prefixed environment variables are primary. Ares also loads simple `KEY=VALUE` entries from `~/.ares/.env` before reading config and before building model clients. Existing process environment values win for the same variable name.

```bash
export ARES_HOME="$HOME/.ares"
export ARES_LLM_PROVIDER="openai"
export ARES_LLM_MODEL="local-model"
export ARES_OPENAI_BASE_URL="http://127.0.0.1:1234/v1"
export ARES_OPENAI_API_KEY="***"
export OPENAI_API_KEY="***"  # also accepted by the OpenAI-compatible adapter
export ARES_OPENROUTER_API_KEY="***"
export ARES_ANTHROPIC_API_KEY="***"
export ARES_GEMINI_API_KEY="***"
export ARES_ROE_PROFILE="safe-active"
export ARES_DEFAULT_MODE="safe-active"
export ARES_ALLOW_PRIVATE_ONLY="true"
export ARES_MAX_RISK="active"
```

Defaults remain conservative:

- private and loopback targets only
- max risk `active`
- exploit and post-exploitation tools require approval

## Architecture map

Primary operator surface:

- `src/ares/cli.py` - primary Typer CLI
- `src/ares/tui.py` - Hermes-style prompt_toolkit/Rich TUI shell with curses fallback
- `src/ares/*` - user-facing compatibility wrappers over the runtime core

Runtime core:

- `src/ares/config` - env/config loader
- `src/ares/policy` - scope, risk, route, and ROE policy
- `src/ares/tools` - central registry and GhostMCP adapter
- `src/ares/agent` - prompt builder, context builder, dispatcher, runtime loop
- `src/ares/llm` - model adapters
- `src/ares/playbooks` - built-in playbooks
- `src/ares/state` - SQLite persistence
- `src/ares/evidence` - evidence parsers
- `src/ares/reporting` - Markdown reports
- `src/ares/run.py` - high-level runtime wiring

## Legacy GUI

The old GUI remains available during transition:

```bash
. .venv/bin/activate
python src/main.py
```

## Tests

Use the project test tree rather than bare repository-wide collection if vendored test packaging is not installed:

```bash
python -m pytest tests -q
python -m compileall src/ares
```

Targeted checks for onboarding/auth work:

```bash
python -m pytest tests/test_prompt_ui.py -q
python -m pytest tests/test_oauth_flows.py -q
python -m pytest tests/test_onboard_cli.py tests/test_cli_model.py tests/test_model_config.py tests/test_llm_provider_adapters.py tests/test_cli_auth.py -q
```

## Release guidance

Ares should still be treated as a controlled-lab alpha. Keep human oversight in place, keep scopes explicit, and keep exploit and post-exploitation approvals outside the model.

The `0.1.0a0` line is suitable for alpha releases, internal testing, and reproducible packaged builds. The intended direction is to make Ares the strongest blend of Hermes-style agent execution and OpenClaw-style operator control for authorized pentesting, but this release should still be described as an early alpha rather than a finished general-purpose platform.

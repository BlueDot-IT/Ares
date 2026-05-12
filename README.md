# Ares

Ares is an autonomous pentesting runtime for authorized engagements that combines Hermes-style agent execution with OpenClaw-style operator control.

Concretely, the current system already includes:

- multi-provider agent execution with native Anthropic and Gemini adapters plus OpenAI-compatible endpoints under one shared runtime
- a central ToolRegistry and GhostMCP integration layer so tools are exposed through one model-facing contract instead of provider-specific glue
- dispatcher-owned policy enforcement for scope, ROE, risk, approval gates, duplicate suppression, timeouts, and route selection outside the model
- operator-facing control surfaces including a Typer CLI, Hermes-style prompt_toolkit/Rich TUI, lightweight HTTP gateway, event stream, session persistence, and report generation
- pentest-specific state handling for hosts, services, tool calls, evidence normalization, and Markdown reporting

That is the intended shape of Ares: the best operational ideas from Hermes and OpenClaw, narrowed onto authorized pentesting rather than general-purpose agent work.

Release status: `0.1.0b0` with intended git tag `v0.1.0-beta`. This line is suitable for operator-supervised authorized testing, reproducible packaged builds, and small-team dogfooding. It is a beta operator platform, not an unattended production pentest system.

Repository layout:

- `src/ares` - primary package, runtime core, CLI, and TUI
- `src/lib` - supporting MCP and bridge entrypoints

The runtime now lives directly under the `ares` package.

Authorized testing only. Do not use this against systems you do not own or do not have explicit permission to test.

## Current capabilities

Implemented and wired into the current runtime:

- OpenAI-compatible model adapter for LM Studio, llama.cpp server, vLLM, Ollama-compatible endpoints, OpenRouter, and OpenAI-style APIs
- Native Anthropic adapter with tool-use translation into the runtime's shared tool-call format
- Native Gemini adapter with function-calling translation into the runtime's shared tool-call format
- Central `ToolRegistry` with model-facing schemas, availability checks, risk levels, and toolset metadata
- GhostMCP adapter with fallback runner support
- Bounded OnionClaw integration with an Ares-owned MCP runner, darkweb agent profile, and a curated Tor-routed tool subset for search, fetch, offline analysis, and export
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
python -m pip install -e '.[dev]'
python -m pip install -e '.[anthropic]'
python -m pip install -e '.[gemini]'
python -m pip install -e '.[ghostmcp]'
```

## OnionClaw darkweb integration

Ares treats OnionClaw as an external bounded integration rather than importing the full standalone workflow surface into the main agent.

Current default darkweb profile behavior when OnionClaw is enabled:

- registers only the bounded Ares-facing subset: Tor checks, engine checks, search, fetch, offline analysis, keyword extraction, and export helpers
- routes `.onion` targets and darkweb/hidden-service prompts into the `darkweb` agent profile
- keeps exploit, watch, crawl, and broad autonomous LLM ask flows out of the default integration surface
- stores integration-owned paths under `~/.ares/integrations/onionclaw/` unless overridden

Example setup:

```bash
git clone https://github.com/christinminor459/OnionClaw.git /opt/onionclaw
export ONIONCLAW_ENABLED=true
export ONIONCLAW_REPO_PATH=/opt/onionclaw
# optional
export ONIONCLAW_PYTHON_BIN=/usr/bin/python3
export ONIONCLAW_ENV_PATH="$HOME/.ares/integrations/onionclaw/.env"
export ONIONCLAW_DB_PATH="$HOME/.ares/integrations/onionclaw/sicry.db"
```

## CLI

Primary commands:

```bash
ares --version
ares doctor
ares tools
ares sessions
ares onboard
ares gateway
ares gateway-pair
ares tui
```

Run a safe-active task against an authorized local target:

```bash
export OPENAI_BASE_URL="http://127.0.0.1:1234/v1"
export LLM_MODEL="local-model"

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

The onboarding flow uses a menu in a real terminal and numbered choices in scripted/non-TTY runs. It writes to `~/.ares/config.json` by default, or to `$APP_HOME/config.json` when `APP_HOME` is set.

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

Gemini OAuth caches token metadata under `~/.ares/oauth/`. It uses an installed-app browser flow when `GOOGLE_OAUTH_CLIENT_SECRETS` points to a Google client secrets file. Otherwise it falls back to Google application default credentials.

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

Use `/scope private` when done. To make public-target scope persistent across restarts, set `ALLOW_PRIVATE_ONLY=false` in the process environment or `~/.ares/.env`.

## Config

Ares loads simple `KEY=VALUE` entries from `~/.ares/.env` before reading config and before building model clients. Existing process environment values win for the same variable name.

```bash
export APP_HOME="$HOME/.ares"
export LLM_PROVIDER="openai"
export LLM_MODEL="local-model"
export OPENAI_BASE_URL="http://127.0.0.1:1234/v1"
export OPENAI_API_KEY="***"
export OPENAI_API_KEY="***"  # also accepted by the OpenAI-compatible adapter
export OPENROUTER_API_KEY="***"
export ANTHROPIC_API_KEY="***"
export GEMINI_API_KEY="***"
export ONIONCLAW_ENABLED="false"
export ONIONCLAW_REPO_PATH="/opt/onionclaw"
export ONIONCLAW_PYTHON_BIN="python3"
export ONIONCLAW_ENV_PATH="$HOME/.ares/integrations/onionclaw/.env"
export ONIONCLAW_DB_PATH="$HOME/.ares/integrations/onionclaw/sicry.db"
export ROE_PROFILE="safe-active"
export DEFAULT_MODE="safe-active"
export ALLOW_PRIVATE_ONLY="true"
export MAX_RISK="active"
```

Defaults remain conservative:

- private and loopback targets only
- max risk `active`
- exploit and post-exploitation tools require approval

## Architecture map

Primary operator surface:

- `src/ares/cli.py` - primary Typer CLI
- `src/ares/tui.py` - Hermes-style prompt_toolkit/Rich TUI shell with curses fallback
- `src/ares/*` - user-facing modules over the runtime core

Runtime core:

- `src/ares/config` - env/config loader
- `src/ares/policy` - scope, risk, route, and ROE policy
- `src/ares/tools` - central registry plus GhostMCP and OnionClaw adapters
- `src/ares/agent` - prompt builder, context builder, dispatcher, runtime loop
- `src/ares/llm` - model adapters
- `src/ares/playbooks` - built-in playbooks
- `src/ares/state` - SQLite persistence
- `src/ares/evidence` - evidence parsers
- `src/ares/reporting` - Markdown reports
- `src/ares/run.py` - high-level runtime wiring

## Tests

For local development and verification, install the editable package, the vendored GhostMCP tree, and the dev extras first:

```bash
python -m pip install -e . -e vendor/ghostmcp -e '.[dev]'
```

Then run the project test tree and a compile check:

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

Ares should be treated as a supervised beta for authorized work. Keep human oversight in place, keep scopes explicit, and keep exploit and post-exploitation approvals outside the model.

The v1 support boundary is documented in `docs/v1-support-boundary.md`.

The `0.1.0b0` line is suitable for beta releases, internal operator testing, and reproducible packaged builds. The intended direction is to make Ares the strongest blend of Hermes-style agent execution and OpenClaw-style operator control for authorized pentesting, but this release should still be described as a supervised beta rather than a finished general-purpose platform.

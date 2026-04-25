# Ares

Ares is a Hermes-style autonomous penetration testing runtime for authorized engagements.

Release status: `0.1.0-alpha`. This release is intended for controlled lab use and explicitly authorized testing, not as a production pentest replacement.

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
- Lightweight HTTP gateway for background runs, run status, and event streaming
- Python hook loading for session automation and auto-report generation
- Multi-agent routing with agent profiles, route selection, and per-agent tool visibility
- New curses-based TUI for dashboard, sessions, doctor view, tool inventory, run launching, and report writing

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

## TUI

Launch the terminal UI:

```bash
ares tui
```

Current keybindings:

- `d` dashboard
- `s` sessions
- `t` tools
- `o` doctor
- `n` prompt for and launch a new run
- `p` write a Markdown report for a selected session
- `j` / `k` move session selection
- `r` refresh
- `q` quit

The TUI is deliberately minimal and stable-first right now. It is a control room for the runtime, not yet a rich multi-pane live event stream.

## Config

Ares-prefixed environment variables are now primary. Legacy `ARES_*` names still work as fallbacks.

```bash
export ARES_HOME="$HOME/.ares"
export ARES_LLM_PROVIDER="openai"
export ARES_LLM_MODEL="local-model"
export ARES_OPENAI_BASE_URL="http://127.0.0.1:1234/v1"
export ARES_OPENAI_API_KEY="***"
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
- `src/ares/tui.py` - curses TUI shell
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

```bash
python -m pytest -q
python -m py_compile src/ares/*.py src/ares/agent/*.py src/ares/config/*.py src/ares/evidence/*.py src/ares/llm/*.py src/ares/playbooks/*.py src/ares/reporting/*.py src/ares/tools/*.py src/ares/policy/*.py src/ares/state/*.py src/ares/*.py src/lib/*.py
```

## Release guidance

Ares should still be treated as a controlled-lab alpha. Keep human oversight in place, keep scopes explicit, and keep exploit and post-exploitation approvals outside the model. The `0.1.0` line is suitable for alpha releases, internal testing, and reproducible packaged builds, but it is not positioned as a general-purpose production pentest platform.

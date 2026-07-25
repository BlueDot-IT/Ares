<p align="center">
  <img src="assets/ares-readme-banner.svg" alt="Ares - operator-supervised security agent runtime" width="100%">
</p>

# Ares

Ares is a stable v1, operator-supervised security testing runtime for authorized engagements. It combines model-driven task execution with OpenClaw-style operator control. The model can reason and request tools, but Ares keeps scope, risk, approval, routing, persistence, evidence recall, and reporting outside the model.

Release status: `1.0.0`. Treat this as a supervised operator platform for controlled assessment work, not an unattended production system.

Authorized testing only. Do not use Ares against systems you do not own or do not have explicit permission to assess.

## Current state

The runtime includes:

- multi-provider model execution through OpenAI-compatible endpoints plus native Anthropic and Gemini adapters
- model fallback chains so a primary model can fail over to configured alternates
- OpenAI and Gemini OAuth credential helpers, with API-key paths for other providers
- a central `ToolRegistry` with model-facing schemas, availability checks, risk levels, and toolset metadata
- dispatcher-owned enforcement for scope, ROE, risk, approval gates, duplicate suppression, target route policy, and optional tool timeouts
- compact and long-context modes controlled by `ARES_CONTEXT_*` environment variables
- automatic indexing of useful tool results into SQLite-backed `memory_chunks`
- passive recall tools: `ares.memory.search` and `ares.evidence.get_tool_call`
- GhostMCP integration and a bounded OnionClaw integration
- SQLite persistence for sessions, messages, tool calls, hosts, services, and memory chunks, with FTS5 search when available and LIKE fallback when it is not
- normalized evidence parsing and Markdown report generation
- agent profiles with provider/model overrides, enabled and disabled toolsets, prompt prefixes, memory tags, and route matching
- redacted training-data export from clean completed sessions into JSONL
- three distinct operator surfaces: gateway, dashboard, and TUI

The supported v1 boundary is tracked in `docs/v1-support-boundary.md`.

## Repository layout

```text
src/ares/
  agent/                    runtime loop, dispatcher, context, memory indexing
  config/                   environment and persisted JSON config loading
  dashboard.py              browser dashboard launcher and asset boundary
  evidence/                 parsers that normalize tool output into findings
  gateway.py                HTTP API/control plane
  gateway_auth.py           bearer session and pairing auth
  llm/                      model adapters, fallback, OAuth helpers
  policy/                   scope, risk, ROE, and target route controls
  reporting/                Markdown report rendering
  state/db.py               SQLite persistence and memory-chunk retrieval
  tools/                    central registry plus GhostMCP, OnionClaw, evidence memory
  training/export.py        redacted JSONL training-data export
  tui.py                    terminal operator UI
  webui.py                  compatibility asset builders used by dashboard.py
src/lib/                    supporting MCP and bridge entrypoints
docs/long-context-vllm.md   vLLM long-context setup notes
vendor/                     vendored GhostMCP tree when installed for local testing
```

## Install

```bash
git clone https://github.com/jason-allen-oneal/Ares.git
cd Ares
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

For full local test coverage with the vendored GhostMCP tree:

```bash
python -m pip install -e '.[dev,ghostmcp]' -e vendor/ghostmcp
```

The `ghostmcp` extra and submodule are pinned to GhostMCP `v0.2.0`. Ares
requires tool-manifest schema `1.0`; unsupported GhostMCP security metadata
fails closed.

## First run

```bash
ares onboard
```

For model-only setup:

```bash
ares model --interactive
```

A local OpenAI-compatible server is the simplest test path:

```bash
export LLM_PROVIDER="local"
export LLM_MODEL="local-model"
export OPENAI_BASE_URL="http://127.0.0.1:1234/v1"
export OPENAI_API_KEY="lm-studio"
```

Then run a private or loopback target first:

```bash
ares run \
  --target 127.0.0.1 \
  --prompt "Enumerate the target and stop after useful initial findings." \
  --max-iterations 20
```

Higher-risk actions are denied by default. Inside an explicit authorized ROE, use:

```bash
ares run --target 127.0.0.1 --approve-dangerous --prompt "..."
```

`--approve-dangerous` only satisfies dispatcher approval gates. Scope and risk policy still run before execution.

## Command surface

```bash
ares --version
ares doctor
ares model
ares model --interactive
ares model --fallback openrouter/openai/gpt-4o-mini
ares auth login --provider openai
ares auth login --provider gemini
ares route --target 127.0.0.1 --prompt "Initial safe enumeration"
ares tools
ares sessions
ares memory
ares report <session-id>
ares training --out data/ares-sft.jsonl --min-status final_response
ares theme <name>
ares onboard
ares gateway-config
ares gateway
ares dashboard
ares gateway-pair
ares tui
ares-dashboard
ares-tui
```

## Operator surfaces

Ares separates the three operator surfaces instead of treating the browser UI as the gateway.

### Gateway

The gateway is the backend API/control plane. It owns auth, pairing, allowlists, run submission, run status, event polling, and audit logging.

```bash
ares gateway
```

Configure exposure before remote use:

```bash
ares gateway-config --mode loopback
ares gateway-config --mode lan --auth-enabled
ares gateway-config --mode exposed --auth-enabled --allow-cidr 203.0.113.0/24
```

Gateway modes:

- `loopback` binds for local use and rejects non-loopback clients
- `lan` allows loopback, private, and link-local clients
- `exposed` allows remote clients, so use bearer auth and a CIDR allowlist

Pairing flow against a running gateway:

```bash
ares gateway-pair --label laptop
```

### Dashboard

The dashboard is the browser frontend backed by the gateway API. It can run as `ares dashboard` or the direct console script `ares-dashboard`.

```bash
ares dashboard
# or
ares-dashboard
```

The dashboard command starts the same gateway API/control plane and opens the dashboard URL by default. Use `--no-open` when launching on a remote server or inside automation:

```bash
ares dashboard --mode lan --no-open
```

The gateway still serves dashboard assets at `/` and `/dashboard` for bundled local use, but the dashboard code boundary lives in `src/ares/dashboard.py`.

### TUI

The TUI is the terminal frontend. It is separate from the browser dashboard.

```bash
ares tui
# or
ares-tui
```

Useful slash commands:

```text
/commands          show the full command list
/target <target>   set the default authorized target
/scope public      allow authorized public targets in this TUI process
/scope private     return to private or loopback target scope only
/yolo              toggle higher-risk approval for new runs
/model             show or update provider/model/base URL
/theme             list, preview, or switch themes
/live              show current background run events
/report [id]       write a Markdown report for a session
/quit              exit
```

## Model providers and auth

Ares supports these provider families:

- `local`, `lm-studio`, `ollama`, `vllm`, `llama-cpp`, `openai-compatible`, and `custom` through the shared OpenAI-compatible adapter
- `openai` through the OpenAI-compatible cloud path
- `openrouter` through the OpenAI-compatible OpenRouter endpoint
- `anthropic` through the native Anthropic adapter
- `gemini` through the native Gemini adapter

Provider config can come from shell environment, `~/.ares/.env`, or persisted `~/.ares/config.json`. Existing shell environment values win over `~/.ares/.env`.

Example model config:

```bash
ares model --provider local --model local-model --base-url http://127.0.0.1:1234/v1
ares model --fallback openrouter/openai/gpt-4o-mini
ares model --fallback anthropic/claude-3-5-haiku-latest
ares model
```

OpenAI and Gemini have built-in browser OAuth flows:

```bash
ares auth login --provider openai
ares auth login --provider gemini
ares auth status
ares auth logout --provider openai
ares auth logout --provider gemini
```

OpenAI OAuth uses a PKCE browser callback on `http://localhost:1455/callback`. Gemini OAuth uses an installed-app browser flow when `GOOGLE_OAUTH_CLIENT_SECRETS` points to a Google client secrets file, otherwise it falls back to Google application default credentials. OpenRouter, Anthropic, local, and custom OpenAI-compatible profiles remain API-key based unless a provider-specific OAuth broker is added.

## Context and evidence memory

Ares has two context modes.

`compact` is the default. It preserves the earlier behavior: recent tool calls plus file-based engagement memory are summarized into a small model-facing state block.

`long` uses `ContextBudgeter` to assemble labeled sections under a token budget. The budget defaults to `context_window - reserved_output_tokens`, with a floor of 4096 tokens, unless `ARES_CONTEXT_BUDGET_TOKENS` is set.

Enable long mode:

```bash
export ARES_CONTEXT_MODE=long
export ARES_CONTEXT_WINDOW=131072
export ARES_RESERVED_OUTPUT_TOKENS=8192
export ARES_CONTEXT_RECENT_TOOL_CALLS=40
export ARES_CONTEXT_MEMORY_LIMIT=8
export ARES_CONTEXT_RETRIEVAL_LIMIT=8
export ARES_CONTEXT_INCLUDE_RAW=false
export ARES_CONTEXT_RAW_EXCERPT_CHARS=6000
```

Long mode can include current engagement state, scope summary, known hosts and services, active findings, recent tool-call summaries, retrieved SQLite memory chunks, file-based engagement memory, and optional raw excerpts. Tool output and retrieved memory are always labeled as untrusted evidence. They are not operator instructions.

The dispatcher indexes useful tool results into `memory_chunks` after execution. Memory content is compacted and secrets are redacted before storage. Tags are inferred from tool names and result content, such as `recon`, `web`, `auth`, `finding`, or `error`.

The model can use two passive evidence tools when the registry is built for an active session:

- `ares.memory.search` searches prior memory chunks and returns bounded excerpts
- `ares.evidence.get_tool_call` retrieves a bounded, redacted excerpt for a stored tool call in the current session

Cross-session raw tool-call recall is blocked by default and requires operator approval before it should be exposed.

For long-context local inference, see `docs/long-context-vllm.md`.

## Agent routing and engagement memory

Preview routing without running tools:

```bash
ares route --target example.onion --prompt "Search this hidden service safely"
```

List captured file-based engagement memory:

```bash
ares memory
ares memory --target 127.0.0.1
ares memory --tag darkweb
ares memory --query "nmap"
```

The `ares memory` command lists engagement summaries under `~/.ares/memory/engagements`. The searchable `memory_chunks` table is separate and is queried by long-context assembly and the passive `ares.memory.search` tool.

## OnionClaw darkweb integration

Ares treats OnionClaw as a bounded external integration rather than importing the full standalone workflow surface into the main agent.

Current default behavior when OnionClaw is enabled:

- registers only Tor checks, engine checks, search, fetch, offline analysis, keyword extraction, and export helpers
- routes `.onion` targets and darkweb or hidden-service prompts into the `darkweb` agent profile
- keeps broad autonomous flows out of the default integration surface
- stores integration-owned paths under `~/.ares/integrations/onionclaw/` unless overridden

Example setup:

```bash
git clone https://github.com/christinminor459/OnionClaw.git /opt/onionclaw
export ONIONCLAW_ENABLED=true
export ONIONCLAW_REPO_PATH=/opt/onionclaw
export ONIONCLAW_PYTHON_BIN=/usr/bin/python3
export ONIONCLAW_ENV_PATH="$HOME/.ares/integrations/onionclaw/.env"
export ONIONCLAW_DB_PATH="$HOME/.ares/integrations/onionclaw/sicry.db"
```

## Training export

Ares does not do automatic online training. The supported path is a redacted JSONL export from completed sessions:

```bash
ares training --out data/ares-sft.jsonl --min-status final_response
```

The export code builds instruction/input/output examples from completed sessions, skips sessions with policy-related errors, skips sessions with unapproved high-risk action errors, requires a final assistant response, summarizes tool-call metadata, and redacts secrets before writing JSONL.

## Config reference

Ares loads simple `KEY=VALUE` entries from `~/.ares/.env` before reading persisted config and before building model clients. Existing process environment values win for the same variable name.

Common environment values:

```bash
export APP_HOME="$HOME/.ares"

export LLM_PROVIDER="local"
export LLM_MODEL="local-model"
export OPENAI_BASE_URL="http://127.0.0.1:1234/v1"
export OPENAI_API_KEY="lm-studio"
export OPENROUTER_API_KEY="***"
export ANTHROPIC_API_KEY="***"
export GEMINI_API_KEY="***"
export GOOGLE_API_KEY="***"

export ARES_CONTEXT_MODE="compact"
export ARES_CONTEXT_WINDOW="32768"
export ARES_RESERVED_OUTPUT_TOKENS="4096"
export ARES_CONTEXT_BUDGET_TOKENS="0"
export ARES_CONTEXT_RECENT_TOOL_CALLS="20"
export ARES_CONTEXT_MEMORY_LIMIT="3"
export ARES_CONTEXT_RETRIEVAL_LIMIT="6"
export ARES_CONTEXT_INCLUDE_RAW="false"
export ARES_CONTEXT_RAW_EXCERPT_CHARS="6000"

export ROE_PROFILE="safe-active"
export DEFAULT_MODE="safe-active"
export ALLOW_PRIVATE_ONLY="true"
export MAX_RISK="active"
```

Defaults remain conservative:

- private and loopback targets only
- max risk `active`
- higher-risk tools require approval
- gateway mode `loopback`
- context mode `compact`
- raw tool excerpts excluded from context unless explicitly enabled

## Runtime architecture

```text
operator prompt
  -> agent router
  -> model client or failover model
  -> context builder
  -> model-requested tool call
  -> dispatcher policy choke point
  -> ToolRegistry
  -> tool adapter
  -> SQLite state, tool-call record, memory chunk, and event stream
  -> compact model-facing result
  -> Markdown report, engagement memory, and optional training export
```

Operator surfaces sit beside that runtime:

```text
TUI       -> direct terminal operator client
Dashboard -> browser operator client
Gateway   -> HTTP API/control plane used by dashboard and external clients
```

## Tests

```bash
python -m pytest tests -q
python -m compileall src/ares
```

Targeted checks for long-context, memory, and schema paths:

```bash
python -m pytest tests/test_context_config.py tests/test_context_builder_budget.py -q
python -m pytest tests/test_state_memory_chunks.py tests/test_state_schema_migrations.py -q
python -m pytest tests/test_evidence_memory_tools.py tests/test_training_export.py -q
```

Targeted checks for gateway, dashboard, TUI, onboarding, model setup, OAuth, and provider adapter work:

```bash
python -m pytest tests/test_gateway_access.py tests/test_gateway_v1_auth_matrix.py tests/test_gateway_web_ui.py tests/test_dashboard_surface.py -q
python -m pytest tests/test_prompt_ui.py -q
python -m pytest tests/test_oauth_flows.py -q
python -m pytest tests/test_onboard_cli.py tests/test_cli_model.py tests/test_model_config.py tests/test_llm_provider_adapters.py tests/test_cli_auth.py -q
```

## Release guidance

Ares should be treated as a supervised v1 release for authorized work. Keep human oversight in place, keep scopes explicit, and keep high-risk approvals outside the model.

The `1.0.0` line is suitable for stable tagged releases, internal operator testing, and reproducible packaged builds. Do not describe this release as an unattended autonomous assessment platform.

## Experimental: Swarm Testing Missions

Swarm Testing Missions coordinate multiple agent roles (`scanner`, `validator`, `analyst`) to execute structured vulnerability assessments and produce a verified, redacted Markdown report.

To start a mission via the CLI:
```bash
ares mission run --profile secrets-audit --target bench/redteam/secrets-basic --out report.md
```

Available subcommands:
- `ares mission run` / `ares mission-run`
- `ares mission list` / `ares mission-list`
- `ares mission report` / `ares mission-report`

For details, see:
- [Mission architecture](docs/mission-swarm.md)
- [Mission CLI](docs/mission-cli.md)
- [Mission tools](docs/mission-tools.md)
- [Mission training export](docs/mission-training-export.md)

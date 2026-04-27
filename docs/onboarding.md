# Ares onboarding and model auth

Ares now has a guided first-run setup path for model provider selection, theme, gateway exposure, and hook defaults. The goal is to avoid raw config editing and avoid asking for values that Ares already knows.

## First-run setup

Run:

```bash
ares onboard
```

The flow writes JSON config under `~/.ares/config.json` by default, or under the directory set with `ARES_HOME`.

The onboarding flow covers:

- model profile and model name
- auth mode when the selected provider supports more than one mode
- theme, defaulting to the configured Ares theme
- gateway mode: `loopback`, `lan`, or `exposed`
- gateway bearer auth and allowlist settings for exposed mode
- auto-report hook defaults

In a real terminal, profile and gateway choices are presented as a menu. In scripted or non-TTY runs, the same prompts accept numbered choices so tests and automation remain deterministic.

## Provider choices

The model setup engine is backed by `src/ares/llm/provider_catalog.py`. Current choices are:

| Choice | Runtime provider | Default model | Endpoint behavior | Auth methods |
| --- | --- | --- | --- | --- |
| `local` | `openai` | `local-model` | Defaults to `http://127.0.0.1:1234/v1` and remains editable | API key |
| `openai` | `openai` | `gpt-4.1-mini` | Uses `https://api.openai.com/v1`; hidden in normal onboarding | API key |
| `openrouter` | `openrouter` | `openai/gpt-4o-mini` | Uses `https://openrouter.ai/api/v1`; hidden in normal onboarding | API key |
| `anthropic` | `anthropic` | `claude-3-7-sonnet-latest` | Native adapter, no OpenAI-compatible endpoint prompt | API key |
| `gemini` | `gemini` | `gemini-2.5-pro` | Native adapter, no OpenAI-compatible endpoint prompt | API key or OAuth |
| `custom` | `custom` | `custom-model` | Requires an operator-provided OpenAI-compatible base URL | API key |

Only Gemini currently exposes a built-in OAuth flow. Other providers stay on API-key auth unless a real broker is added for them.

## Model-only setup

To configure only the model profile without gateway and hook prompts, run:

```bash
ares model --interactive
```

Non-interactive updates still work:

```bash
ares model --profile openai --model gpt-4.1-mini
ares model --profile openrouter --model openai/gpt-4o-mini
ares model --provider openai --model local-model --base-url http://127.0.0.1:1234/v1
```

## OAuth commands

OAuth credentials are cached under `~/.ares/oauth/` by default. The cache stores token metadata and expiry so Ares can reuse unexpired tokens without prompting again.

Check status:

```bash
ares auth status
ares auth status --provider gemini
```

Login:

```bash
ares auth login --provider gemini
```

Logout:

```bash
ares auth logout --provider gemini
```

Gemini OAuth uses Google credentials. If `ARES_GOOGLE_OAUTH_CLIENT_SECRETS` or `GOOGLE_OAUTH_CLIENT_SECRETS` points at an installed-app client secrets file, Ares starts a browser login flow through `google-auth-oauthlib`. Without that file, Ares falls back to Google application default credentials through `google-auth`.

Install Gemini OAuth dependencies before using this path:

```bash
python -m pip install -e '.[gemini]'
python -m pip install google-auth google-auth-oauthlib
```

The legacy `oauth_token_command` path still exists as a fallback for environments that already have a command which prints a fresh access token.

## Environment variables

API-key auth uses the existing provider-specific environment variables:

```bash
export ARES_OPENAI_API_KEY="..."
export ARES_OPENROUTER_API_KEY="..."
export ARES_ANTHROPIC_API_KEY="..."
export ARES_GEMINI_API_KEY="..."
```

For local OpenAI-compatible servers that do not require a real key, use a placeholder if the upstream client requires one.

## Gateway settings from onboarding

`ares onboard` can persist gateway exposure settings. You can also inspect or update them directly:

```bash
ares gateway-config
ares gateway-config --mode loopback
ares gateway-config --mode lan
ares gateway-config --mode exposed --auth-enabled --operator-token 'change-me' --allow-cidr 203.0.113.0/24
```

Mode semantics:

- `loopback`: local clients only
- `lan`: loopback plus private, link-local, and local IPv6 clients
- `exposed`: remote clients allowed, with bearer auth strongly recommended

When auth is enabled in exposed mode, use the web login flow or a pairing code from a trusted local operator session. If you explicitly run exposed mode without auth, CLI status output prints a warning because remote clients can reach the control plane unauthenticated.

## Local file privacy

Ares writes secret-bearing local files with private permissions on normal Unix filesystems:

- `~/.ares/config.json`: `0600`, because it can contain the gateway operator token
- `~/.ares/oauth/*.json`: `0600`, because it can contain OAuth access and refresh tokens
- `~/.ares/gateway-audit.jsonl`: `0600`, because it can contain client addresses, targets, and operator actions
- `~/.ares/memory/engagements/session-*.json`: `0600`, because it can contain target names and engagement summaries

Provider keys used for OAuth cache filenames are constrained to safe local identifiers, such as `gemini`, so untrusted provider input cannot write outside the OAuth cache directory.

## Verification

Useful local checks after changing onboarding or auth code:

```bash
python -m pytest tests/test_prompt_ui.py -q
python -m pytest tests/test_oauth_flows.py -q
python -m pytest tests/test_onboard_cli.py tests/test_cli_model.py tests/test_model_config.py tests/test_llm_provider_adapters.py tests/test_cli_auth.py -q
python -m pytest tests -q
python -m compileall src/ares
```

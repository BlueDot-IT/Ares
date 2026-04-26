# Onboarding UX and OAuth Refresh Implementation Plan

> **For Hermes:** Use subagent-driven-development skill to implement this plan task-by-task.

**Goal:** Replace Ares' painful text-prompt onboarding with a guided menu-driven setup that auto-fills known endpoints, exposes only meaningful choices, and supports real OAuth login flows for providers that actually support OAuth.

**Architecture:** Keep the runtime/provider adapters intact and improve the operator experience around them. Introduce a provider capability catalog, a reusable interactive prompt/menu layer, and an OAuth broker that can run browser/device-style logins and cache tokens. Refactor `ares onboard` and `ares model --interactive` to share one onboarding engine instead of duplicating prompt logic.

**Tech Stack:** Python 3.11+, Typer CLI, curses for TTY selection UI, stdlib `webbrowser`/`http.server` where practical, existing `openai`, optional `google-genai`, optional `google-auth` / `google-auth-oauthlib`, JSON config under `~/.ares/config.json`, token cache under `~/.ares/oauth/`.

---

## Evidence from the current codebase

Current pain points already visible in the repo:
- `src/ares/cli.py` duplicates onboarding/model-wizard logic and relies on raw `typer.prompt(...)` string entry for almost everything.
- `src/ares/cli.py` asks for `OpenAI-compatible base URL` even when the provider/profile already implies the correct endpoint.
- `src/ares/llm/oauth.py` is only a thin wrapper around a shell token command. It is not a real login flow.
- `src/ares/config/loader.py` has model profiles, but those profiles are only `{provider, model, openai_base_url}` and do not describe UX labels, auth capabilities, or whether an endpoint should be hidden/locked.
- Tests cover current scripted prompts, but there is no reusable menu/select abstraction and no browser/device OAuth test surface.

Design constraints:
- Preserve scripted/non-interactive testability.
- Do not require a GUI dependency just for onboarding.
- Avoid asking the operator to type values Ares can already infer.
- Only expose OAuth for providers/endpoints where we have an actual supported flow. Keep API-key auth for the rest.

---

## Scope chosen for this refresh

1. A menu-based onboarding UI with arrow-key or numbered-choice selection
2. Provider/profile catalog with labels, known endpoints, endpoint visibility rules, and auth capabilities
3. One shared onboarding engine for both `ares onboard` and `ares model --interactive`
4. Real OAuth login broker for supported providers
5. Token cache, auth status, login/logout CLI helpers
6. Updated docs and tests

---

## Files expected to change

Core onboarding/config:
- Modify: `src/ares/cli.py`
- Modify: `src/ares/config/loader.py`
- Modify: `src/ares/llm/openai_compat.py`
- Modify: `src/ares/llm/gemini_adapter.py`
- Modify: `src/ares/llm/__init__.py`
- Modify: `README.md`

New support modules:
- Create: `src/ares/onboarding.py`
- Create: `src/ares/prompt_ui.py`
- Create: `src/ares/llm/provider_catalog.py`
- Create: `src/ares/llm/oauth_cache.py`
- Create: `src/ares/llm/oauth_flows.py`

Tests:
- Create: `tests/test_prompt_ui.py`
- Create: `tests/test_oauth_flows.py`
- Modify: `tests/test_onboard_cli.py`
- Modify: `tests/test_cli_model.py`
- Modify: `tests/test_model_config.py`
- Modify: `tests/test_llm_provider_adapters.py`

---

## Task 1: Add failing tests for provider capability metadata

**Objective:** Lock in the provider/profile information that onboarding needs before changing UI code.

**Files:**
- Create or modify: `tests/test_model_config.py`
- Create: `src/ares/llm/provider_catalog.py`

**Step 1: Write failing tests**
- Assert the catalog exposes user-facing choices for at least:
  - local
  - openai
  - openrouter
  - anthropic
  - gemini
  - custom OpenAI-compatible
- Assert known providers expose endpoint behavior:
  - `local` => default local endpoint, editable
  - `openai` => `https://api.openai.com/v1`, hidden unless advanced edit requested
  - `openrouter` => `https://openrouter.ai/api/v1`, hidden unless advanced edit requested
  - `anthropic` / `gemini` => native, no OpenAI-compatible endpoint prompt
- Assert auth capabilities:
  - `openai` => api-key plus optional configured OAuth broker only if explicitly supported by catalog entry
  - `gemini` => api-key and OAuth
  - `anthropic` / `openrouter` => api-key only unless a future broker is explicitly added

**Step 2: Run test to verify failure**
Run: `python -m pytest tests/test_model_config.py -q`
Expected: FAIL because no provider capability catalog exists yet.

**Step 3: Write minimal implementation**
- Create `src/ares/llm/provider_catalog.py` with immutable descriptors like:
  - key
  - label
  - provider
  - default_model
  - default_endpoint
  - endpoint_mode: `hidden`, `editable`, `native`
  - auth_methods: tuple of `api-key`, `oauth`
  - oauth_provider key if applicable
- Keep `config.loader` profile presets and catalog defaults in sync through shared helpers instead of duplicated literals.

**Step 4: Run test to verify pass**
Run: `python -m pytest tests/test_model_config.py -q`
Expected: PASS.

---

## Task 2: Add failing tests for menu-driven selection UI

**Objective:** Replace free-text profile entry with a pleasant chooser that still works in tests.

**Files:**
- Create: `tests/test_prompt_ui.py`
- Create: `src/ares/prompt_ui.py`
- Modify: `tests/test_onboard_cli.py`
- Modify: `tests/test_cli_model.py`

**Step 1: Write failing tests**
- Non-TTY/scripted mode accepts numbered input and maps it to a choice.
- Selection UI can render labels separately from internal values.
- Prompt helpers support:
  - select one
  - confirm
  - optional text input
- `ares onboard` scripted tests can choose providers by number instead of typing profile names.

**Step 2: Run tests to verify failure**
Run: `python -m pytest tests/test_prompt_ui.py tests/test_onboard_cli.py tests/test_cli_model.py -q`
Expected: FAIL because the prompt/menu abstraction does not exist.

**Step 3: Write minimal implementation**
- Build `src/ares/prompt_ui.py` with a small API, for example:
  - `Choice(value, label, hint="")`
  - `select_one(...)`
  - `confirm(...)`
  - `ask_text(...)`
- TTY mode:
  - use curses-based arrow-key selection with Enter to choose
  - show label plus optional hint/summary
- Non-TTY mode:
  - print numbered list and accept `1`, `2`, etc.
- Keep the interface deterministic so subprocess tests remain easy.

**Step 4: Run tests to verify pass**
Run: `python -m pytest tests/test_prompt_ui.py tests/test_onboard_cli.py tests/test_cli_model.py -q`
Expected: PASS.

---

## Task 3: Add failing tests for endpoint auto-fill and hidden advanced settings

**Objective:** Stop asking operators to type endpoints Ares already knows.

**Files:**
- Modify: `tests/test_onboard_cli.py`
- Modify: `tests/test_cli_model.py`
- Create or modify: `src/ares/onboarding.py`

**Step 1: Write failing tests**
- `openai` onboarding no longer requires the endpoint prompt in normal mode.
- `openrouter` onboarding no longer requires the endpoint prompt in normal mode.
- `local` onboarding defaults to the local endpoint but still allows editing.
- `anthropic` and `gemini` do not show an OpenAI base URL prompt.
- Custom OpenAI-compatible provider still prompts for endpoint.
- Advanced mode can reveal and override hidden endpoints when explicitly requested.

**Step 2: Run tests to verify failure**
Run: `python -m pytest tests/test_onboard_cli.py tests/test_cli_model.py -q`
Expected: FAIL because current onboarding always asks in a provider-blind way.

**Step 3: Write minimal implementation**
- Create `src/ares/onboarding.py` with one shared flow used by:
  - `ares onboard`
  - `ares model --interactive`
- Feed that flow from the provider catalog.
- Add a small `advanced` branch for endpoint override/editing rather than asking every time.

**Step 4: Run tests to verify pass**
Run: `python -m pytest tests/test_onboard_cli.py tests/test_cli_model.py -q`
Expected: PASS.

---

## Task 4: Add failing tests for real OAuth broker behavior

**Objective:** Replace shell-token-command-only behavior with a proper OAuth broker for supported providers.

**Files:**
- Create: `tests/test_oauth_flows.py`
- Create: `src/ares/llm/oauth_cache.py`
- Create: `src/ares/llm/oauth_flows.py`
- Modify: `src/ares/llm/oauth.py`
- Modify: `tests/test_llm_provider_adapters.py`

**Step 1: Write failing tests**
- OAuth broker can describe provider-specific login methods.
- Token cache persists access token plus expiry metadata.
- Cached unexpired token is reused.
- Expired token triggers refresh/login path.
- Gemini OAuth flow can build credentials without requiring a shell token command in the happy path.
- OpenAI-compatible OAuth path can use a broker-issued bearer token provider when configured.
- Legacy token-command mode still works as a fallback.

**Step 2: Run tests to verify failure**
Run: `python -m pytest tests/test_oauth_flows.py tests/test_llm_provider_adapters.py -q`
Expected: FAIL because only command-based token execution exists today.

**Step 3: Write minimal implementation**
- Add `oauth_cache.py` for read/write of cached token JSON under `~/.ares/oauth/`.
- Add `oauth_flows.py` with provider-specific broker interfaces, for example:
  - Google installed-app / browser flow for Gemini Vertex use
  - Generic OAuth2 device/browser flow for providers that publish metadata and are explicitly configured in Ares
- Keep unsupported providers on API-key auth rather than pretending OAuth exists.
- Refactor `src/ares/llm/oauth.py` into a thin compatibility layer that can:
  - use the new broker
  - fall back to `oauth_token_command`
- Update adapter construction so `auth_mode="oauth"` uses broker-backed token retrieval rather than always requiring a shell command.

**Step 4: Run tests to verify pass**
Run: `python -m pytest tests/test_oauth_flows.py tests/test_llm_provider_adapters.py -q`
Expected: PASS.

---

## Task 5: Add failing tests for auth login/status/logout CLI surfaces

**Objective:** Make OAuth manageable outside the onboarding moment.

**Files:**
- Modify: `src/ares/cli.py`
- Modify: `tests/test_cli_model.py` or create `tests/test_cli_auth.py`
- Modify: `src/ares/onboarding.py`

**Step 1: Write failing tests**
- `ares auth login --provider gemini` triggers the configured OAuth broker.
- `ares auth status` shows whether cached credentials exist and when they expire.
- `ares auth logout --provider gemini` clears cached credentials.
- `ares onboard` can offer “Sign in now” after selecting an OAuth-capable provider.

**Step 2: Run tests to verify failure**
Run: `python -m pytest tests/test_cli_auth.py tests/test_onboard_cli.py -q`
Expected: FAIL because these CLI commands do not exist.

**Step 3: Write minimal implementation**
- Add Typer command group:
  - `ares auth login`
  - `ares auth status`
  - `ares auth logout`
- Use the broker/cache modules instead of duplicate auth logic.
- In onboarding, if the selected provider supports OAuth, offer immediate login and validation.

**Step 4: Run tests to verify pass**
Run: `python -m pytest tests/test_cli_auth.py tests/test_onboard_cli.py -q`
Expected: PASS.

---

## Task 6: Refactor `ares onboard` and `ares model --interactive` onto one engine

**Objective:** Remove duplicated onboarding/model prompt logic so UX changes happen in one place.

**Files:**
- Modify: `src/ares/cli.py`
- Create or modify: `src/ares/onboarding.py`
- Modify: `tests/test_onboard_cli.py`
- Modify: `tests/test_cli_model.py`

**Step 1: Write failing tests**
- Shared engine supports a full onboarding flow and a model-only flow.
- Output summaries remain appropriate to the command used.
- Existing model/onboard regression tests still pass with the new helper.

**Step 2: Run tests to verify failure**
Run: `python -m pytest tests/test_onboard_cli.py tests/test_cli_model.py -q`
Expected: FAIL while the flows are still duplicated.

**Step 3: Write minimal implementation**
- Move selection/input/auth orchestration into `src/ares/onboarding.py`.
- Keep `cli.py` thin.
- Expose reusable functions such as:
  - `run_model_setup(...)`
  - `run_full_onboarding(...)`
  - `format_onboarding_summary(...)`

**Step 4: Run tests to verify pass**
Run: `python -m pytest tests/test_onboard_cli.py tests/test_cli_model.py -q`
Expected: PASS.

---

## Task 7: Documentation refresh

**Objective:** Explain the new profile/auth UX clearly so operators do not guess.

**Files:**
- Modify: `README.md`
- Optionally create: `docs/onboarding.md`

**Step 1: Write docs changes**
- Explain provider choices in plain language:
  - `local` = local OpenAI-compatible endpoint
  - `openai` = OpenAI cloud
  - `openrouter` = OpenRouter cloud
  - `anthropic` = native Anthropic API
  - `gemini` = native Gemini API / Vertex path
  - `custom` = operator-provided OpenAI-compatible endpoint
- Explain when endpoint prompts appear and when they are hidden.
- Explain which providers support real OAuth and which remain API-key only.
- Document `ares auth login/status/logout`.

**Step 2: Verify docs accuracy**
- Run the final onboarding flows locally.
- Make sure prompt text and command names match actual output.

---

## Validation commands

Run throughout implementation:
- `python -m pytest tests/test_prompt_ui.py -q`
- `python -m pytest tests/test_oauth_flows.py -q`
- `python -m pytest tests/test_onboard_cli.py tests/test_cli_model.py tests/test_model_config.py tests/test_llm_provider_adapters.py -q`
- `python -m pytest tests -q`
- `python -m compileall src/ares`

Manual smoke checks:
- `ares onboard` in a real TTY should show a menu selector, not free-text profile guessing.
- `ares onboard` with `openai` should not ask for the endpoint unless advanced edit is requested.
- `ares onboard` with `local` should default to the local endpoint and allow editing.
- `ares onboard` with `gemini` should offer API key or OAuth and allow immediate login.
- `ares auth status` should show cached token metadata without dumping secrets.

---

## Pitfalls

- Do not claim OAuth support for a provider unless Ares actually has a working broker flow for it.
- Do not force endpoint prompts for providers with fixed/default endpoints.
- Do not make the menu system TTY-only; subprocess tests still need deterministic numbered fallback input.
- Do not leave `ares onboard` and `ares model --interactive` as separate prompt implementations.
- Do not store raw secrets in plaintext summaries or logs.
- Do not break existing config compatibility; new metadata should layer on top of current config and profile helpers.

---

## Good outcome

A good implementation leaves Ares with an onboarding flow that feels like a product instead of a debug shell:
- clear profile selection
- smart defaults
- hidden complexity unless asked for
- real sign-in flow where supported
- reusable auth/status commands
- one onboarding engine shared across CLI entrypoints

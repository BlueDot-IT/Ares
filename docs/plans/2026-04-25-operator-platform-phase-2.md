# Operator Platform Phase 2 Implementation Plan

> **For Hermes:** Use subagent-driven-development skill to implement this plan task-by-task.

**Goal:** Add the next operator-platform layer to Ares by shipping exposed-mode gateway hardening, a richer web control surface, expanded hooks and engagement memory, deeper routing/profile controls, and an onboarding flow.

**Architecture:** Keep the existing runtime intact and layer operator features around it. Add new persistence and config fields in small seams, expose only thin CLI and HTTP surfaces, and wire richer behavior through the existing gateway, hooks, routing, reporting, and StateDB modules.

**Tech Stack:** Python 3.13, stdlib `http.server`, Typer CLI, SQLite `StateDB`, JSON config under `~/.ares/config.json`, browser UI served from `src/ares/webui.py`.

---

## Scope chosen for this phase

This phase implements the user’s requested feature buckets as practical alpha slices:

1. **Gateway hardening**
   - token-backed operator login for exposed mode
   - one-time pairing/invite codes generated locally
   - CIDR/IP allowlists
   - JSONL audit log for auth and operator actions

2. **Richer control UI**
   - auth screen when gateway auth is enabled
   - config/status panel
   - persisted session list and run detail view
   - report and evidence preview panes

3. **Hooks and automation lifecycle**
   - built-in hook support alongside workspace hooks
   - `session_started`, `route_selected`, `session_finished`, and `gateway_started` events
   - built-in engagement memory writer hook

4. **Deeper routing and profiles**
   - profile `prompt_prefix` and `memory_tags`
   - route matching on prompt substrings and ROE profiles
   - route preview / profile listing CLI surfaces

5. **Engagement memory / recall**
   - deterministic memory files under `~/.ares/memory/engagements/`
   - prompt-time loading of recent target-relevant memory
   - CLI search/list helper for engagement memory

6. **Onboarding**
   - interactive `ares onboard` flow for model, gateway mode, auth token, allowlist, hooks, theme

---

## Files expected to change

Core runtime/control-plane:
- Modify: `src/ares/config/loader.py`
- Modify: `src/ares/config/__init__.py`
- Modify: `src/ares/cli.py`
- Modify: `src/ares/gateway.py`
- Modify: `src/ares/webui.py`
- Modify: `src/ares/hooks.py`
- Modify: `src/ares/routing.py`
- Modify: `src/ares/run.py`
- Modify: `src/ares/agent/context_builder.py`
- Modify: `src/ares/state/db.py`
- Modify: `src/ares/reporting/markdown.py`

New support modules likely:
- Create: `src/ares/gateway_auth.py`
- Create: `src/ares/engagement_memory.py`

Tests:
- Create: `tests/test_gateway_auth.py`
- Create: `tests/test_engagement_memory.py`
- Create: `tests/test_onboard_cli.py`
- Modify: `tests/test_gateway_control_plane.py`
- Modify: `tests/test_gateway_web_ui.py`
- Modify: `tests/test_hooks_automation.py`
- Modify: `tests/test_agent_routing.py`
- Modify: `tests/test_run_helpers_cli.py`
- Modify: `tests/test_cli_gateway.py`
- Modify: `tests/test_model_config.py`
- Modify: `tests/test_session_report_helpers.py`

---

## Task 1: Add failing tests for gateway auth, pairing invites, allowlists, and audit logging

**Objective:** Lock the desired external control-plane behavior before implementation.

**Files:**
- Create: `tests/test_gateway_auth.py`
- Modify: `tests/test_gateway_control_plane.py`
- Modify: `tests/test_cli_gateway.py`

**Step 1: Write failing tests**
- Verify exposed mode rejects unauthenticated requests when auth is enabled.
- Verify a valid bearer session token allows requests.
- Verify one-time pairing/invite codes can be exchanged for a session.
- Verify CIDR allowlist blocks public clients not in scope.
- Verify JSONL audit entries are written for auth attempts and run submission.

**Step 2: Run tests to verify failure**
Run: `python -m pytest tests/test_gateway_auth.py tests/test_gateway_control_plane.py tests/test_cli_gateway.py -q`
Expected: FAIL with missing auth/pairing/audit behavior.

**Step 3: Write minimal implementation**
- Add gateway auth config and helpers.
- Add in-memory session tokens and one-time pairing code exchange.
- Add audit-log append helper.
- Enforce auth on API/UI access for exposed mode when enabled.

**Step 4: Run tests to verify pass**
Run: `python -m pytest tests/test_gateway_auth.py tests/test_gateway_control_plane.py tests/test_cli_gateway.py -q`
Expected: PASS.

---

## Task 2: Add failing tests for the richer web control UI

**Objective:** Expand the browser surface from a shell to an operator dashboard.

**Files:**
- Modify: `tests/test_gateway_web_ui.py`
- Possibly modify: `tests/test_session_report_helpers.py`

**Step 1: Write failing tests**
- UI HTML includes auth panel / login affordance when auth is enabled.
- UI assets reference config, sessions, reports, and run detail endpoints.
- New API routes return persisted sessions, report text, and doctor/config snapshot.
- Session detail exposes evidence and tool history.

**Step 2: Run tests to verify failure**
Run: `python -m pytest tests/test_gateway_web_ui.py -q`
Expected: FAIL because new routes and UI markers do not exist.

**Step 3: Write minimal implementation**
- Extend gateway routes for config, sessions, session detail, and reports.
- Enrich HTML/CSS/JS with login panel, config/status panel, session explorer, and report/evidence panes.

**Step 4: Run tests to verify pass**
Run: `python -m pytest tests/test_gateway_web_ui.py tests/test_gateway_control_plane.py -q`
Expected: PASS.

---

## Task 3: Add failing tests for built-in hooks and engagement memory generation

**Objective:** Make Ares emit a richer lifecycle and persist deterministic engagement memories.

**Files:**
- Create: `tests/test_engagement_memory.py`
- Modify: `tests/test_hooks_automation.py`
- Modify: `tests/test_run_helpers_cli.py`

**Step 1: Write failing tests**
- `session_started`, `route_selected`, `session_finished`, and `gateway_started` can be observed by built-ins.
- A built-in engagement-memory hook writes a memory file after session finish.
- Memory file contains target, agent, status, key evidence, and report reference.
- Hook failures still do not crash runs.

**Step 2: Run tests to verify failure**
Run: `python -m pytest tests/test_hooks_automation.py tests/test_engagement_memory.py tests/test_run_helpers_cli.py -q`
Expected: FAIL due to missing built-ins / memory behavior.

**Step 3: Write minimal implementation**
- Add built-in hook registration support.
- Add deterministic engagement-memory writer.
- Emit `gateway_started` from the gateway bootstrap path.

**Step 4: Run tests to verify pass**
Run: `python -m pytest tests/test_hooks_automation.py tests/test_engagement_memory.py tests/test_run_helpers_cli.py -q`
Expected: PASS.

---

## Task 4: Add failing tests for memory recall and prompt-time loading

**Objective:** Use prior engagement notes as runtime context, not just as archive files.

**Files:**
- Create: `tests/test_engagement_memory.py` (extend)
- Modify: `src/ares/agent/context_builder.py` tests if present, otherwise add to `tests/test_agent_flow_builders.py`

**Step 1: Write failing tests**
- Recent engagement memory files matching the current target are loaded into session context.
- Unrelated memory files are ignored.
- CLI memory listing/search returns matching entries.

**Step 2: Run tests to verify failure**
Run: `python -m pytest tests/test_engagement_memory.py tests/test_agent_flow_builders.py -q`
Expected: FAIL because memory recall helpers do not exist.

**Step 3: Write minimal implementation**
- Add engagement memory module for indexing/searching/loading files.
- Thread a short memory summary into `ContextBuilder`.
- Add CLI list/search commands.

**Step 4: Run tests to verify pass**
Run: `python -m pytest tests/test_engagement_memory.py tests/test_agent_flow_builders.py -q`
Expected: PASS.

---

## Task 5: Add failing tests for deeper routing and profile controls

**Objective:** Make profile routing more useful for pentest roles and operator workflows.

**Files:**
- Modify: `tests/test_agent_routing.py`
- Possibly add: `tests/test_cli_route_preview.py` or extend existing CLI tests

**Step 1: Write failing tests**
- Route rules can match on prompt substrings and ROE profiles.
- Profiles can inject a `prompt_prefix`.
- Profiles expose `memory_tags` that appear in memory output.
- CLI route preview reports the chosen agent and reason.

**Step 2: Run tests to verify failure**
Run: `python -m pytest tests/test_agent_routing.py -q`
Expected: FAIL because new route fields and CLI preview do not exist.

**Step 3: Write minimal implementation**
- Extend config dataclasses and loader.
- Extend `AgentRouter.resolve(...)` inputs.
- Prefix prompt input before runtime execution when configured.
- Add CLI route/profile inspection commands.

**Step 4: Run tests to verify pass**
Run: `python -m pytest tests/test_agent_routing.py tests/test_run_helpers_cli.py -q`
Expected: PASS.

---

## Task 6: Add failing tests for onboarding flow

**Objective:** Create a guided setup path for operators instead of hand-editing config.

**Files:**
- Create: `tests/test_onboard_cli.py`
- Modify: `src/ares/cli.py`

**Step 1: Write failing tests**
- `ares onboard` can accept scripted input and persist provider/model/theme/gateway mode.
- Exposed mode onboarding can create/save an auth token and allowlist.
- Onboarding can enable auto-report and engagement memory defaults.

**Step 2: Run tests to verify failure**
Run: `python -m pytest tests/test_onboard_cli.py -q`
Expected: FAIL because `onboard` does not exist.

**Step 3: Write minimal implementation**
- Add Typer onboarding command using `typer.prompt` / `typer.confirm`.
- Save settings through config helpers instead of hand-writing JSON in the CLI.

**Step 4: Run tests to verify pass**
Run: `python -m pytest tests/test_onboard_cli.py tests/test_model_config.py tests/test_cli_gateway.py -q`
Expected: PASS.

---

## Task 7: Full integration verification

**Objective:** Prove the new operator-platform layer works together and does not regress the existing alpha.

**Files:**
- No code changes required unless failures reveal gaps.

**Step 1: Run targeted suites**
Run:
- `python -m pytest tests/test_gateway_auth.py tests/test_gateway_control_plane.py tests/test_gateway_web_ui.py -q`
- `python -m pytest tests/test_hooks_automation.py tests/test_engagement_memory.py tests/test_agent_routing.py tests/test_onboard_cli.py -q`

**Step 2: Run full Ares suite**
Run: `python -m pytest tests -q`
Expected: PASS.

**Step 3: Compile check**
Run: `python -m compileall src/ares`
Expected: PASS.

**Step 4: Review diff and commit**
Run:
- `git diff --stat`
- `git add -A && git commit -m "feat: add operator platform hardening and memory workflows"`

---

## Notes for implementation

- Keep the TUI local and additive to the web UI.
- Use `python -m pytest tests -q`, not bare repo-wide `pytest -q`.
- Exposed mode must not silently remain open without auth when auth is configured.
- Prefer deterministic summaries for engagement memory over adding a new summarization model dependency.
- Keep remote-access hardening operator-visible in both CLI and web UI status surfaces.

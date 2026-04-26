from __future__ import annotations


def build_web_ui_html(*, auth_required: bool = False) -> str:
    auth_hidden = "" if auth_required else " hidden"
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Ares Web UI</title>
  <link rel="stylesheet" href="/app.css">
</head>
<body data-theme="ember">
  <div id="app-shell" data-auth-required="{'true' if auth_required else 'false'}">
    <header class="hero panel">
      <div>
        <div class="eyebrow">AUTHORIZED PENTEST OPERATIONS</div>
        <h1>Ares Web UI</h1>
        <p class="subtitle">Hermes-style runtime, OpenClaw-style operator control, focused on pentesting.</p>
      </div>
      <div class="hero-status stack-tight">
        <div id="health-badge" class="badge">connecting</div>
        <div id="auth-state-badge" class="badge subtle">browser auth</div>
      </div>
    </header>

    <section id="auth-panel" class="panel stack"{auth_hidden}>
      <h2>Gateway Access</h2>
      <p class="subtitle auth-copy">Authenticate with an operator token or exchange a one-time pairing code.</p>
      <div id="auth-status" class="status-note">Login or pair to continue.</div>
      <div class="auth-grid">
        <form id="login-form" class="stack auth-form">
          <label>
            Operator token
            <input id="operator-token-input" name="operator_token" type="password" placeholder="Persisted operator token">
          </label>
          <button id="login-button" type="submit">Login</button>
        </form>
        <form id="pair-form" class="stack auth-form">
          <label>
            Pairing code
            <input id="pair-code-input" name="code" type="text" placeholder="One-time pairing code">
          </label>
          <button id="pair-button" type="submit">Pair</button>
        </form>
      </div>
      <div class="inline-actions">
        <button id="logout-button" type="button" class="ghost-button">Forget browser session</button>
      </div>
    </section>

    <section class="grid">
      <aside id="runs-panel" class="panel stack">
        <h2>Runs</h2>
        <div id="runs-list" class="list empty">No runs yet.</div>
      </aside>

      <main id="transcript-panel" class="panel stack">
        <h2>Transcript</h2>
        <div id="transcript-feed" class="feed empty">Submit a run to begin.</div>
      </main>

      <aside id="events-panel" class="panel stack">
        <h2>Event Stream</h2>
        <div id="events-feed" class="feed empty">Awaiting gateway events.</div>
      </aside>
    </section>

    <section class="panel stack">
      <h2>Launch Run</h2>
      <form id="run-form" class="run-form">
        <label>
          Target
          <input id="target-input" name="target" type="text" placeholder="127.0.0.1 or authorized scope">
        </label>
        <label>
          Agent
          <input id="agent-input" name="agent" type="text" placeholder="default or routing profile">
        </label>
        <label class="wide">
          Prompt
          <textarea id="prompt-input" name="prompt" rows="4" placeholder="Describe the authorized pentest task"></textarea>
        </label>
        <label class="check-row">
          <input id="approve-input" name="approve_dangerous" type="checkbox">
          Approve dangerous tools for this run
        </label>
        <button id="submit-button" type="submit">Launch</button>
      </form>
    </section>
  </div>
  <script src="/app.js"></script>
</body>
</html>
"""


def build_web_ui_css() -> str:
    return """html, body {
  margin: 0;
  padding: 0;
  background: #160d09;
  color: #f4e6d8;
  font-family: Inter, ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, \"Segoe UI\", sans-serif;
}

* {
  box-sizing: border-box;
}

body {
  min-height: 100vh;
}

#app-shell {
  max-width: 1500px;
  margin: 0 auto;
  padding: 24px;
}

.grid {
  display: grid;
  grid-template-columns: 280px 1fr 340px;
  gap: 16px;
  margin: 16px 0;
}

.panel {
  background: #24140f;
  border: 1px solid #5e2f1a;
  border-radius: 16px;
  box-shadow: 0 12px 40px rgba(0, 0, 0, 0.32);
  padding: 16px;
}

.stack {
  display: flex;
  flex-direction: column;
  gap: 12px;
}

.stack-tight {
  display: flex;
  flex-direction: column;
  gap: 8px;
}

.hero {
  display: flex;
  align-items: start;
  justify-content: space-between;
  gap: 16px;
}

.hero-status {
  align-items: end;
}

.eyebrow {
  color: #ffb36b;
  font-size: 12px;
  letter-spacing: 0.14em;
}

.subtitle {
  margin: 8px 0 0;
  color: #d7b08d;
}

.badge {
  align-self: center;
  padding: 8px 12px;
  border-radius: 999px;
  border: 1px solid #a14b1e;
  background: #2b1710;
  color: #ffd4a6;
  font-size: 13px;
}

.badge.subtle {
  border-color: #6d4026;
  background: #211511;
  color: #e8c6a2;
}

.status-note {
  padding: 10px 12px;
  border-radius: 12px;
  border: 1px solid #5b311b;
  background: #1d110d;
  color: #ffd8b4;
}

.auth-copy {
  margin-top: 0;
}

.auth-grid {
  display: grid;
  grid-template-columns: repeat(2, minmax(0, 1fr));
  gap: 14px;
}

.auth-form {
  padding: 12px;
  border-radius: 12px;
  border: 1px solid #5b311b;
  background: #1d110d;
}

.inline-actions {
  display: flex;
  justify-content: flex-end;
}

.ghost-button {
  border-color: #744023;
  background: #1d110d;
  color: #ffd4a6;
}

[hidden] {
  display: none !important;
}

.list, .feed {
  min-height: 280px;
  max-height: 480px;
  overflow: auto;
  padding: 12px;
  border-radius: 12px;
  background: #1d110d;
  border: 1px solid #4d2817;
  white-space: pre-wrap;
  font-family: \"SFMono-Regular\", Consolas, \"Liberation Mono\", Menlo, monospace;
  font-size: 13px;
  line-height: 1.45;
}

.empty {
  color: #a98b74;
}

.run-form {
  display: grid;
  grid-template-columns: repeat(2, minmax(0, 1fr));
  gap: 14px;
}

.run-form label,
.auth-form label {
  display: flex;
  flex-direction: column;
  gap: 8px;
  font-size: 14px;
  color: #efdac7;
}

.run-form .wide {
  grid-column: 1 / -1;
}

.run-form .check-row {
  grid-column: 1 / -1;
  flex-direction: row;
  align-items: center;
}

input, textarea, button {
  font: inherit;
}

input, textarea {
  width: 100%;
  padding: 10px 12px;
  border-radius: 10px;
  border: 1px solid #744023;
  background: #140c09;
  color: #fff0e1;
}

button {
  width: fit-content;
  padding: 10px 16px;
  border-radius: 10px;
  border: 1px solid #ff8a3c;
  background: linear-gradient(180deg, #ff8a3c, #b74b1e);
  color: white;
  cursor: pointer;
}

button:disabled,
input:disabled,
textarea:disabled {
  cursor: not-allowed;
  opacity: 0.65;
}

.run-card {
  padding: 10px;
  border-radius: 10px;
  border: 1px solid #5b311b;
  background: #271712;
  margin-bottom: 10px;
}

.run-card strong {
  color: #ffffff;
}

.event-line.tool_call { color: #ffd07a; }
.event-line.tool_result { color: #93f0ae; }
.event-line.session_failed { color: #ffb0a1; }
.event-line.final_response,
.event-line.session_finished { color: #ffb36b; }

@media (max-width: 1100px) {
  .grid,
  .auth-grid {
    grid-template-columns: 1fr;
  }

  .hero {
    flex-direction: column;
  }

  .hero-status {
    align-items: start;
  }
}
"""


def build_web_ui_js(*, auth_required: bool = False) -> str:
    return """const AUTH_REQUIRED = __AUTH_REQUIRED__;
const STORAGE_KEY = 'ares.gateway.session_token';

const state = {
  runs: [],
  lastSeq: 0,
  transcript: [],
  events: [],
  authRequired: AUTH_REQUIRED,
  sessionToken: '',
};

const el = (id) => document.getElementById(id);

function escapeHtml(value) {
  return String(value)
    .replaceAll('&', '&amp;')
    .replaceAll('<', '&lt;')
    .replaceAll('>', '&gt;')
    .replaceAll('"', '&quot;')
    .replaceAll("'", '&#39;');
}

function updateHealthBadge(text) {
  el('health-badge').textContent = text;
}

function authSatisfied() {
  return !state.authRequired || !!state.sessionToken;
}

function setSessionToken(token) {
  const normalized = String(token || '').trim();
  state.sessionToken = normalized;
  if (normalized) {
    window.sessionStorage.setItem(STORAGE_KEY, normalized);
  } else {
    window.sessionStorage.removeItem(STORAGE_KEY);
  }
  renderAuthPanel();
}

function authHeaders(extraHeaders = {}) {
  const headers = { ...extraHeaders };
  if (state.sessionToken) {
    headers.Authorization = `Bearer ${state.sessionToken}`;
  }
  return headers;
}

async function apiFetch(path, options = {}) {
  const response = await fetch(path, {
    ...options,
    headers: authHeaders(options.headers || {}),
  });
  if (response.status === 401) {
    const error = new Error('unauthorized');
    error.code = 401;
    throw error;
  }
  return response;
}

function setRunFormEnabled(enabled) {
  const form = el('run-form');
  if (!form) return;
  for (const field of form.querySelectorAll('input, textarea, button')) {
    field.disabled = !enabled;
  }
}

function renderAuthPanel() {
  const panel = el('auth-panel');
  if (!panel) return;
  panel.hidden = !state.authRequired;
  const status = el('auth-status');
  const badge = el('auth-state-badge');
  const logoutButton = el('logout-button');
  if (!state.authRequired) {
    status.textContent = 'Gateway auth not required for this browser session.';
    badge.textContent = 'auth open';
    logoutButton.hidden = true;
    setRunFormEnabled(true);
    return;
  }
  if (state.sessionToken) {
    status.textContent = 'Browser session authenticated.';
    badge.textContent = 'auth ok';
    logoutButton.hidden = false;
    setRunFormEnabled(true);
  } else {
    status.textContent = 'Login or pair to continue.';
    badge.textContent = 'auth required';
    logoutButton.hidden = true;
    setRunFormEnabled(false);
  }
}

function renderRuns() {
  const container = el('runs-list');
  if (!state.runs.length) {
    container.className = 'list empty';
    container.textContent = authSatisfied() ? 'No runs yet.' : 'Authenticate to load runs.';
    return;
  }
  container.className = 'list';
  container.innerHTML = state.runs.slice().reverse().map((run) => `
    <div class="run-card">
      <strong>${escapeHtml(run.id)}</strong>\n
      status: ${escapeHtml(run.status)}\n
      target: ${escapeHtml(run.target || 'none')}\n
      agent: ${escapeHtml(run.requested_agent || 'default')}\n
      session: ${escapeHtml(run.session_id || 'pending')}\n
      prompt: ${escapeHtml(run.prompt || '')}
    </div>
  `).join('');
}

function renderEvents(events) {
  const container = el('events-feed');
  if (!events.length) {
    container.className = 'feed empty';
    container.textContent = authSatisfied() ? 'Awaiting gateway events.' : 'Authenticate to stream gateway events.';
    return;
  }
  container.className = 'feed';
  container.innerHTML = events.slice(-40).map((event) => {
    const message = event.message || event.final_response || event.error || JSON.stringify(event);
    return `<div class="event-line ${escapeHtml(event.type || 'event')}">[${escapeHtml(event.seq)}] ${escapeHtml(event.type || 'event')} :: ${escapeHtml(message)}</div>`;
  }).join('');
  container.scrollTop = container.scrollHeight;
}

function renderTranscript() {
  const container = el('transcript-feed');
  if (!state.transcript.length) {
    container.className = 'feed empty';
    container.textContent = authSatisfied() ? 'Submit a run to begin.' : 'Authenticate before launching runs.';
    return;
  }
  container.className = 'feed';
  container.innerHTML = state.transcript.slice(-60).map((line) => `<div>${escapeHtml(line)}</div>`).join('');
  container.scrollTop = container.scrollHeight;
}

function pushTranscriptLine(prefix, text) {
  state.transcript.push(`${prefix} ${text}`.trim());
  renderTranscript();
}

function clearProtectedViews() {
  state.runs = [];
  state.events = [];
  state.lastSeq = 0;
  renderRuns();
  renderEvents([]);
}

async function refreshRuns() {
  if (!authSatisfied()) {
    state.runs = [];
    renderRuns();
    return;
  }
  const response = await apiFetch('/api/runs');
  state.runs = await response.json();
  renderRuns();
}

async function refreshHealth() {
  if (!authSatisfied()) {
    updateHealthBadge('auth required');
    return;
  }
  const response = await apiFetch('/health');
  const payload = await response.json();
  updateHealthBadge(`${payload.status} · ${payload.runs} runs`);
}

async function refreshEvents() {
  if (!authSatisfied()) {
    state.events = [];
    renderEvents([]);
    return;
  }
  const response = await apiFetch(`/api/events?after=${state.lastSeq}`);
  const payload = await response.json();
  const events = payload.events || [];
  if (!events.length) {
    return;
  }
  state.lastSeq = events[events.length - 1].seq;
  for (const event of events) {
    const message = event.message || event.final_response || event.error || JSON.stringify(event);
    if (event.type === 'session_started') pushTranscriptLine('status   >', message);
    else if (event.type === 'tool_call') pushTranscriptLine('tool     >', message);
    else if (event.type === 'tool_result') pushTranscriptLine('result   >', message);
    else if (event.type === 'final_response') pushTranscriptLine('ares     >', message);
    else if (event.type === 'session_failed') pushTranscriptLine('error    >', message);
    else pushTranscriptLine('event    >', message);
  }
  await loadAllEvents();
  await refreshRuns();
  await refreshHealth();
}

async function loadAllEvents() {
  if (!authSatisfied()) {
    state.events = [];
    renderEvents([]);
    return [];
  }
  const response = await apiFetch('/api/events?after=0');
  const payload = await response.json();
  state.events = payload.events || [];
  renderEvents(state.events);
  return state.events;
}

async function refreshProtectedState() {
  if (!authSatisfied()) {
    clearProtectedViews();
    updateHealthBadge('auth required');
    return;
  }
  await refreshHealth();
  await refreshRuns();
  await loadAllEvents();
}

async function submitRun(event) {
  event.preventDefault();
  if (!authSatisfied()) {
    pushTranscriptLine('status   >', 'Authenticate before launching runs.');
    return;
  }
  const payload = {
    target: el('target-input').value.trim() || null,
    agent: el('agent-input').value.trim() || null,
    prompt: el('prompt-input').value.trim(),
    approve_dangerous: el('approve-input').checked,
  };
  if (!payload.prompt) {
    pushTranscriptLine('status   >', 'Prompt required before launch.');
    return;
  }
  pushTranscriptLine('operator >', payload.prompt);
  const response = await apiFetch('/api/runs', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload),
  });
  const created = await response.json();
  pushTranscriptLine('status   >', `submitted run ${created.id}`);
  el('run-form').reset();
  await refreshRuns();
  await refreshHealth();
}

async function submitLogin(event) {
  event.preventDefault();
  const operatorToken = el('operator-token-input').value.trim();
  if (!operatorToken) {
    pushTranscriptLine('status   >', 'Operator token required for login.');
    return;
  }
  const response = await fetch('/api/auth/login', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ operator_token: operatorToken }),
  });
  if (!response.ok) {
    pushTranscriptLine('error    >', 'Operator login failed.');
    return;
  }
  const payload = await response.json();
  setSessionToken(payload.session_token || '');
  el('login-form').reset();
  pushTranscriptLine('status   >', 'Browser session authenticated by operator token.');
  await refreshProtectedState();
}

async function submitPair(event) {
  event.preventDefault();
  const code = el('pair-code-input').value.trim();
  if (!code) {
    pushTranscriptLine('status   >', 'Pairing code required.');
    return;
  }
  const response = await fetch('/api/auth/pair', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ code }),
  });
  if (!response.ok) {
    pushTranscriptLine('error    >', 'Pairing code exchange failed.');
    return;
  }
  const payload = await response.json();
  setSessionToken(payload.session_token || '');
  el('pair-form').reset();
  pushTranscriptLine('status   >', 'Browser session paired successfully.');
  await refreshProtectedState();
}

async function handleProtectedError(error) {
  if (error && error.code === 401) {
    setSessionToken('');
    clearProtectedViews();
    renderTranscript();
    updateHealthBadge('auth required');
    pushTranscriptLine('status   >', 'Browser session expired or auth required.');
    return;
  }
  updateHealthBadge('gateway error');
  console.error(error);
}

async function boot() {
  state.authRequired = el('app-shell').dataset.authRequired === 'true';
  state.sessionToken = window.sessionStorage.getItem(STORAGE_KEY) || '';
  el('run-form').addEventListener('submit', submitRun);
  el('login-form').addEventListener('submit', submitLogin);
  el('pair-form').addEventListener('submit', submitPair);
  el('logout-button').addEventListener('click', () => {
    setSessionToken('');
    clearProtectedViews();
    renderTranscript();
    updateHealthBadge(state.authRequired ? 'auth required' : 'ok');
    pushTranscriptLine('status   >', 'Browser session cleared.');
  });
  renderAuthPanel();
  renderTranscript();
  renderEvents([]);
  renderRuns();
  if (authSatisfied()) {
    await refreshProtectedState();
  } else {
    updateHealthBadge('auth required');
  }
  setInterval(() => {
    refreshEvents().catch(handleProtectedError);
  }, 1500);
  setInterval(() => {
    refreshRuns().catch(handleProtectedError);
    refreshHealth().catch(handleProtectedError);
  }, 4000);
}

window.addEventListener('load', () => {
  boot().catch(handleProtectedError);
});
""".replace('__AUTH_REQUIRED__', 'true' if auth_required else 'false')

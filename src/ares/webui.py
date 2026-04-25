from __future__ import annotations


def build_web_ui_html() -> str:
    return """<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Ares Web UI</title>
  <link rel="stylesheet" href="/app.css">
</head>
<body>
  <div id="app-shell">
    <header class="hero panel">
      <div>
        <div class="eyebrow">AUTHORIZED PENTEST OPERATIONS</div>
        <h1>Ares Web UI</h1>
        <p class="subtitle">Hermes-style runtime, OpenClaw-style operator control, focused on pentesting.</p>
      </div>
      <div id="health-badge" class="badge">connecting</div>
    </header>

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
  background: #0b1020;
  color: #dbe7ff;
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
  background: #11182d;
  border: 1px solid #26314f;
  border-radius: 16px;
  box-shadow: 0 12px 40px rgba(0, 0, 0, 0.28);
  padding: 16px;
}

.stack {
  display: flex;
  flex-direction: column;
  gap: 12px;
}

.hero {
  display: flex;
  align-items: start;
  justify-content: space-between;
  gap: 16px;
}

.eyebrow {
  color: #7dd3fc;
  font-size: 12px;
  letter-spacing: 0.14em;
}

.subtitle {
  margin: 8px 0 0;
  color: #9fb2d9;
}

.badge {
  align-self: center;
  padding: 8px 12px;
  border-radius: 999px;
  border: 1px solid #31507f;
  background: #0f1730;
  color: #9ad8ff;
  font-size: 13px;
}

.list, .feed {
  min-height: 280px;
  max-height: 480px;
  overflow: auto;
  padding: 12px;
  border-radius: 12px;
  background: #0f1730;
  border: 1px solid #223250;
  white-space: pre-wrap;
  font-family: \"SFMono-Regular\", Consolas, \"Liberation Mono\", Menlo, monospace;
  font-size: 13px;
  line-height: 1.45;
}

.empty {
  color: #7285aa;
}

.run-form {
  display: grid;
  grid-template-columns: repeat(2, minmax(0, 1fr));
  gap: 14px;
}

.run-form label {
  display: flex;
  flex-direction: column;
  gap: 8px;
  font-size: 14px;
  color: #c7d6f8;
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
  border: 1px solid #31405f;
  background: #0c1328;
  color: #e5edff;
}

button {
  width: fit-content;
  padding: 10px 16px;
  border-radius: 10px;
  border: 1px solid #2b7fff;
  background: linear-gradient(180deg, #2874ff, #1e56c8);
  color: white;
  cursor: pointer;
}

.run-card {
  padding: 10px;
  border-radius: 10px;
  border: 1px solid #2a3958;
  background: #101831;
  margin-bottom: 10px;
}

.run-card strong {
  color: #ffffff;
}

.event-line.tool_call { color: #ffd37d; }
.event-line.tool_result { color: #8df2b8; }
.event-line.session_failed { color: #f5a3a3; }
.event-line.final_response,
.event-line.session_finished { color: #9ad8ff; }

@media (max-width: 1100px) {
  .grid {
    grid-template-columns: 1fr;
  }
}
"""


def build_web_ui_js() -> str:
    return """const state = {
  runs: [],
  lastSeq: 0,
  transcript: [],
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

function renderRuns() {
  const container = el('runs-list');
  if (!state.runs.length) {
    container.className = 'list empty';
    container.textContent = 'No runs yet.';
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
    container.textContent = 'Awaiting gateway events.';
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
    container.textContent = 'Submit a run to begin.';
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

async function refreshRuns() {
  const response = await fetch('/api/runs');
  state.runs = await response.json();
  renderRuns();
}

async function refreshHealth() {
  const response = await fetch('/health');
  const payload = await response.json();
  el('health-badge').textContent = `${payload.status} · ${payload.runs} runs`;
}

async function refreshEvents() {
  const response = await fetch(`/api/events?after=${state.lastSeq}`);
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
  renderEvents(await loadAllEvents());
  await refreshRuns();
  await refreshHealth();
}

async function loadAllEvents() {
  const response = await fetch('/api/events?after=0');
  const payload = await response.json();
  return payload.events || [];
}

async function submitRun(event) {
  event.preventDefault();
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
  const response = await fetch('/api/runs', {
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

async function boot() {
  el('run-form').addEventListener('submit', submitRun);
  await refreshHealth();
  await refreshRuns();
  renderTranscript();
  renderEvents([]);
  setInterval(() => {
    refreshEvents().catch((error) => {
      el('health-badge').textContent = 'gateway error';
      console.error(error);
    });
  }, 1500);
  setInterval(() => {
    refreshRuns().catch(console.error);
    refreshHealth().catch(console.error);
  }, 4000);
}

window.addEventListener('load', () => {
  boot().catch((error) => {
    el('health-badge').textContent = 'boot failed';
    console.error(error);
  });
});
"""

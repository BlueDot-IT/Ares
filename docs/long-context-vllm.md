# Long-Context vLLM Setup for Ares

This document describes how to run Ares with long-context models using vLLM, enabling context windows up to 256K tokens (tested) or 128K tokens (recommended for stability).

## Recommended Model: Qwen2.5-7B-Instruct-1M

**Qwen/Qwen2.5-7B-Instruct-1M** is the recommended long-context model for this experiment.

- Parameters: 7.61B
- Official max context: 1,010,000 tokens
- Official max generation: 8192 tokens
- VRAM requirement for full 1M context: **at least 120 GB** (per Qwen documentation)

> **WARNING:** On a single 80 GB A100, start at 128K. Then test 256K. Do not assume 512K or 1M will fit. Full 1M is outside the official 120 GB VRAM requirement for Qwen2.5-7B-Instruct-1M.

## vLLM Server Setup

### Install vLLM

```bash
python -m pip install -U vllm
```

### 128K Context (Recommended starting point for A100 80GB)

```bash
vllm serve Qwen/Qwen2.5-7B-Instruct-1M \
  --host 0.0.0.0 \
  --port 8000 \
  --max-model-len 131072 \
  --enable-chunked-prefill \
  --max-num-batched-tokens 32768 \
  --max-num-seqs 1
```

### 256K Context (Test after 128K is stable)

```bash
vllm serve Qwen/Qwen2.5-7B-Instruct-1M \
  --host 0.0.0.0 \
  --port 8000 \
  --max-model-len 262144 \
  --enable-chunked-prefill \
  --max-num-batched-tokens 32768 \
  --max-num-seqs 1
```

## Ares Configuration

Set the following environment variables or persist them in Ares config:

```bash
# LLM provider config
export LLM_PROVIDER=custom
export LLM_MODEL="Qwen/Qwen2.5-7B-Instruct-1M"
export OPENAI_BASE_URL="http://127.0.0.1:8000/v1"
export OPENAI_API_KEY="local-not-used"

# Long-context mode
export ARES_CONTEXT_MODE=long
export ARES_CONTEXT_WINDOW=131072          # Match vLLM --max-model-len
export ARES_RESERVED_OUTPUT_TOKENS=8192
export ARES_CONTEXT_RECENT_TOOL_CALLS=40
export ARES_CONTEXT_MEMORY_LIMIT=8
export ARES_CONTEXT_RETRIEVAL_LIMIT=8
export ARES_CONTEXT_INCLUDE_RAW=false
export ARES_CONTEXT_RAW_EXCERPT_CHARS=6000
```

For 256K context, change:
```bash
export ARES_CONTEXT_WINDOW=262144
```

## Test Command

```bash
# Verify Ares can reach the model
ares doctor

# Run a simple passive task
ares run \
  --target 127.0.0.1 \
  --prompt "Use only passive inspection. Summarize available context and stop." \
  --max-iterations 3
```

## How It Works

When `ARES_CONTEXT_MODE=long` is set:

1. **Budgeted context assembly**: `ContextBuilder` uses a token budget (`context_window - reserved_output_tokens`) instead of blindly stuffing recent history.
2. **Sectioned evidence**: Context is assembled from labeled sections:
   - Current engagement state
   - Scope and target summary
   - Known hosts and services
   - Active findings
   - Recent tool calls (labeled "Untrusted current-session evidence")
   - Retrieved memory chunks (labeled "Untrusted retrieved prior memory")
   - Prior engagement memory (labeled "Untrusted retrieved prior memory")
   - Raw tool excerpts (labeled "Untrusted raw tool excerpt") — only if `ARES_CONTEXT_INCLUDE_RAW=true`
3. **All evidence is labeled as untrusted**: Tool output and memory are data, never operator instructions.
4. **Model-visible recall tools**:
   - `ares.memory.search` — Search memory chunks by query
   - `ares.evidence.get_tool_call` — Retrieve bounded raw excerpt of a specific tool call
5. **Memory indexing**: Successful tool results are automatically indexed into SQLite `memory_chunks` with FTS5 search (falls back to LIKE if FTS5 unavailable).
6. **Secret redaction**: API keys, tokens, passwords, and Bearer tokens are redacted from memory, recall, and training export.

## Training Data Export

Ares does **not** implement automatic online LoRA training. That is unsafe and would poison adapters with bad outputs, prompt injection, secrets, and failed tool behavior.

Instead, use the clean export path:

```bash
ares training export --out data/ares-sft.jsonl --min-status final_response
```

This exports only sessions that:
- Completed successfully
- Have no unapproved dangerous actions
- Have no policy violations
- Have a final response
- Have secrets redacted

## Environment Variables Reference

| Variable | Default | Description |
|----------|---------|-------------|
| `ARES_CONTEXT_MODE` | `compact` | `compact` = legacy behavior, `long` = budgeted assembly |
| `ARES_CONTEXT_WINDOW` | `32768` | Backend model context size (must match vLLM `--max-model-len`) |
| `ARES_RESERVED_OUTPUT_TOKENS` | `4096` | Tokens reserved for model generation |
| `ARES_CONTEXT_BUDGET_TOKENS` | `0` | Override computed prompt budget (0 = auto) |
| `ARES_CONTEXT_RECENT_TOOL_CALLS` | `20` | Recent tool calls to include in context |
| `ARES_CONTEXT_MEMORY_LIMIT` | `3` | Prior engagement memories to include |
| `ARES_CONTEXT_RETRIEVAL_LIMIT` | `6` | Memory chunks to retrieve per query |
| `ARES_CONTEXT_INCLUDE_RAW` | `false` | Include raw tool excerpts in context |
| `ARES_CONTEXT_RAW_EXCERPT_CHARS` | `6000` | Max chars for raw excerpts |

## Troubleshooting

### OOM on vLLM startup
- Reduce `--max-model-len` to 128K or 64K
- Reduce `--max-num-batched-tokens` to 16384
- Ensure no other GPU processes are running

### Context budget exhausted
- Reduce `ARES_CONTEXT_RECENT_TOOL_CALLS`
- Reduce `ARES_CONTEXT_RETRIEVAL_LIMIT`
- Set `ARES_CONTEXT_INCLUDE_RAW=false`

### Memory search returns no results
- Ensure tool calls are completing successfully (only successful calls are indexed by default)
- Check that `memory_chunks` table exists in `state.db`
- Verify FTS5 is available: `python -c "import sqlite3; sqlite3.connect(':memory:').execute('CREATE VIRTUAL TABLE t USING fts5(x)')"`

## Security Notes

- All evidence presented to the model is explicitly labeled as **untrusted**.
- Raw tool output is never treated as operator instructions.
- The model cannot execute tools via recall tools — they are strictly read-only (`risk: passive`).
- Cross-session evidence recall (`ares.evidence.get_tool_call` with different `session_id`) requires operator approval.
- Secrets are redacted using pattern matching before storage and recall.

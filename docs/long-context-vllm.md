# Long-Context vLLM Setup for Ares

This document describes running Ares with a long-context model behind vLLM for larger evidence-heavy authorized assessment sessions.

## Recommended model

`Qwen/Qwen2.5-7B-Instruct-1M` is the recommended model for this experiment.

- Parameters: 7.61B
- Official max context: 1,010,000 tokens
- Official max generation: 8192 tokens
- Full 1M context requires at least 120 GB VRAM per Qwen documentation

On a single 80 GB A100, start at 128K. Then test 256K after 128K is stable. Do not assume 512K or 1M will fit.

## vLLM server setup

Install vLLM:

```bash
python -m pip install -U vllm
```

Start with 128K context:

```bash
vllm serve Qwen/Qwen2.5-7B-Instruct-1M \
  --host 0.0.0.0 \
  --port 8000 \
  --max-model-len 131072 \
  --enable-chunked-prefill \
  --max-num-batched-tokens 32768 \
  --max-num-seqs 1
```

For 256K context after 128K is stable:

```bash
vllm serve Qwen/Qwen2.5-7B-Instruct-1M \
  --host 0.0.0.0 \
  --port 8000 \
  --max-model-len 262144 \
  --enable-chunked-prefill \
  --max-num-batched-tokens 32768 \
  --max-num-seqs 1
```

## Ares configuration

```bash
export LLM_PROVIDER=custom
export LLM_MODEL="Qwen/Qwen2.5-7B-Instruct-1M"
export OPENAI_BASE_URL="http://127.0.0.1:8000/v1"
export OPENAI_API_KEY="local-not-used"

export ARES_CONTEXT_MODE=long
export ARES_CONTEXT_WINDOW=131072
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

## Test command

```bash
ares doctor

ares run \
  --target 127.0.0.1 \
  --prompt "Use only passive inspection. Summarize available context and stop." \
  --max-iterations 3
```

## How it works

When `ARES_CONTEXT_MODE=long` is set, `ContextBuilder` uses a budgeted prompt assembly path instead of only a small recent-history summary.

The long-context path can include:

- current engagement state
- scope and target summary
- known hosts and services
- active findings
- recent tool-call summaries labeled as untrusted current-session evidence
- retrieved memory chunks labeled as untrusted prior memory
- prior engagement memory labeled as untrusted prior memory
- optional raw excerpts labeled as untrusted raw tool output, only when `ARES_CONTEXT_INCLUDE_RAW=true`

The recall tools are passive:

- `ares.memory.search` searches memory chunks by query
- `ares.evidence.get_tool_call` retrieves a bounded, redacted excerpt of a current-session tool call

Useful tool results and error summaries are indexed into SQLite `memory_chunks` with FTS5 search when available and LIKE fallback otherwise. Secrets such as API keys, tokens, passwords, and Bearer tokens are redacted from memory, recall, and training export.

## Training-data export

Ares does not implement automatic online training. The supported path is a reviewed JSONL export from completed sessions:

```bash
ares training --out data/ares-sft.jsonl --min-status final_response
```

This exports sessions that match the configured status, have a final response, and pass the export filters in `src/ares/training/export.py`.

## Environment variables reference

| Variable | Default | Description |
|----------|---------|-------------|
| `ARES_CONTEXT_MODE` | `compact` | `compact` = compact summaries, `long` = budgeted assembly |
| `ARES_CONTEXT_WINDOW` | `32768` | Backend model context size, should match vLLM `--max-model-len` |
| `ARES_RESERVED_OUTPUT_TOKENS` | `4096` | Tokens reserved for model generation |
| `ARES_CONTEXT_BUDGET_TOKENS` | `0` | Override computed prompt budget, 0 = auto |
| `ARES_CONTEXT_RECENT_TOOL_CALLS` | `20` | Recent tool calls to include in context |
| `ARES_CONTEXT_MEMORY_LIMIT` | `3` | Prior engagement memories to include |
| `ARES_CONTEXT_RETRIEVAL_LIMIT` | `6` | Memory chunks to retrieve per query |
| `ARES_CONTEXT_INCLUDE_RAW` | `false` | Include raw tool excerpts in context |
| `ARES_CONTEXT_RAW_EXCERPT_CHARS` | `6000` | Max chars for raw excerpts |

## Troubleshooting

If vLLM fails to start because of memory pressure, reduce `--max-model-len` to 128K or 64K and reduce `--max-num-batched-tokens` to 16384.

If the context budget is exhausted, reduce `ARES_CONTEXT_RECENT_TOOL_CALLS`, reduce `ARES_CONTEXT_RETRIEVAL_LIMIT`, and keep `ARES_CONTEXT_INCLUDE_RAW=false`.

If memory search returns no results, confirm that useful tool calls have been executed and that the `memory_chunks` table exists in `state.db`.

FTS5 check:

```bash
python -c "import sqlite3; sqlite3.connect(':memory:').execute('CREATE VIRTUAL TABLE t USING fts5(x)')"
```

## Security notes

- Evidence presented to the model is labeled as untrusted.
- Raw tool output is never treated as operator instructions.
- Recall tools are read-only and passive.
- Cross-session raw tool-call recall requires operator approval before it should be exposed.
- Secrets are redacted using pattern matching before storage and recall.

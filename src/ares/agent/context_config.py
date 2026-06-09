from __future__ import annotations

from dataclasses import dataclass
from typing import Literal, Mapping
import os


@dataclass(frozen=True)
class ContextConfig:
    mode: Literal["compact", "long"] = "compact"
    context_window: int = 32768
    reserved_output_tokens: int = 4096
    budget_tokens: int = 0
    recent_tool_calls: int = 20
    memory_limit: int = 3
    raw_excerpt_chars: int = 6000
    include_raw_excerpts: bool = False
    retrieval_limit: int = 6
    section_header_tokens: int = 256

    @property
    def usable_budget_tokens(self) -> int:
        if self.budget_tokens > 0:
            return self.budget_tokens
        return max(4096, self.context_window - self.reserved_output_tokens)


def parse_bool(value: str | None, default: bool = False) -> bool:
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


def parse_int(value: str | None, default: int, *, minimum: int = 0) -> int:
    if value is None or not str(value).strip():
        return default
    try:
        parsed = int(str(value).strip())
    except ValueError:
        return default
    return max(minimum, parsed)


def load_context_config(env: Mapping[str, str] | None = None) -> ContextConfig:
    env = env or os.environ
    mode = str(env.get("ARES_CONTEXT_MODE", "compact")).strip().lower()
    if mode not in {"compact", "long"}:
        mode = "compact"

    return ContextConfig(
        mode=mode,  # type: ignore[arg-type]
        context_window=parse_int(env.get("ARES_CONTEXT_WINDOW"), 32768, minimum=8192),
        reserved_output_tokens=parse_int(env.get("ARES_RESERVED_OUTPUT_TOKENS"), 4096, minimum=512),
        budget_tokens=parse_int(env.get("ARES_CONTEXT_BUDGET_TOKENS"), 0, minimum=0),
        recent_tool_calls=parse_int(env.get("ARES_CONTEXT_RECENT_TOOL_CALLS"), 20, minimum=1),
        memory_limit=parse_int(env.get("ARES_CONTEXT_MEMORY_LIMIT"), 3, minimum=0),
        raw_excerpt_chars=parse_int(env.get("ARES_CONTEXT_RAW_EXCERPT_CHARS"), 6000, minimum=0),
        include_raw_excerpts=parse_bool(env.get("ARES_CONTEXT_INCLUDE_RAW"), False),
        retrieval_limit=parse_int(env.get("ARES_CONTEXT_RETRIEVAL_LIMIT"), 6, minimum=0),
    )

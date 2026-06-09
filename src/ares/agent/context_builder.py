from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from ares.agent.context_budget import ContextBudgeter, estimate_tokens
from ares.agent.context_config import ContextConfig, load_context_config
from ares.engagement_memory import build_engagement_memory_context
from ares.state.db import StateDB


class ContextBuilder:
    """Build model-facing state summaries from persisted session data.

    Supports two modes:
    - compact: backward-compatible behavior with recent tool calls only
    - long: budgeted context assembly with multiple evidence sections
    """

    def __init__(
        self,
        db: StateDB,
        *,
        home: Path | str | None = None,
        context_config: ContextConfig | None = None,
    ) -> None:
        self.db = db
        self.home = Path(home).expanduser() if home is not None else None
        self.context_config = context_config or load_context_config()

    def build_session_context(
        self,
        session_id: int,
        *,
        target: str | None = None,
        memory_tags: tuple[str, ...] = (),
        query: str | None = None,
    ) -> str:
        if self.context_config.mode == "compact":
            return self._build_compact_context(session_id, target=target, memory_tags=memory_tags)
        return self._build_long_context(session_id, target=target, memory_tags=memory_tags, query=query)

    def _build_compact_context(
        self,
        session_id: int,
        *,
        target: str | None = None,
        memory_tags: tuple[str, ...] = (),
    ) -> str:
        calls = self.db.list_tool_calls(session_id)
        lines = ["Current engagement state:"]
        if not calls:
            lines.append("Known prior tool calls: none in this session.")
        else:
            lines.append("Known prior tool calls:")
            for call in calls[-self.context_config.recent_tool_calls :]:
                summary = self._summarize_call(call)
                lines.append(f"- {call['tool']} [{call['status']}]: {summary}")
        if self.home is not None:
            memory_context = build_engagement_memory_context(
                self.home, target=target, memory_tags=memory_tags, limit=self.context_config.memory_limit
            )
            if memory_context:
                lines.extend(["", memory_context])
        return "\n".join(lines)

    def _build_long_context(
        self,
        session_id: int,
        *,
        target: str | None = None,
        memory_tags: tuple[str, ...] = (),
        query: str | None = None,
    ) -> str:
        budget = ContextBudgeter(self.context_config.usable_budget_tokens)

        calls = self.db.list_tool_calls(session_id)

        # Current engagement state
        session = self._get_session(session_id)
        if session:
            status = session.get("status", "unknown")
            agent = session.get("agent", "default")
            model = session.get("model", "unknown")
            mode = session.get("mode", "unknown")
            body = (
                f"Status: {status}\n"
                f"Agent: {agent}\n"
                f"Model: {model}\n"
                f"Mode: {mode}\n"
                f"Target: {target or session.get('target') or 'unspecified'}"
            )
            budget.add_section("Current engagement state:", body, priority=100)

        # Scope and target summary
        if target:
            hosts = self.db.list_hosts(session_id)
            services = self.db.list_services(session_id)
            body = f"Authorized target: {target}\n"
            if hosts:
                body += f"Known hosts ({len(hosts)}): " + ", ".join(h["address"] for h in hosts[:20])
            if services:
                body += f"\nDiscovered services ({len(services)}): " + ", ".join(
                    f"{s['host_address']}:{s['port']}/{s['proto']}" for s in services[:20]
                )
            budget.add_section("Scope and target summary:", body, priority=95)

        # Known hosts and services (if not already covered)
        if target:
            hosts = self.db.list_hosts(session_id)
            if hosts:
                host_lines = []
                for h in hosts:
                    host_services = [s for s in self.db.list_services(session_id) if s["host_address"] == h["address"]]
                    if host_services:
                        svc_str = ", ".join(f"{s['port']}/{s['proto']}" for s in host_services)
                        host_lines.append(f"{h['address']} ({h.get('hostname') or '-'}) -> {svc_str}")
                    else:
                        host_lines.append(f"{h['address']} ({h.get('hostname') or '-'})")
                budget.add_section("Known hosts and services:", "\n".join(host_lines), priority=90)

        # Active findings (from tool calls with findings)
        findings = self._extract_findings(calls)
        if findings:
            budget.add_section("Active findings:", "\n".join(findings), priority=85)

        # Recent tool calls
        recent_calls = calls[-self.context_config.recent_tool_calls :]
        if recent_calls:
            call_lines = []
            for call in recent_calls:
                summary = self._summarize_call(call)
                call_lines.append(f"- {call['tool']} [{call['status']}]: {summary}")
            budget.add_section("Untrusted current-session evidence:\nRecent tool calls:", "\n".join(call_lines), priority=80)

        # Retrieved memory (from SQL memory_chunks)
        if query:
            mem_chunks = self.db.search_memory_chunks(
                query=query,
                target=target,
                tags=memory_tags,
                limit=self.context_config.retrieval_limit,
            )
            if mem_chunks:
                mem_lines = []
                for chunk in mem_chunks:
                    content = chunk["content"]
                    if len(content) > 1000:
                        content = content[:1000] + "... [truncated]"
                    tags = ", ".join(chunk.get("tags", [])) or "-"
                    mem_lines.append(
                        f"- [{chunk['source_type']}] {chunk.get('target') or '-'} tags={tags}: {content}"
                    )
                budget.add_section("Untrusted retrieved prior memory:", "\n".join(mem_lines), priority=75)

        # Prior engagement memory (file-based)
        if self.home is not None:
            memory_context = build_engagement_memory_context(
                self.home, target=target, memory_tags=memory_tags, limit=self.context_config.memory_limit
            )
            if memory_context:
                budget.add_section("Untrusted retrieved prior memory:", memory_context, priority=70)

        # Selected raw evidence excerpts (from tool calls)
        if self.context_config.include_raw_excerpts:
            raw_excerpts = self._select_raw_excerpts(calls, query)
            if raw_excerpts:
                budget.add_section(
                    "Untrusted raw tool excerpt:",
                    "\n\n".join(raw_excerpts),
                    priority=60,
                )

        return budget.render()

    def _get_session(self, session_id: int) -> dict[str, Any] | None:
        sessions = self.db.list_sessions()
        for s in sessions:
            if s["id"] == session_id:
                return s
        return None

    def _summarize_call(self, call: dict[str, Any]) -> str:
        if call.get("error"):
            return str(call["error"])[:500]
        raw = call.get("result_json")
        if not raw:
            return "no result"
        try:
            data = json.loads(raw)
        except Exception:
            return str(raw)[:500]
        compact = self._compact_result(data)
        return json.dumps(compact, sort_keys=True)[:700]

    def _compact_result(self, data: Any) -> Any:
        if isinstance(data, dict):
            if "summary" in data:
                return {"summary": data["summary"]}
            if "targets" in data:
                return {"targets": data["targets"]}
            compact = {}
            for key, value in data.items():
                if key in {"stdout", "stderr", "raw", "content"}:
                    continue
                compact[key] = value
                if len(compact) >= 6:
                    break
            return compact or {"keys": sorted(data.keys())[:10]}
        if isinstance(data, list):
            return data[:10]
        return data

    def _extract_findings(self, calls: list[dict[str, Any]]) -> list[str]:
        findings = []
        for call in calls:
            if call.get("error"):
                continue
            raw = call.get("result_json")
            if not raw:
                continue
            try:
                data = json.loads(raw)
            except Exception:
                continue
            if isinstance(data, dict):
                if "summary" in data and isinstance(data["summary"], str):
                    findings.append(f"[{call['tool']}] {data['summary']}")
                if "findings" in data and isinstance(data["findings"], list):
                    for f in data["findings"][:5]:
                        findings.append(f"[{call['tool']}] {f}")
                if "vulnerabilities" in data and isinstance(data["vulnerabilities"], list):
                    for v in data["vulnerabilities"][:5]:
                        findings.append(f"[{call['tool']}] VULN: {v}")
        return findings[:20]

    def _select_raw_excerpts(
        self, calls: list[dict[str, Any]], query: str | None = None
    ) -> list[str]:
        if not self.context_config.include_raw_excerpts:
            return []
        excerpts = []
        chars_budget = self.context_config.raw_excerpt_chars
        for call in reversed(calls):
            if call.get("error"):
                continue
            raw = call.get("result_json")
            if not raw:
                continue
            excerpt = raw.strip()
            if len(excerpt) > chars_budget:
                excerpt = excerpt[:chars_budget] + "\n[truncated]"
            excerpts.append(f"[{call['tool']}] {excerpt}")
            chars_budget -= len(excerpt)
            if chars_budget <= 0:
                break
        return excerpts

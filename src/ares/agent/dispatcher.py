from __future__ import annotations

import concurrent.futures
import time
from typing import Any, Callable

from ares.agent.runtime import ToolCall, ToolResult
from ares.agent.tool_result_indexer import should_index_tool_result, tool_result_to_memory_text
from ares.policy.context import PolicyContext
from ares.policy.risk import RISK_ORDER, risk_allows
from ares.policy.route import RoutePolicy
from ares.tools.registry import ToolRegistry


class ToolDispatcher:
    """Central Hermes-style tool-call choke point.

    It validates through policy, dispatches via the registry, compacts the
    model-facing result, and persists the full raw result when a recorder is
    attached.
    """

    def __init__(
        self,
        *,
        registry: ToolRegistry,
        policy: PolicyContext,
        recorder: Any | None = None,
        session_id: int | None = None,
        approval_callback: Callable[[ToolCall, Any], bool] | None = None,
        approval_required_risks: set[str] | None = None,
        route_policy: RoutePolicy | None = None,
        tool_timeout_seconds: float | None = None,
        engagement_id: str | None = None,
    ) -> None:
        self.registry = registry
        self.policy = policy
        self.recorder = recorder
        self.session_id = session_id
        self.approval_callback = approval_callback
        self.approval_required_risks = approval_required_risks or {"exploit", "post-exploitation"}
        self.route_policy = route_policy or RoutePolicy()
        self.tool_timeout_seconds = tool_timeout_seconds
        self.engagement_id = engagement_id

    def dispatch(self, call: ToolCall) -> ToolResult:
        started = time.perf_counter()
        raw_result: Any = None
        try:
            entry = self.registry.get_entry(call.name)
            if entry is None:
                raise KeyError(f"unknown tool: {call.name}")
            effective_risk = entry.risk
            if call.required_risk is not None:
                if call.required_risk not in RISK_ORDER:
                    raise ValueError(f"unknown required risk level: {call.required_risk}")
                if RISK_ORDER[call.required_risk] > RISK_ORDER[effective_risk]:
                    effective_risk = call.required_risk
            if not risk_allows(self.policy.max_risk, effective_risk):
                raise PermissionError(
                    f"risk policy violation: tool {call.name!r} effective risk "
                    f"{effective_risk!r} exceeds max {self.policy.max_risk!r}"
                )
            if self._is_duplicate_success(call):
                raise RuntimeError("duplicate_successful_action: identical tool call already succeeded in this session")
            if effective_risk in self.approval_required_risks:
                if self.approval_callback is None or not self.approval_callback(call, entry):
                    raise PermissionError(
                        f"approval denied for tool {call.name!r} with effective risk {effective_risk!r}"
                    )
            target = self._target_from_args(call.args)
            with self.route_policy.apply_for_target(target):
                raw_result = self._dispatch_registry(call)
            compact_result = self._compact_tool_result(raw_result)
            result = ToolResult(
                tool=call.name,
                args=call.args,
                status="ok",
                result=compact_result,
                duration_ms=self._duration_ms(started),
            )
            self._record(result, raw_result=raw_result)
            self._index_memory(result, raw_result=raw_result)
            return result
        except Exception as exc:
            result = ToolResult(
                tool=call.name,
                args=call.args,
                status="error",
                error=str(exc),
                duration_ms=self._duration_ms(started),
            )
            self._record(result, raw_result=None)
            self._index_memory(result, raw_result=None)
            return result

    def _dispatch_registry(self, call: ToolCall) -> Any:
        context: dict[str, Any] = {"policy": self.policy}
        if self.engagement_id is not None:
            context["engagement_id"] = self.engagement_id
        if self.tool_timeout_seconds is None:
            return self.registry.dispatch(call.name, call.args, **context)
        with concurrent.futures.ThreadPoolExecutor(max_workers=1) as executor:
            future = executor.submit(
                self.registry.dispatch,
                call.name,
                call.args,
                **context,
            )
            try:
                return future.result(timeout=self.tool_timeout_seconds)
            except concurrent.futures.TimeoutError as exc:
                future.cancel()
                raise TimeoutError(f"tool {call.name!r} timed out after {self.tool_timeout_seconds} seconds") from exc

    def _record(self, result: ToolResult, *, raw_result: Any) -> None:
        if self.recorder is None or self.session_id is None:
            return
        self.recorder.record_tool_call(
            session_id=self.session_id,
            tool=result.tool,
            args=result.args,
            status=result.status,
            result=raw_result if result.status == "ok" else result.result,
            error=result.error,
            duration_ms=result.duration_ms,
        )

    def _index_memory(self, result: ToolResult, *, raw_result: Any) -> None:
        """Index useful tool results into memory_chunks for long-context retrieval."""
        if self.recorder is None or self.session_id is None:
            return
        if not hasattr(self.recorder, "add_memory_chunk"):
            return
        try:
            if not should_index_tool_result(result.tool, result.status, raw_result):
                return
            # Determine target from args
            target = self._target_from_args(result.args)
            # Determine tags based on tool name and result
            tags = self._infer_tags(result.tool, raw_result, result.status)
            memory_text = tool_result_to_memory_text(
                tool_name=result.tool,
                status=result.status,
                args=result.args,
                result=raw_result if result.status == "ok" else result.result,
                error=result.error,
            )
            self.recorder.add_memory_chunk(
                session_id=self.session_id,
                source_type="tool_call",
                source_id=result.tool,
                target=target,
                tags=tags,
                content=memory_text,
            )
        except Exception:
            # Indexing must never interfere with tool execution
            pass

    def _infer_tags(self, tool_name: str, result: Any, status: str) -> list[str]:
        tags = []
        if status != "ok":
            tags.append("error")
        # Tool-specific tags
        if any(kw in tool_name.lower() for kw in ("scan", "nmap", "masscan", "recon", "discover", "enumerate")):
            tags.append("recon")
        if any(kw in tool_name.lower() for kw in ("exploit", "poc", "cve", "vuln")):
            tags.append("vuln")
        if any(kw in tool_name.lower() for kw in ("post", "pivot", "lateral", "persist", "cred")):
            tags.append("post-exploitation")
        if any(kw in tool_name.lower() for kw in ("web", "http", "burp", "zap", "nikto", "dirb", "gobuster")):
            tags.append("web")
        if any(kw in tool_name.lower() for kw in ("ssh", "rdp", "smb", "winrm", "ldap", "kerberos")):
            tags.append("auth")
        # Content-based tags
        if isinstance(result, dict):
            if "vulnerabilities" in result or "findings" in result:
                tags.append("finding")
            if "targets" in result or "hosts" in result:
                tags.append("target")
        return tags

    def _is_duplicate_success(self, call: ToolCall) -> bool:
        if self.recorder is None or self.session_id is None:
            return False
        has_success = getattr(self.recorder, "has_successful_tool_call", None)
        if has_success is None:
            return False
        return bool(has_success(session_id=self.session_id, tool=call.name, args=call.args))

    @staticmethod
    def _target_from_args(args: dict[str, Any]) -> str | None:
        for key in ("target", "host", "ip", "url", "base_url"):
            value = args.get(key)
            if isinstance(value, str) and value.strip():
                return value.strip()
        for key in ("targets", "hosts", "urls"):
            value = args.get(key)
            if isinstance(value, list) and value:
                return str(value[0])
            if isinstance(value, str) and value.strip():
                return value.replace("\n", ";").split(";")[0].strip()
        return None

    def _compact_tool_result(self, raw_result: Any) -> Any:
        if isinstance(raw_result, dict):
            if "summary" in raw_result:
                return {"summary": raw_result["summary"]}
            if "targets" in raw_result:
                return {"targets": raw_result["targets"]}
            compact = {}
            for key, value in raw_result.items():
                if key in {"stdout", "stderr", "raw", "content"}:
                    continue
                compact[key] = value
                if len(compact) >= 8:
                    break
            if compact:
                return compact
            return {"keys": sorted(raw_result.keys())[:10]}
        return raw_result

    @staticmethod
    def _duration_ms(started: float) -> int:
        return int((time.perf_counter() - started) * 1000)

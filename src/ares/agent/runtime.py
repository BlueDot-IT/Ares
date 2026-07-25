from __future__ import annotations

import json
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Protocol

from ares.policy.context import PolicyContext
from ares.tools.registry import ToolRegistry


@dataclass(frozen=True)
class ToolCall:
    name: str
    args: dict[str, Any] = field(default_factory=dict)
    id: str = "tool-call"
    required_risk: str | None = None


@dataclass(frozen=True)
class ModelResponse:
    final_text: str | None = None
    tool_calls: list[ToolCall] = field(default_factory=list)


@dataclass(frozen=True)
class ToolResult:
    tool: str
    args: dict[str, Any]
    status: str
    result: Any = None
    error: str = ""
    duration_ms: int = 0


@dataclass(frozen=True)
class RuntimeResult:
    final_response: str
    stop_reason: str
    messages: list[dict[str, Any]]
    tool_results: list[ToolResult]


class ModelClient(Protocol):
    def complete(self, messages: list[dict[str, Any]], tools: list[dict[str, Any]]) -> ModelResponse:
        ...


class StreamingModelClient(ModelClient, Protocol):
    def complete_with_events(
        self,
        messages: list[dict[str, Any]],
        tools: list[dict[str, Any]],
        event_callback: Callable[[dict[str, Any]], None],
    ) -> ModelResponse:
        ...


class ToolCallRecorder(Protocol):
    def record_tool_call(
        self,
        *,
        session_id: int,
        tool: str,
        args: dict[str, Any],
        status: str,
        result: Any = None,
        error: str = "",
        duration_ms: int = 0,
    ) -> int:
        ...


class AgentRuntime:
    """First-pass Hermes-like tool-calling runtime.

    The runtime intentionally keeps policy enforcement outside the model. The
    model may request tool calls, but dispatch runs through ToolRegistry with a
    PolicyContext before any handler executes.
    """

    def __init__(
        self,
        *,
        model: ModelClient,
        registry: ToolRegistry,
        policy: PolicyContext | None = None,
        enabled_toolsets: set[str] | None = None,
        disabled_toolsets: set[str] | None = None,
        max_iterations: int = 20,
        recorder: ToolCallRecorder | None = None,
        session_id: int | None = None,
        system_prompt: str | None = None,
        context_summary: str | None = None,
        dispatcher: Any | None = None,
        event_callback: Callable[[dict[str, Any]], None] | None = None,
    ) -> None:
        self.model = model
        self.registry = registry
        self.policy = policy or PolicyContext()
        self.enabled_toolsets = enabled_toolsets
        self.disabled_toolsets = disabled_toolsets
        self.max_iterations = max_iterations
        self.recorder = recorder
        self.session_id = session_id
        self.system_prompt = system_prompt
        self.context_summary = context_summary
        self.dispatcher = dispatcher
        self.event_callback = event_callback
        self.tools = self.registry.get_tool_definitions(
            enabled_toolsets=self.enabled_toolsets,
            disabled_toolsets=self.disabled_toolsets,
            max_risk=self.policy.max_risk,
        )

    def run(self, user_message: str) -> RuntimeResult:
        messages: list[dict[str, Any]] = []
        if self.system_prompt:
            messages.append({"role": "system", "content": self.system_prompt})
        if self.context_summary:
            messages.append({"role": "user", "content": self.context_summary})
        messages.append({"role": "user", "content": user_message})
        tool_results: list[ToolResult] = []

        for _iteration in range(self.max_iterations):
            response = self._complete(messages)
            if response.final_text is not None and not response.tool_calls:
                messages.append({"role": "assistant", "content": response.final_text})
                self._emit_event(
                    {
                        "type": "final_response",
                        "final_response": response.final_text,
                        "message": response.final_text,
                    }
                )
                return RuntimeResult(
                    final_response=response.final_text,
                    stop_reason="final_response",
                    messages=messages,
                    tool_results=tool_results,
                )

            if not response.tool_calls:
                messages.append({"role": "assistant", "content": response.final_text or ""})
                return RuntimeResult(
                    final_response=response.final_text or "",
                    stop_reason="empty_response",
                    messages=messages,
                    tool_results=tool_results,
                )

            messages.append(
                {
                    "role": "assistant",
                    "content": response.final_text or "",
                    "tool_calls": [self._tool_call_message(call) for call in response.tool_calls],
                }
            )
            for call in response.tool_calls:
                self._emit_event(
                    {
                        "type": "tool_call",
                        "tool": call.name,
                        "args": dict(call.args),
                        "message": f"{call.name} {json.dumps(call.args, sort_keys=True)}",
                    }
                )
                tool_result = self._execute_tool_call(call)
                if self.dispatcher is None:
                    self._record_tool_result(tool_result)
                tool_results.append(tool_result)
                self._emit_event(
                    {
                        "type": "tool_result",
                        "tool": tool_result.tool,
                        "status": tool_result.status,
                        "duration_ms": tool_result.duration_ms,
                        "message": self._tool_result_event_message(tool_result),
                        "error": tool_result.error,
                    }
                )
                messages.append(
                    {
                        "role": "tool",
                        "tool_call_id": call.id,
                        "name": call.name,
                        "content": json.dumps(self._tool_result_payload(tool_result), sort_keys=True),
                    }
                )

        return RuntimeResult(
            final_response="",
            stop_reason="max_iterations",
            messages=messages,
            tool_results=tool_results,
        )

    def _complete(self, messages: list[dict[str, Any]]) -> ModelResponse:
        complete_with_events = getattr(self.model, "complete_with_events", None)
        if callable(complete_with_events):
            return complete_with_events(messages, self.tools, self._emit_event)
        return self.model.complete(messages, self.tools)

    def _execute_tool_call(self, call: ToolCall) -> ToolResult:
        if self.dispatcher is not None:
            return self.dispatcher.dispatch(call)
        started = time.perf_counter()
        try:
            result = self.registry.dispatch(call.name, call.args, policy=self.policy)
        except Exception as exc:
            return ToolResult(
                tool=call.name,
                args=call.args,
                status="error",
                error=str(exc),
                duration_ms=self._duration_ms(started),
            )
        return ToolResult(
            tool=call.name,
            args=call.args,
            status="ok",
            result=result,
            duration_ms=self._duration_ms(started),
        )

    def _record_tool_result(self, tool_result: ToolResult) -> None:
        if self.recorder is None or self.session_id is None:
            return
        self.recorder.record_tool_call(
            session_id=self.session_id,
            tool=tool_result.tool,
            args=tool_result.args,
            status=tool_result.status,
            result=tool_result.result,
            error=tool_result.error,
            duration_ms=tool_result.duration_ms,
        )

    @staticmethod
    def _duration_ms(started: float) -> int:
        return int((time.perf_counter() - started) * 1000)

    @staticmethod
    def _tool_call_message(call: ToolCall) -> dict[str, Any]:
        return {
            "id": call.id,
            "type": "function",
            "function": {"name": call.name, "arguments": json.dumps(call.args, sort_keys=True)},
        }

    @staticmethod
    def _tool_result_payload(tool_result: ToolResult) -> dict[str, Any]:
        if tool_result.status == "ok":
            return {"status": "ok", "result": tool_result.result}
        return {"status": "error", "error": tool_result.error}

    @staticmethod
    def _tool_result_event_message(tool_result: ToolResult) -> str:
        if tool_result.status != "ok":
            return tool_result.error or f"{tool_result.tool} failed"
        result = tool_result.result
        if isinstance(result, dict):
            for key in ("summary", "stdout", "result"):
                value = result.get(key)
                if isinstance(value, str) and value.strip():
                    return value.strip()
        if result is None:
            return f"{tool_result.tool} ok"
        return str(result)

    def _emit_event(self, event: dict[str, Any]) -> None:
        if self.event_callback is not None:
            self.event_callback(event)

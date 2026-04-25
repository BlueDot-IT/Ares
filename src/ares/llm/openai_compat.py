from __future__ import annotations

import json
from typing import Any

from .base import ModelResponse, ToolCall
from .common import emit_text_stream


class OpenAICompatModel:
    """Adapter for OpenAI-compatible chat completion APIs.

    The adapter accepts an injected client for tests/local servers. If no client
    is provided, it lazily imports the OpenAI SDK and creates one.
    """

    def __init__(
        self,
        *,
        model: str,
        client: Any | None = None,
        base_url: str | None = None,
        api_key: str | None = None,
        provider: str = "openai",
        temperature: float = 0,
        max_tokens: int | None = None,
    ) -> None:
        self.model = model
        self.provider = provider
        self.client = client or self._create_client(base_url=base_url, api_key=api_key)
        self.temperature = temperature
        self.max_tokens = max_tokens

    def complete(self, messages: list[dict[str, Any]], tools: list[dict[str, Any]]) -> ModelResponse:
        kwargs: dict[str, Any] = {
            "model": self.model,
            "messages": messages,
            "temperature": self.temperature,
        }
        if tools:
            kwargs["tools"] = tools
            kwargs["tool_choice"] = "auto"
        else:
            kwargs["tools"] = tools
        if self.max_tokens is not None:
            kwargs["max_tokens"] = self.max_tokens

        response = self.client.chat.completions.create(**kwargs)
        message = response.choices[0].message
        tool_calls = getattr(message, "tool_calls", None) or []
        if tool_calls:
            return ModelResponse(
                final_text=getattr(message, "content", None),
                tool_calls=[self._convert_tool_call(call) for call in tool_calls],
            )
        return ModelResponse(final_text=getattr(message, "content", "") or "")

    def complete_with_events(self, messages: list[dict[str, Any]], tools: list[dict[str, Any]], event_callback: Any) -> ModelResponse:
        response = self.complete(messages, tools)
        emit_text_stream(provider=self.provider, text=response.final_text, event_callback=event_callback)
        return response

    @staticmethod
    def _convert_tool_call(call: Any) -> ToolCall:
        function = getattr(call, "function", None)
        name = getattr(function, "name", "") if function is not None else ""
        raw_args = getattr(function, "arguments", "{}") if function is not None else "{}"
        try:
            parsed = json.loads(raw_args or "{}")
        except json.JSONDecodeError:
            parsed = {}
        if not isinstance(parsed, dict):
            parsed = {}
        return ToolCall(
            id=getattr(call, "id", "tool-call"),
            name=name,
            args=parsed,
        )

    @staticmethod
    def _create_client(*, base_url: str | None, api_key: str | None) -> Any:
        try:
            from openai import OpenAI
        except Exception as exc:  # pragma: no cover - only hit without dependency
            raise RuntimeError("openai package is required for OpenAICompatModel") from exc
        kwargs: dict[str, Any] = {}
        if base_url is not None:
            kwargs["base_url"] = base_url
        if api_key is not None:
            kwargs["api_key"] = api_key
        return OpenAI(**kwargs)

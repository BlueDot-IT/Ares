from __future__ import annotations

from typing import Any

from .base import ModelResponse, ToolCall
from .common import emit_text_stream, get_field, parse_json_object, to_text


class AnthropicModel:
    def __init__(
        self,
        *,
        model: str,
        client: Any | None = None,
        api_key: str | None = None,
        provider: str = "anthropic",
        temperature: float = 0,
        max_tokens: int = 4096,
    ) -> None:
        self.model = model
        self.provider = provider
        self.client = client or self._create_client(api_key=api_key)
        self.temperature = temperature
        self.max_tokens = max_tokens

    def complete(self, messages: list[dict[str, Any]], tools: list[dict[str, Any]]) -> ModelResponse:
        system, anthropic_messages = self._convert_messages(messages)
        kwargs: dict[str, Any] = {
            "model": self.model,
            "messages": anthropic_messages,
            "max_tokens": self.max_tokens,
            "temperature": self.temperature,
        }
        if system:
            kwargs["system"] = system
        if tools:
            kwargs["tools"] = [self._convert_tool(tool) for tool in tools]

        response = self.client.messages.create(**kwargs)
        return self._convert_response(response)

    def complete_with_events(self, messages: list[dict[str, Any]], tools: list[dict[str, Any]], event_callback: Any) -> ModelResponse:
        response = self.complete(messages, tools)
        emit_text_stream(provider=self.provider, text=response.final_text, event_callback=event_callback)
        return response

    @classmethod
    def _create_client(cls, *, api_key: str | None) -> Any:
        try:
            from anthropic import Anthropic
        except Exception as exc:  # pragma: no cover - only hit without dependency
            raise RuntimeError("anthropic package is required for AnthropicModel") from exc
        kwargs: dict[str, Any] = {}
        if api_key is not None:
            kwargs["api_key"] = api_key
        return Anthropic(**kwargs)

    @classmethod
    def _convert_messages(cls, messages: list[dict[str, Any]]) -> tuple[str | None, list[dict[str, Any]]]:
        system_parts: list[str] = []
        converted: list[dict[str, Any]] = []
        for message in messages:
            role = str(message.get("role", "user"))
            if role == "system":
                text = to_text(message.get("content", "")).strip()
                if text:
                    system_parts.append(text)
                continue
            converted_message = cls._convert_message(message)
            if not converted_message["content"]:
                continue
            if converted and converted[-1]["role"] == converted_message["role"]:
                converted[-1]["content"].extend(converted_message["content"])
            else:
                converted.append(converted_message)
        system = "\n\n".join(system_parts).strip() or None
        return system, converted

    @classmethod
    def _convert_message(cls, message: dict[str, Any]) -> dict[str, Any]:
        role = str(message.get("role", "user"))
        if role == "assistant":
            content: list[dict[str, Any]] = []
            text = to_text(message.get("content", "")).strip()
            if text:
                content.append({"type": "text", "text": text})
            for tool_call in message.get("tool_calls") or []:
                content.append(cls._convert_tool_call(tool_call))
            return {"role": "assistant", "content": content}
        if role == "tool":
            return {
                "role": "user",
                "content": [
                    {
                        "type": "tool_result",
                        "tool_use_id": str(message.get("tool_call_id") or "tool-call"),
                        "content": to_text(message.get("content", "")),
                    }
                ],
            }
        text = to_text(message.get("content", "")).strip()
        return {"role": "user", "content": ([{"type": "text", "text": text}] if text else [])}

    @staticmethod
    def _convert_tool(tool: dict[str, Any]) -> dict[str, Any]:
        function = tool.get("function", tool)
        return {
            "name": str(function.get("name", "tool")),
            "description": str(function.get("description", function.get("name", "tool"))),
            "input_schema": dict(function.get("parameters", {"type": "object", "properties": {}})),
        }

    @staticmethod
    def _convert_tool_call(tool_call: Any) -> dict[str, Any]:
        function = get_field(tool_call, "function") or {}
        return {
            "type": "tool_use",
            "id": str(get_field(tool_call, "id") or "tool-call"),
            "name": str(get_field(function, "name") or "tool"),
            "input": parse_json_object(get_field(function, "arguments")),
        }

    @classmethod
    def _convert_response(cls, response: Any) -> ModelResponse:
        text_parts: list[str] = []
        tool_calls: list[ToolCall] = []
        for index, block in enumerate(get_field(response, "content") or []):
            block_type = get_field(block, "type")
            if block_type == "text":
                text = to_text(get_field(block, "text")).strip()
                if text:
                    text_parts.append(text)
                continue
            if block_type == "tool_use":
                tool_calls.append(
                    ToolCall(
                        id=str(get_field(block, "id") or f"anthropic-tool-{index}"),
                        name=str(get_field(block, "name") or "tool"),
                        args=parse_json_object(get_field(block, "input")),
                    )
                )
        final_text = "\n".join(text_parts).strip()
        if tool_calls and not final_text:
            return ModelResponse(final_text=None, tool_calls=tool_calls)
        return ModelResponse(final_text=final_text, tool_calls=tool_calls)

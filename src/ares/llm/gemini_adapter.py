from __future__ import annotations

import json
from typing import Any

from .base import ModelResponse, ToolCall
from .common import emit_text_stream, get_field, parse_json_object, to_text


class GeminiModel:
    def __init__(
        self,
        *,
        model: str,
        client: Any | None = None,
        api_key: str | None = None,
        provider: str = "gemini",
        temperature: float = 0,
    ) -> None:
        self.model = model
        self.provider = provider
        self.client = client or self._create_client(api_key=api_key)
        self.temperature = temperature

    def complete(self, messages: list[dict[str, Any]], tools: list[dict[str, Any]]) -> ModelResponse:
        system, contents = self._convert_messages(messages)
        config: dict[str, Any] = {"temperature": self.temperature}
        if system:
            config["system_instruction"] = system
        if tools:
            config["tools"] = [{"function_declarations": [self._convert_tool(tool) for tool in tools]}]

        response = self.client.models.generate_content(
            model=self.model,
            contents=contents,
            config=config,
        )
        return self._convert_response(response)

    def complete_with_events(self, messages: list[dict[str, Any]], tools: list[dict[str, Any]], event_callback: Any) -> ModelResponse:
        response = self.complete(messages, tools)
        emit_text_stream(provider=self.provider, text=response.final_text, event_callback=event_callback)
        return response

    @classmethod
    def _create_client(cls, *, api_key: str | None) -> Any:
        try:
            from google import genai
        except Exception as exc:  # pragma: no cover - only hit without dependency
            raise RuntimeError("google-genai package is required for GeminiModel") from exc
        kwargs: dict[str, Any] = {}
        if api_key is not None:
            kwargs["api_key"] = api_key
        return genai.Client(**kwargs)

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
            if not converted_message["parts"]:
                continue
            if converted and converted[-1]["role"] == converted_message["role"]:
                converted[-1]["parts"].extend(converted_message["parts"])
            else:
                converted.append(converted_message)
        system = "\n\n".join(system_parts).strip() or None
        return system, converted

    @classmethod
    def _convert_message(cls, message: dict[str, Any]) -> dict[str, Any]:
        role = str(message.get("role", "user"))
        if role == "assistant":
            parts: list[dict[str, Any]] = []
            text = to_text(message.get("content", "")).strip()
            if text:
                parts.append({"text": text})
            for tool_call in message.get("tool_calls") or []:
                parts.append(cls._convert_tool_call(tool_call))
            return {"role": "model", "parts": parts}
        if role == "tool":
            response = cls._parse_tool_response(message.get("content", ""))
            return {
                "role": "user",
                "parts": [
                    {
                        "function_response": {
                            "name": str(message.get("name") or "tool"),
                            "response": response,
                        }
                    }
                ],
            }
        text = to_text(message.get("content", "")).strip()
        return {"role": "user", "parts": ([{"text": text}] if text else [])}

    @staticmethod
    def _convert_tool(tool: dict[str, Any]) -> dict[str, Any]:
        function = tool.get("function", tool)
        return {
            "name": str(function.get("name", "tool")),
            "description": str(function.get("description", function.get("name", "tool"))),
            "parameters": dict(function.get("parameters", {"type": "object", "properties": {}})),
        }

    @staticmethod
    def _convert_tool_call(tool_call: Any) -> dict[str, Any]:
        function = get_field(tool_call, "function") or {}
        return {
            "function_call": {
                "name": str(get_field(function, "name") or "tool"),
                "args": parse_json_object(get_field(function, "arguments")),
            }
        }

    @staticmethod
    def _parse_tool_response(value: Any) -> dict[str, Any]:
        if isinstance(value, dict):
            return dict(value)
        if isinstance(value, str):
            try:
                parsed = json.loads(value)
            except json.JSONDecodeError:
                return {"result": value}
            return parsed if isinstance(parsed, dict) else {"result": parsed}
        return {"result": value}

    @classmethod
    def _convert_response(cls, response: Any) -> ModelResponse:
        candidates = get_field(response, "candidates") or []
        if not candidates:
            return ModelResponse(final_text="")
        content = get_field(candidates[0], "content") or {}
        parts = get_field(content, "parts") or []
        text_parts: list[str] = []
        tool_calls: list[ToolCall] = []
        for index, part in enumerate(parts):
            text = get_field(part, "text")
            if text:
                clean = to_text(text).strip()
                if clean:
                    text_parts.append(clean)
            function_call = get_field(part, "function_call", "functionCall")
            if function_call:
                tool_calls.append(
                    ToolCall(
                        id=f"gemini-tool-{index}",
                        name=str(get_field(function_call, "name") or "tool"),
                        args=parse_json_object(get_field(function_call, "args", "arguments")),
                    )
                )
        final_text = "\n".join(text_parts).strip()
        if tool_calls and not final_text:
            return ModelResponse(final_text=None, tool_calls=tool_calls)
        return ModelResponse(final_text=final_text, tool_calls=tool_calls)

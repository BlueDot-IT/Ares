from __future__ import annotations

import base64
import hashlib
import json
import re
from typing import Any, Callable

from .base import ModelResponse, ToolCall
from .common import emit_text_stream


OPENAI_CODEX_BASE_URL = "https://chatgpt.com/backend-api/codex"
OPENAI_CODEX_AUTH_CLAIM = "https://api.openai.com/auth"


def decode_openai_oauth_claims(token: str) -> dict[str, Any]:
    parts = str(token or "").split(".")
    if len(parts) != 3:
        raise ValueError("OpenAI OAuth access token is not a JWT")
    try:
        payload = parts[1]
        decoded = base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4))
        claims = json.loads(decoded)
    except (ValueError, json.JSONDecodeError) as exc:
        raise ValueError("OpenAI OAuth access token has invalid JWT claims") from exc
    if not isinstance(claims, dict):
        raise ValueError("OpenAI OAuth access token has invalid JWT claims")
    return claims


def resolve_openai_codex_account_id(token: str) -> str:
    claims = decode_openai_oauth_claims(token)
    auth_claim = claims.get(OPENAI_CODEX_AUTH_CLAIM)
    if not isinstance(auth_claim, dict):
        raise ValueError("OpenAI OAuth token is missing the Codex account claim")
    account_id = str(auth_claim.get("chatgpt_account_id") or "").strip()
    if not account_id:
        raise ValueError("OpenAI OAuth token is missing the ChatGPT account ID")
    return account_id


class OpenAICodexResponsesModel:
    """ChatGPT OAuth transport for the Codex Responses backend."""

    def __init__(
        self,
        *,
        model: str,
        token_provider: Callable[[], str],
        client: Any | None = None,
        base_url: str = OPENAI_CODEX_BASE_URL,
        provider: str = "openai",
        max_tokens: int | None = None,
    ) -> None:
        self.model = model
        self.provider = provider
        self.token_provider = token_provider
        self.max_tokens = max_tokens
        self.client = client or self._create_client(
            base_url=base_url,
            token_provider=token_provider,
        )

    def complete(
        self,
        messages: list[dict[str, Any]],
        tools: list[dict[str, Any]],
    ) -> ModelResponse:
        converted_tools, projected_names = self._convert_tools(tools)
        original_names = {
            original: projected
            for projected, original in projected_names.items()
        }
        instructions, input_items = self._convert_messages(
            messages,
            original_names,
        )
        request: dict[str, Any] = {
            "model": self.model,
            "instructions": instructions or "You are a helpful assistant.",
            "input": input_items,
            "store": False,
            "text": {"verbosity": "low"},
            "include": ["reasoning.encrypted_content"],
            "extra_headers": self._request_headers(),
        }
        if converted_tools:
            request["tools"] = converted_tools
            request["tool_choice"] = "auto"
            request["parallel_tool_calls"] = True
        if self.max_tokens is not None:
            request["max_output_tokens"] = self.max_tokens

        text_parts: list[str] = []
        tool_calls: list[ToolCall] = []
        with self.client.responses.stream(**request) as stream:
            for event in stream:
                event_type = str(getattr(event, "type", ""))
                if event_type == "response.output_text.delta":
                    text_parts.append(str(getattr(event, "delta", "")))
                elif event_type == "response.output_item.done":
                    item = getattr(event, "item", None)
                    if getattr(item, "type", None) == "function_call":
                        tool_calls.append(
                            self._convert_function_call(item, projected_names)
                        )

        return ModelResponse(
            final_text="".join(text_parts) or None,
            tool_calls=tool_calls,
        )

    def complete_with_events(
        self,
        messages: list[dict[str, Any]],
        tools: list[dict[str, Any]],
        event_callback: Any,
    ) -> ModelResponse:
        response = self.complete(messages, tools)
        emit_text_stream(
            provider=self.provider,
            text=response.final_text,
            event_callback=event_callback,
        )
        return response

    def _request_headers(self) -> dict[str, str]:
        token = self.token_provider()
        return {
            "chatgpt-account-id": resolve_openai_codex_account_id(token),
            "originator": "ares",
            "OpenAI-Beta": "responses=experimental",
        }

    @staticmethod
    def _convert_messages(
        messages: list[dict[str, Any]],
        original_names: dict[str, str],
    ) -> tuple[str, list[dict[str, Any]]]:
        instructions: list[str] = []
        input_items: list[dict[str, Any]] = []
        for message in messages:
            role = str(message.get("role", "")).strip().lower()
            content = message.get("content", "")
            if not isinstance(content, str):
                content = json.dumps(content, sort_keys=True)
            if role == "system":
                if content.strip():
                    instructions.append(content)
                continue
            if role == "tool":
                input_items.append(
                    {
                        "type": "function_call_output",
                        "call_id": str(message.get("tool_call_id") or ""),
                        "output": content,
                    }
                )
                continue
            if role == "assistant":
                if content:
                    input_items.append(
                        {
                            "role": "assistant",
                            "content": [{"type": "output_text", "text": content}],
                        }
                    )
                for call in message.get("tool_calls") or []:
                    function = call.get("function") if isinstance(call, dict) else {}
                    if not isinstance(function, dict):
                        function = {}
                    input_items.append(
                        {
                            "type": "function_call",
                            "call_id": str(call.get("id") or ""),
                            "name": original_names.get(
                                str(function.get("name") or ""),
                                str(function.get("name") or ""),
                            ),
                            "arguments": str(function.get("arguments") or "{}"),
                        }
                    )
                continue
            if role in {"user", "developer"}:
                input_items.append(
                    {
                        "role": role,
                        "content": [{"type": "input_text", "text": content}],
                    }
                )
        return "\n\n".join(instructions), input_items

    @staticmethod
    def _convert_tools(
        tools: list[dict[str, Any]],
    ) -> tuple[list[dict[str, Any]], dict[str, str]]:
        converted: list[dict[str, Any]] = []
        projected_names: dict[str, str] = {}
        for tool in tools:
            function = tool.get("function") if isinstance(tool, dict) else None
            if not isinstance(function, dict):
                continue
            name = str(function.get("name") or "").strip()
            if not name:
                continue
            projected_name = OpenAICodexResponsesModel._project_tool_name(name)
            if (
                projected_name in projected_names
                and projected_names[projected_name] != name
            ):
                raise ValueError(
                    f"Codex tool-name projection collision: {name!r}"
                )
            projected_names[projected_name] = name
            converted.append(
                {
                    "type": "function",
                    "name": projected_name,
                    "description": str(function.get("description") or name),
                    "parameters": function.get("parameters")
                    if isinstance(function.get("parameters"), dict)
                    else {"type": "object", "properties": {}},
                }
            )
        return converted, projected_names

    @staticmethod
    def _project_tool_name(name: str) -> str:
        projected = re.sub(
            r"[^a-zA-Z0-9_-]",
            lambda match: f"_{ord(match.group(0)):02x}_",
            name,
        )
        if len(projected) <= 64:
            return projected
        digest = hashlib.sha256(name.encode("utf-8")).hexdigest()[:12]
        return f"{projected[:51]}_{digest}"

    @staticmethod
    def _convert_function_call(
        item: Any,
        projected_names: dict[str, str],
    ) -> ToolCall:
        raw_args = str(getattr(item, "arguments", "") or "{}")
        try:
            args = json.loads(raw_args)
        except json.JSONDecodeError:
            args = {}
        if not isinstance(args, dict):
            args = {}
        return ToolCall(
            id=str(getattr(item, "call_id", "") or getattr(item, "id", "") or "tool-call"),
            name=projected_names.get(
                str(getattr(item, "name", "") or ""),
                str(getattr(item, "name", "") or ""),
            ),
            args=args,
        )

    @staticmethod
    def _create_client(
        *,
        base_url: str,
        token_provider: Callable[[], str],
    ) -> Any:
        try:
            from openai import OpenAI
        except Exception as exc:  # pragma: no cover - only hit without dependency
            raise RuntimeError("openai package is required for OpenAI Codex OAuth") from exc
        return OpenAI(base_url=base_url, api_key=token_provider)

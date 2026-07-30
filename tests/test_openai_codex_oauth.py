from __future__ import annotations

import base64
import json
from types import SimpleNamespace

from ares.llm.openai_codex import (
    OpenAICodexResponsesModel,
    resolve_openai_codex_account_id,
)


def _jwt(*, account_id: str = "acct-test", exp: int = 2_000_000_000) -> str:
    header = base64.urlsafe_b64encode(b'{"alg":"none"}').rstrip(b"=").decode()
    payload = base64.urlsafe_b64encode(
        json.dumps(
            {
                "exp": exp,
                "https://api.openai.com/auth": {
                    "chatgpt_account_id": account_id,
                },
            }
        ).encode()
    ).rstrip(b"=").decode()
    return f"{header}.{payload}.signature"


class _FakeStream:
    def __init__(self, events):
        self.events = events

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return False

    def __iter__(self):
        return iter(self.events)


class _FakeResponses:
    def __init__(self, events):
        self.events = events
        self.request = None

    def stream(self, **request):
        self.request = request
        return _FakeStream(self.events)


class _FakeClient:
    def __init__(self, events):
        self.responses = _FakeResponses(events)


def test_codex_oauth_resolves_account_id():
    assert resolve_openai_codex_account_id(_jwt(account_id="acct-123")) == "acct-123"


def test_codex_oauth_stream_parses_text_and_tool_calls():
    events = [
        SimpleNamespace(type="response.output_text.delta", delta="Working"),
        SimpleNamespace(
            type="response.output_item.done",
            item=SimpleNamespace(
                type="function_call",
                call_id="call-1",
                id="item-1",
                name="unit.echo",
                arguments='{"text":"ok"}',
            ),
        ),
    ]
    client = _FakeClient(events)
    model = OpenAICodexResponsesModel(
        model="gpt-test",
        token_provider=lambda: _jwt(),
        client=client,
    )

    response = model.complete(
        [
            {"role": "system", "content": "System"},
            {"role": "user", "content": "Use the tool"},
        ],
        [
            {
                "type": "function",
                "function": {
                    "name": "unit.echo",
                    "description": "Echo text",
                    "parameters": {
                        "type": "object",
                        "properties": {"text": {"type": "string"}},
                        "required": ["text"],
                    },
                },
            }
        ],
    )

    assert response.final_text == "Working"
    assert response.tool_calls[0].name == "unit.echo"
    assert response.tool_calls[0].args == {"text": "ok"}
    assert client.responses.request["instructions"] == "System"
    assert client.responses.request["tools"][0]["name"] == "unit_2e_echo"
    assert client.responses.request["extra_headers"]["chatgpt-account-id"] == "acct-test"


def test_codex_oauth_converts_prior_tool_result():
    client = _FakeClient(
        [SimpleNamespace(type="response.output_text.delta", delta="Done")]
    )
    model = OpenAICodexResponsesModel(
        model="gpt-test",
        token_provider=lambda: _jwt(),
        client=client,
    )
    response = model.complete(
        [
            {"role": "user", "content": "Use the tool"},
            {
                "role": "assistant",
                "content": "",
                "tool_calls": [
                    {
                        "id": "call-1",
                        "type": "function",
                        "function": {
                            "name": "unit.echo",
                            "arguments": '{"text":"ok"}',
                        },
                    }
                ],
            },
            {
                "role": "tool",
                "tool_call_id": "call-1",
                "name": "unit.echo",
                "content": '{"status":"ok","result":"ok"}',
            },
        ],
        [
            {
                "type": "function",
                "function": {
                    "name": "unit.echo",
                    "description": "Echo text",
                    "parameters": {
                        "type": "object",
                        "properties": {"text": {"type": "string"}},
                    },
                },
            }
        ],
    )

    assert response.final_text == "Done"
    assert client.responses.request["input"][1]["type"] == "function_call"
    assert client.responses.request["input"][1]["name"] == "unit_2e_echo"
    assert client.responses.request["input"][2]["type"] == "function_call_output"


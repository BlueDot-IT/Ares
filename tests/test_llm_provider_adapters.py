import os
import sys
import tempfile
import types
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))


class _AnthropicMessagesClient:
    def __init__(self, response):
        self.response = response
        self.calls = []

    def create(self, **kwargs):
        self.calls.append(kwargs)
        return self.response


class _AnthropicClient:
    def __init__(self, response):
        self.messages = _AnthropicMessagesClient(response)


class _GeminiModelsClient:
    def __init__(self, response):
        self.response = response
        self.calls = []

    def generate_content(self, **kwargs):
        self.calls.append(kwargs)
        return self.response


class _GeminiClient:
    def __init__(self, response):
        self.models = _GeminiModelsClient(response)


class ProviderSelectionTests(unittest.TestCase):
    def test_build_model_selects_anthropic_adapter_for_anthropic_provider(self):
        from ares.config.loader import AppConfig, LLMConfig, PolicyConfig
        from ares.llm.anthropic_adapter import AnthropicModel
        from ares.run import build_model

        with tempfile.TemporaryDirectory() as tmp:
            config = AppConfig(
                home=Path(tmp),
                llm=LLMConfig(provider="anthropic", model="claude-3-7-sonnet"),
                policy=PolicyConfig(),
            )
            with patch.dict(os.environ, {"ANTHROPIC_API_KEY": "anth-key"}, clear=False):
                with patch.object(AnthropicModel, "_create_client", return_value=object()) as create_client:
                    model = build_model(config)

        self.assertIsInstance(model, AnthropicModel)
        create_client.assert_called_once_with(api_key="anth-key")

    def test_build_model_selects_gemini_adapter_for_gemini_provider(self):
        from ares.config.loader import AppConfig, LLMConfig, PolicyConfig
        from ares.llm.gemini_adapter import GeminiModel
        from ares.run import build_model

        with tempfile.TemporaryDirectory() as tmp:
            home = Path(tmp)
            config = AppConfig(
                home=home,
                llm=LLMConfig(provider="gemini", model="gemini-2.5-pro"),
                policy=PolicyConfig(),
            )
            with patch.dict(os.environ, {"GEMINI_API_KEY": "gem-key"}, clear=False):
                with patch.object(GeminiModel, "_create_client", return_value=object()) as create_client:
                    model = build_model(config)

        self.assertIsInstance(model, GeminiModel)
        create_client.assert_called_once_with(
            api_key="gem-key",
            auth_mode="api-key",
            oauth_token_command="",
            oauth_project="",
            oauth_location="",
            home=home,
            provider="gemini",
        )

    def test_build_model_routes_openai_oauth_to_codex_responses_adapter(self):
        from ares.config.loader import AppConfig, LLMConfig, PolicyConfig
        from ares.llm.openai_codex import (
            OPENAI_CODEX_BASE_URL,
            OpenAICodexResponsesModel,
        )
        from ares.run import build_model

        with tempfile.TemporaryDirectory() as tmp:
            home = Path(tmp)
            config = AppConfig(
                home=home,
                llm=LLMConfig(
                    provider="openai",
                    model="gpt-4.1-mini",
                    openai_base_url="https://api.openai.com/v1",
                    auth_mode="oauth",
                    oauth_token_command="print-openai-token",
                ),
                policy=PolicyConfig(),
            )
            with patch.object(
                OpenAICodexResponsesModel,
                "_create_client",
                return_value=object(),
            ) as create_client:
                model = build_model(config)

        self.assertIsInstance(model, OpenAICodexResponsesModel)
        self.assertEqual(create_client.call_args.kwargs["base_url"], OPENAI_CODEX_BASE_URL)
        self.assertTrue(callable(create_client.call_args.kwargs["token_provider"]))

    def test_build_model_passes_gemini_oauth_settings_to_gemini_adapter(self):
        from ares.config.loader import AppConfig, LLMConfig, PolicyConfig
        from ares.llm.gemini_adapter import GeminiModel
        from ares.run import build_model

        with tempfile.TemporaryDirectory() as tmp:
            home = Path(tmp)
            config = AppConfig(
                home=home,
                llm=LLMConfig(
                    provider="gemini",
                    model="gemini-2.5-pro",
                    auth_mode="oauth",
                    oauth_project="demo-project",
                    oauth_location="us-central1",
                ),
                policy=PolicyConfig(),
            )
            with patch.object(GeminiModel, "_create_client", return_value=object()) as create_client:
                model = build_model(config)

        self.assertIsInstance(model, GeminiModel)
        create_client.assert_called_once_with(
            api_key=None,
            auth_mode="oauth",
            oauth_token_command="",
            oauth_project="demo-project",
            oauth_location="us-central1",
            home=home,
            provider="gemini",
        )


class AnthropicAdapterTests(unittest.TestCase):
    def test_complete_translates_openai_style_messages_tools_and_tool_results(self):
        from ares.llm.anthropic_adapter import AnthropicModel

        response = types.SimpleNamespace(
            content=[
                types.SimpleNamespace(type="text", text="Need to inspect ports first."),
                types.SimpleNamespace(type="tool_use", id="anth-call-2", name="nmap_basic", input={"target": "127.0.0.1"}),
            ]
        )
        client = _AnthropicClient(response)
        model = AnthropicModel(model="claude-3-7-sonnet", client=client)

        result = model.complete(
            messages=[
                {"role": "system", "content": "Authorized lab only."},
                {"role": "user", "content": "Enumerate the target."},
                {
                    "role": "assistant",
                    "content": "Resolving hostname.",
                    "tool_calls": [
                        {
                            "id": "call-1",
                            "type": "function",
                            "function": {"name": "resolve_host", "arguments": '{"host": "example.local"}'},
                        }
                    ],
                },
                {
                    "role": "tool",
                    "tool_call_id": "call-1",
                    "name": "resolve_host",
                    "content": '{"status": "ok", "result": {"ip": "127.0.0.1"}}',
                },
            ],
            tools=[
                {
                    "type": "function",
                    "function": {
                        "name": "resolve_host",
                        "description": "Resolve a hostname.",
                        "parameters": {
                            "type": "object",
                            "properties": {"host": {"type": "string"}},
                            "required": ["host"],
                        },
                    },
                }
            ],
        )

        request = client.messages.calls[0]
        self.assertEqual(request["system"], "Authorized lab only.")
        self.assertEqual(
            request["tools"],
            [
                {
                    "name": "resolve_host",
                    "description": "Resolve a hostname.",
                    "input_schema": {
                        "type": "object",
                        "properties": {"host": {"type": "string"}},
                        "required": ["host"],
                    },
                }
            ],
        )
        self.assertEqual(
            request["messages"],
            [
                {"role": "user", "content": [{"type": "text", "text": "Enumerate the target."}]},
                {
                    "role": "assistant",
                    "content": [
                        {"type": "text", "text": "Resolving hostname."},
                        {"type": "tool_use", "id": "call-1", "name": "resolve_host", "input": {"host": "example.local"}},
                    ],
                },
                {
                    "role": "user",
                    "content": [
                        {
                            "type": "tool_result",
                            "tool_use_id": "call-1",
                            "content": '{"status": "ok", "result": {"ip": "127.0.0.1"}}',
                        }
                    ],
                },
            ],
        )
        self.assertEqual(result.final_text, "Need to inspect ports first.")
        self.assertEqual(result.tool_calls[0].id, "anth-call-2")
        self.assertEqual(result.tool_calls[0].name, "nmap_basic")
        self.assertEqual(result.tool_calls[0].args, {"target": "127.0.0.1"})


class GeminiAdapterTests(unittest.TestCase):
    def test_complete_translates_openai_style_messages_and_function_calls(self):
        from ares.llm.gemini_adapter import GeminiModel

        response = {
            "candidates": [
                {
                    "content": {
                        "parts": [
                            {"text": "Need a quick fingerprint first."},
                            {"function_call": {"name": "http_probe", "args": {"target": "127.0.0.1"}}},
                        ]
                    }
                }
            ]
        }
        client = _GeminiClient(response)
        model = GeminiModel(model="gemini-2.5-pro", client=client)

        result = model.complete(
            messages=[
                {"role": "system", "content": "Stay inside authorized scope."},
                {"role": "user", "content": "Inspect the local web app."},
                {
                    "role": "assistant",
                    "content": "Calling resolver.",
                    "tool_calls": [
                        {
                            "id": "call-1",
                            "type": "function",
                            "function": {"name": "resolve_host", "arguments": '{"host": "example.local"}'},
                        }
                    ],
                },
                {
                    "role": "tool",
                    "tool_call_id": "call-1",
                    "name": "resolve_host",
                    "content": '{"status": "ok", "result": {"ip": "127.0.0.1"}}',
                },
            ],
            tools=[
                {
                    "type": "function",
                    "function": {
                        "name": "resolve_host",
                        "description": "Resolve a hostname.",
                        "parameters": {
                            "type": "object",
                            "properties": {"host": {"type": "string"}},
                            "required": ["host"],
                        },
                    },
                }
            ],
        )

        request = client.models.calls[0]
        self.assertEqual(request["model"], "gemini-2.5-pro")
        self.assertEqual(request["config"]["system_instruction"], "Stay inside authorized scope.")
        self.assertEqual(
            request["config"]["tools"],
            [
                {
                    "function_declarations": [
                        {
                            "name": "resolve_host",
                            "description": "Resolve a hostname.",
                            "parameters": {
                                "type": "object",
                                "properties": {"host": {"type": "string"}},
                                "required": ["host"],
                            },
                        }
                    ]
                }
            ],
        )
        self.assertEqual(
            request["contents"],
            [
                {"role": "user", "parts": [{"text": "Inspect the local web app."}]},
                {
                    "role": "model",
                    "parts": [
                        {"text": "Calling resolver."},
                        {"function_call": {"name": "resolve_host", "args": {"host": "example.local"}}},
                    ],
                },
                {
                    "role": "user",
                    "parts": [
                        {
                            "function_response": {
                                "name": "resolve_host",
                                "response": {"status": "ok", "result": {"ip": "127.0.0.1"}},
                            }
                        }
                    ],
                },
            ],
        )
        self.assertEqual(result.final_text, "Need a quick fingerprint first.")
        self.assertEqual(result.tool_calls[0].name, "http_probe")
        self.assertEqual(result.tool_calls[0].args, {"target": "127.0.0.1"})


if __name__ == "__main__":
    unittest.main()

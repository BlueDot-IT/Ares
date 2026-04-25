import sys
import unittest
from pathlib import Path
from types import SimpleNamespace

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))


class _FakeCompletions:
    def __init__(self, response):
        self.response = response
        self.calls = []

    def create(self, **kwargs):
        self.calls.append(kwargs)
        return self.response


class _FakeClient:
    def __init__(self, response):
        self.chat = SimpleNamespace(completions=_FakeCompletions(response))


class OpenAICompatModelTests(unittest.TestCase):
    def test_complete_returns_final_text_and_sends_openai_request(self):
        from ares.llm.openai_compat import OpenAICompatModel

        response = SimpleNamespace(
            choices=[SimpleNamespace(message=SimpleNamespace(content="final answer", tool_calls=None))]
        )
        client = _FakeClient(response)
        model = OpenAICompatModel(client=client, model="unit-model")
        messages = [{"role": "user", "content": "hello"}]
        tools = [{"type": "function", "function": {"name": "echo_tool"}}]

        result = model.complete(messages, tools)

        self.assertEqual(result.final_text, "final answer")
        self.assertEqual(result.tool_calls, [])
        call = client.chat.completions.calls[0]
        self.assertEqual(call["model"], "unit-model")
        self.assertEqual(call["messages"], messages)
        self.assertEqual(call["tools"], tools)
        self.assertEqual(call["temperature"], 0)

    def test_complete_maps_tool_calls_to_runtime_dataclasses(self):
        from ares.llm.openai_compat import OpenAICompatModel

        tool_call = SimpleNamespace(
            id="call-1",
            function=SimpleNamespace(name="echo_tool", arguments='{"text": "hello"}'),
        )
        response = SimpleNamespace(
            choices=[SimpleNamespace(message=SimpleNamespace(content=None, tool_calls=[tool_call]))]
        )
        model = OpenAICompatModel(client=_FakeClient(response), model="unit-model")

        result = model.complete([{"role": "user", "content": "hello"}], [])

        self.assertIsNone(result.final_text)
        self.assertEqual(len(result.tool_calls), 1)
        self.assertEqual(result.tool_calls[0].id, "call-1")
        self.assertEqual(result.tool_calls[0].name, "echo_tool")
        self.assertEqual(result.tool_calls[0].args, {"text": "hello"})

    def test_complete_treats_malformed_tool_arguments_as_empty_dict(self):
        from ares.llm.openai_compat import OpenAICompatModel

        tool_call = SimpleNamespace(
            id="call-bad-json",
            function=SimpleNamespace(name="echo_tool", arguments="not-json"),
        )
        response = SimpleNamespace(
            choices=[SimpleNamespace(message=SimpleNamespace(content=None, tool_calls=[tool_call]))]
        )
        model = OpenAICompatModel(client=_FakeClient(response), model="unit-model")

        result = model.complete([{"role": "user", "content": "hello"}], [])

        self.assertEqual(result.tool_calls[0].args, {})


if __name__ == "__main__":
    unittest.main()

import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))


class _StubModel:
    def __init__(self, *, responses=None, error=None):
        self.responses = list(responses or [])
        self.error = error
        self.calls = []

    def complete(self, messages, tools):
        self.calls.append({"messages": list(messages), "tools": list(tools)})
        if self.error is not None:
            raise self.error
        if not self.responses:
            raise AssertionError("stub model exhausted")
        return self.responses.pop(0)


class ModelFallbackTests(unittest.TestCase):
    def test_failover_model_retries_next_candidate_after_primary_error(self):
        from ares.agent.runtime import ModelResponse
        from ares.llm.failover import FailoverCandidate, FailoverModel

        primary = _StubModel(error=RuntimeError("primary unavailable"))
        secondary = _StubModel(responses=[ModelResponse(final_text="fallback response")])
        events: list[dict[str, str]] = []

        model = FailoverModel(
            [
                FailoverCandidate(provider="openai", model="primary-model", client=primary),
                FailoverCandidate(provider="openrouter", model="backup-model", client=secondary),
            ]
        )

        result = model.complete_with_events(
            messages=[{"role": "user", "content": "Enumerate scope."}],
            tools=[],
            event_callback=events.append,
        )

        self.assertEqual(result.final_text, "fallback response")
        self.assertEqual(len(primary.calls), 1)
        self.assertEqual(len(secondary.calls), 1)
        self.assertTrue(any(event.get("type") == "model_fallback" for event in events))
        self.assertEqual(events[-1].get("model"), "backup-model")

    def test_failover_model_falls_back_after_malformed_response(self):
        from ares.agent.runtime import ModelResponse
        from ares.llm.failover import FailoverCandidate, FailoverModel

        primary = _StubModel(responses=[{"unexpected": True}])
        secondary = _StubModel(responses=[ModelResponse(final_text="recovered")])
        events: list[dict[str, str]] = []

        model = FailoverModel(
            [
                FailoverCandidate(provider="openai", model="primary-model", client=primary),
                FailoverCandidate(provider="openrouter", model="backup-model", client=secondary),
            ]
        )

        result = model.complete_with_events(
            messages=[{"role": "user", "content": "Enumerate scope."}],
            tools=[],
            event_callback=events.append,
        )

        self.assertEqual(result.final_text, "recovered")
        self.assertEqual(len(primary.calls), 1)
        self.assertEqual(len(secondary.calls), 1)
        self.assertEqual(events[-1].get("provider"), "openrouter")
        self.assertIn("invalid model response", events[-1].get("error", ""))

    def test_failover_model_falls_back_after_empty_response(self):
        from ares.agent.runtime import ModelResponse
        from ares.llm.failover import FailoverCandidate, FailoverModel

        primary = _StubModel(responses=[ModelResponse(final_text="   ")])
        secondary = _StubModel(responses=[ModelResponse(final_text="recovered after blank")])

        model = FailoverModel(
            [
                FailoverCandidate(provider="openai", model="primary-model", client=primary),
                FailoverCandidate(provider="openrouter", model="backup-model", client=secondary),
            ]
        )

        result = model.complete(messages=[{"role": "user", "content": "Enumerate scope."}], tools=[])

        self.assertEqual(result.final_text, "recovered after blank")
        self.assertEqual(len(primary.calls), 1)
        self.assertEqual(len(secondary.calls), 1)

    def test_failover_model_raises_summary_error_with_attempt_history_when_exhausted(self):
        from ares.llm.failover import FailoverCandidate, FailoverExhaustedError, FailoverModel

        primary = _StubModel(error=RuntimeError("primary unavailable"))
        secondary = _StubModel(error=TimeoutError("backup timed out"))
        model = FailoverModel(
            [
                FailoverCandidate(provider="openai", model="primary-model", client=primary),
                FailoverCandidate(provider="openrouter", model="backup-model", client=secondary),
            ]
        )

        with self.assertRaises(FailoverExhaustedError) as ctx:
            model.complete(messages=[{"role": "user", "content": "Enumerate scope."}], tools=[])

        err = ctx.exception
        self.assertEqual(len(err.attempts), 2)
        self.assertEqual(err.attempts[0]["provider"], "openai")
        self.assertEqual(err.attempts[1]["provider"], "openrouter")
        self.assertIn("backup timed out", str(err))

    def test_build_model_deduplicates_primary_and_alias_fallback_candidates(self):
        from ares.config.loader import AppConfig, LLMConfig, PolicyConfig
        from ares.llm.failover import FailoverModel
        from ares.run import build_model

        with tempfile.TemporaryDirectory() as tmp:
            config = AppConfig(
                home=Path(tmp),
                llm=LLMConfig(
                    provider="anthropic",
                    model="claude-3-7-sonnet",
                    fallbacks=(
                        "claude/claude-3-7-sonnet",
                        "anthropic/claude-3-7-sonnet",
                        "openrouter/openai/gpt-4o-mini",
                        "openrouter/openai/gpt-4o-mini",
                    ),
                ),
                policy=PolicyConfig(),
            )
            with patch("ares.run._build_single_model", side_effect=lambda **kwargs: _StubModel(responses=[])):
                model = build_model(config)

        self.assertIsInstance(model, FailoverModel)
        self.assertEqual(
            [(candidate.provider, candidate.model) for candidate in model.candidates],
            [
                ("anthropic", "claude-3-7-sonnet"),
                ("openrouter", "openai/gpt-4o-mini"),
            ],
        )

    def test_build_model_defers_client_construction_until_candidates_are_needed(self):
        from ares.config.loader import AppConfig, LLMConfig, PolicyConfig
        from ares.llm.failover import FailoverModel
        from ares.run import build_model

        created: list[tuple[str, str]] = []

        def fake_build_single_model(*, provider: str, model: str, openai_base_url: str):
            created.append((provider, model))
            if provider == "anthropic":
                raise RuntimeError("anthropic package is required")
            return _StubModel(responses=[])

        with tempfile.TemporaryDirectory() as tmp:
            config = AppConfig(
                home=Path(tmp),
                llm=LLMConfig(
                    provider="openai",
                    model="local-model",
                    fallbacks=("anthropic/claude-3-7-sonnet",),
                ),
                policy=PolicyConfig(),
            )
            with patch("ares.run._build_single_model", side_effect=fake_build_single_model):
                model = build_model(config)

        self.assertIsInstance(model, FailoverModel)
        self.assertEqual(created, [])

    def test_build_model_can_fail_over_after_primary_client_init_error(self):
        from ares.agent.runtime import ModelResponse
        from ares.config.loader import AppConfig, LLMConfig, PolicyConfig
        from ares.run import build_model

        def fake_build_single_model(*, provider: str, model: str, openai_base_url: str, **_: object):
            if provider == "openai":
                raise RuntimeError("openai package is required")
            return _StubModel(responses=[ModelResponse(final_text="fallback survived init error")])

        with tempfile.TemporaryDirectory() as tmp:
            config = AppConfig(
                home=Path(tmp),
                llm=LLMConfig(
                    provider="openai",
                    model="primary-model",
                    fallbacks=("anthropic/claude-3-7-sonnet",),
                ),
                policy=PolicyConfig(),
            )
            with patch("ares.run._build_single_model", side_effect=fake_build_single_model):
                model = build_model(config)
                result = model.complete(messages=[{"role": "user", "content": "Enumerate scope."}], tools=[])

        self.assertEqual(result.final_text, "fallback survived init error")


if __name__ == "__main__":
    unittest.main()

from __future__ import annotations
from dataclasses import dataclass, field
from typing import Any, Callable

from ares.agent.runtime import ModelClient, ModelResponse


@dataclass(frozen=True)
class FailoverCandidate:
    provider: str
    model: str
    client: Any


@dataclass(frozen=True)
class FailoverAttempt:
    provider: str
    model: str
    error: str
    error_type: str

    def as_dict(self) -> dict[str, str]:
        return {
            "provider": self.provider,
            "model": self.model,
            "error": self.error,
            "error_type": self.error_type,
        }


@dataclass
class FailoverExhaustedError(RuntimeError):
    attempts: list[dict[str, str]] = field(default_factory=list)

    def __post_init__(self) -> None:
        summary = "; ".join(
            f"{attempt['provider']}/{attempt['model']}: {attempt['error']}" for attempt in self.attempts
        ) or "no model attempts recorded"
        super().__init__(f"all model fallback candidates failed: {summary}")


class FailoverModel(ModelClient):
    def __init__(self, candidates: list[FailoverCandidate]) -> None:
        if not candidates:
            raise ValueError("at least one failover candidate is required")
        self.candidates = list(candidates)

    def complete(self, messages: list[dict[str, Any]], tools: list[dict[str, Any]]) -> ModelResponse:
        return self._complete(messages, tools, event_callback=None)

    def complete_with_events(
        self,
        messages: list[dict[str, Any]],
        tools: list[dict[str, Any]],
        event_callback: Callable[[dict[str, Any]], None],
    ) -> ModelResponse:
        return self._complete(messages, tools, event_callback=event_callback)

    def _complete(
        self,
        messages: list[dict[str, Any]],
        tools: list[dict[str, Any]],
        event_callback: Callable[[dict[str, Any]], None] | None,
    ) -> ModelResponse:
        attempts: list[FailoverAttempt] = []
        for index, candidate in enumerate(self.candidates):
            try:
                client = self._resolve_client(candidate)
                complete_with_events = getattr(client, "complete_with_events", None)
                if event_callback is not None and callable(complete_with_events):
                    response = complete_with_events(messages, tools, event_callback)
                else:
                    response = client.complete(messages, tools)
                return self._validate_response(response, candidate)
            except Exception as exc:
                attempt = FailoverAttempt(
                    provider=candidate.provider,
                    model=candidate.model,
                    error=str(exc),
                    error_type=type(exc).__name__,
                )
                attempts.append(attempt)
                if index + 1 >= len(self.candidates):
                    raise FailoverExhaustedError(attempts=[item.as_dict() for item in attempts]) from exc
                next_candidate = self.candidates[index + 1]
                if event_callback is not None:
                    event_callback(
                        {
                            "type": "model_fallback",
                            "from_provider": candidate.provider,
                            "from_model": candidate.model,
                            "provider": next_candidate.provider,
                            "model": next_candidate.model,
                            "error": str(exc),
                            "error_type": type(exc).__name__,
                            "attempt": index + 1,
                            "total": len(self.candidates),
                            "attempts": [item.as_dict() for item in attempts],
                            "message": (
                                f"fallback {candidate.provider}/{candidate.model} -> "
                                f"{next_candidate.provider}/{next_candidate.model}: {exc}"
                            ),
                        }
                    )
        raise FailoverExhaustedError(attempts=[item.as_dict() for item in attempts])

    def _resolve_client(self, candidate: FailoverCandidate) -> ModelClient:
        client = candidate.client
        if hasattr(client, "complete"):
            return client
        if callable(client):
            resolved = client()
            if hasattr(resolved, "complete"):
                return resolved
        raise TypeError(
            f"invalid model client for {candidate.provider}/{candidate.model}: "
            f"expected object with complete(), got {type(client).__name__}"
        )

    def _validate_response(self, response: Any, candidate: FailoverCandidate) -> ModelResponse:
        if not isinstance(response, ModelResponse):
            raise TypeError(
                f"invalid model response from {candidate.provider}/{candidate.model}: "
                f"expected ModelResponse, got {type(response).__name__}"
            )
        if response.final_text is None and not response.tool_calls:
            raise ValueError(
                f"invalid model response from {candidate.provider}/{candidate.model}: empty completion"
            )
        if isinstance(response.final_text, str) and not response.final_text.strip() and not response.tool_calls:
            raise ValueError(
                f"invalid model response from {candidate.provider}/{candidate.model}: blank completion"
            )
        return response

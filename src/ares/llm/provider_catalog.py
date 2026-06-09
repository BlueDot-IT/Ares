from __future__ import annotations

from dataclasses import dataclass

DEFAULT_LOCAL_OPENAI_BASE_URL = "http://127.0.0.1:1234/v1"
DEFAULT_OPENAI_CLOUD_BASE_URL = "https://api.openai.com/v1"
DEFAULT_OPENROUTER_BASE_URL = "https://openrouter.ai/api/v1"


@dataclass(frozen=True)
class ProviderChoice:
    key: str
    label: str
    provider: str
    default_model: str
    default_endpoint: str
    endpoint_mode: str
    auth_methods: tuple[str, ...]
    hint: str = ""
    oauth_provider: str | None = None
    persisted_profile: bool = True


_PROVIDER_CHOICES: tuple[ProviderChoice, ...] = (
    ProviderChoice(
        key="local",
        label="Local OpenAI-compatible",
        provider="openai",
        default_model="local-model",
        default_endpoint=DEFAULT_LOCAL_OPENAI_BASE_URL,
        endpoint_mode="editable",
        auth_methods=("api-key",),
        hint="LM Studio, llama.cpp, vLLM, or another local server.",
    ),
    ProviderChoice(
        key="openai",
        label="OpenAI cloud",
        provider="openai",
        default_model="gpt-4.1-mini",
        default_endpoint=DEFAULT_OPENAI_CLOUD_BASE_URL,
        endpoint_mode="hidden",
        auth_methods=("api-key", "oauth"),
        hint="Uses OpenAI's hosted API with the standard cloud endpoint. Supports API key or ChatGPT OAuth.",
        oauth_provider="openai",
    ),
    ProviderChoice(
        key="openrouter",
        label="OpenRouter",
        provider="openrouter",
        default_model="openai/gpt-4o-mini",
        default_endpoint=DEFAULT_OPENROUTER_BASE_URL,
        endpoint_mode="hidden",
        auth_methods=("api-key",),
        hint="Hosted OpenRouter access through its known cloud endpoint.",
    ),
    ProviderChoice(
        key="anthropic",
        label="Anthropic",
        provider="anthropic",
        default_model="claude-3-7-sonnet-latest",
        default_endpoint="",
        endpoint_mode="native",
        auth_methods=("api-key",),
        hint="Native Anthropic API adapter; no endpoint prompt needed.",
    ),
    ProviderChoice(
        key="gemini",
        label="Gemini",
        provider="gemini",
        default_model="gemini-2.5-pro",
        default_endpoint="",
        endpoint_mode="native",
        auth_methods=("api-key", "oauth"),
        hint="Native Gemini adapter with API key or real Google OAuth/ADC support.",
        oauth_provider="gemini",
    ),
    ProviderChoice(
        key="custom",
        label="Custom OpenAI-compatible",
        provider="custom",
        default_model="custom-model",
        default_endpoint="",
        endpoint_mode="editable",
        auth_methods=("api-key",),
        hint="Bring your own OpenAI-compatible endpoint and model.",
        persisted_profile=False,
    ),
)

_PROVIDER_CHOICES_BY_KEY = {choice.key: choice for choice in _PROVIDER_CHOICES}


def list_provider_choices() -> list[ProviderChoice]:
    return list(_PROVIDER_CHOICES)


def get_provider_choice(key: str) -> ProviderChoice:
    normalized = str(key or "").strip().lower()
    if normalized not in _PROVIDER_CHOICES_BY_KEY:
        raise ValueError(f"unknown provider choice: {key}")
    return _PROVIDER_CHOICES_BY_KEY[normalized]


def build_profile_presets() -> dict[str, dict[str, str]]:
    presets: dict[str, dict[str, str]] = {}
    for choice in _PROVIDER_CHOICES:
        if not choice.persisted_profile:
            continue
        presets[choice.key] = {
            "provider": choice.provider,
            "model": choice.default_model,
            "openai_base_url": choice.default_endpoint,
        }
    return presets

from __future__ import annotations

import os
from dataclasses import dataclass


DEFAULT_OPENROUTER_BASE_URL = "https://openrouter.ai/api/v1"


@dataclass(frozen=True)
class ProviderSpec:
    name: str
    family: str
    api_key_envs: tuple[str, ...]
    openai_compatible: bool = False
    default_base_url: str | None = None


_OPENAI_COMPAT_PROVIDER_SPECS = {
    "openai": ProviderSpec(
        name="openai",
        family="openai_compat",
        api_key_envs=("ARES_OPENAI_API_KEY", "OPENAI_API_KEY"),
        openai_compatible=True,
    ),
    "openrouter": ProviderSpec(
        name="openrouter",
        family="openai_compat",
        api_key_envs=("ARES_OPENROUTER_API_KEY", "OPENROUTER_API_KEY", "ARES_OPENAI_API_KEY", "OPENAI_API_KEY"),
        openai_compatible=True,
        default_base_url=DEFAULT_OPENROUTER_BASE_URL,
    ),
    "local": ProviderSpec(
        name="local",
        family="openai_compat",
        api_key_envs=("ARES_OPENAI_API_KEY", "OPENAI_API_KEY"),
        openai_compatible=True,
    ),
    "lm-studio": ProviderSpec(
        name="lm-studio",
        family="openai_compat",
        api_key_envs=("ARES_OPENAI_API_KEY", "OPENAI_API_KEY"),
        openai_compatible=True,
    ),
    "ollama": ProviderSpec(
        name="ollama",
        family="openai_compat",
        api_key_envs=("ARES_OPENAI_API_KEY", "OPENAI_API_KEY"),
        openai_compatible=True,
    ),
    "vllm": ProviderSpec(
        name="vllm",
        family="openai_compat",
        api_key_envs=("ARES_OPENAI_API_KEY", "OPENAI_API_KEY"),
        openai_compatible=True,
    ),
    "llama-cpp": ProviderSpec(
        name="llama-cpp",
        family="openai_compat",
        api_key_envs=("ARES_OPENAI_API_KEY", "OPENAI_API_KEY"),
        openai_compatible=True,
    ),
    "openai-compatible": ProviderSpec(
        name="openai-compatible",
        family="openai_compat",
        api_key_envs=("ARES_OPENAI_API_KEY", "OPENAI_API_KEY"),
        openai_compatible=True,
    ),
    "custom": ProviderSpec(
        name="custom",
        family="openai_compat",
        api_key_envs=("ARES_OPENAI_API_KEY", "OPENAI_API_KEY"),
        openai_compatible=True,
    ),
}

_PROVIDER_ALIASES = {
    "claude": "anthropic",
    "anthropic": "anthropic",
    "google": "gemini",
    "google-genai": "gemini",
    "gemini": "gemini",
    "lmstudio": "lm-studio",
    "llamacpp": "llama-cpp",
}

_PROVIDER_SPECS = {
    **_OPENAI_COMPAT_PROVIDER_SPECS,
    "anthropic": ProviderSpec(
        name="anthropic",
        family="anthropic",
        api_key_envs=("ARES_ANTHROPIC_API_KEY", "ANTHROPIC_API_KEY"),
    ),
    "gemini": ProviderSpec(
        name="gemini",
        family="gemini",
        api_key_envs=("ARES_GEMINI_API_KEY", "GEMINI_API_KEY", "GOOGLE_API_KEY"),
    ),
}


def normalize_provider(provider: str | None) -> str:
    raw = (provider or "openai").strip().lower()
    if not raw:
        return "openai"
    return _PROVIDER_ALIASES.get(raw, raw)


def provider_exists(provider: str | None) -> bool:
    normalized = normalize_provider(provider)
    return normalized in _PROVIDER_SPECS


def resolve_provider(provider: str | None) -> ProviderSpec:
    normalized = normalize_provider(provider)
    return _PROVIDER_SPECS.get(normalized, _OPENAI_COMPAT_PROVIDER_SPECS["openai"])


def provider_default_base_url(provider: str | None, *, fallback: str) -> str:
    spec = resolve_provider(provider)
    if not spec.openai_compatible:
        return ""
    return spec.default_base_url or fallback


def resolve_api_key(provider: str | None, *, environ: dict[str, str] | None = None) -> str | None:
    environ = os.environ if environ is None else environ
    spec = resolve_provider(provider)
    for env_name in spec.api_key_envs:
        value = environ.get(env_name)
        if value:
            return value
    return None

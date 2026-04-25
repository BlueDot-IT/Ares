from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from ares.llm.providers import provider_default_base_url, provider_exists, resolve_provider
from ares.policy.roe import ROEProfileRegistry
from ares.themes import DEFAULT_THEME, normalize_theme


DEFAULT_LLM_PROVIDER = "openai"
DEFAULT_LLM_MODEL = "local-model"
DEFAULT_OPENAI_BASE_URL = "http://127.0.0.1:1234/v1"
DEFAULT_HOME = "~/.ares"
DEFAULT_MODE = "safe-active"
DEFAULT_GATEWAY_HOST = "127.0.0.1"
DEFAULT_GATEWAY_PORT = 18791

LLM_PROFILE_PRESETS: dict[str, dict[str, str]] = {
    "local": {
        "provider": "openai",
        "model": "local-model",
        "openai_base_url": DEFAULT_OPENAI_BASE_URL,
    },
    "openrouter": {
        "provider": "openrouter",
        "model": "openai/gpt-4o-mini",
        "openai_base_url": "https://openrouter.ai/api/v1",
    },
    "anthropic": {
        "provider": "anthropic",
        "model": "claude-3-7-sonnet-latest",
        "openai_base_url": "",
    },
    "gemini": {
        "provider": "gemini",
        "model": "gemini-2.5-pro",
        "openai_base_url": "",
    },
}


@dataclass(frozen=True)
class LLMConfig:
    provider: str = DEFAULT_LLM_PROVIDER
    model: str = DEFAULT_LLM_MODEL
    openai_base_url: str = DEFAULT_OPENAI_BASE_URL
    fallbacks: tuple[str, ...] = ()


@dataclass(frozen=True)
class PolicyConfig:
    default_mode: str = DEFAULT_MODE
    allow_private_only: bool = True
    max_risk: str = "active"
    roe_profile: str = DEFAULT_MODE


@dataclass(frozen=True)
class UIConfig:
    theme: str = DEFAULT_THEME


@dataclass(frozen=True)
class HooksConfig:
    auto_report_on_finish: bool = False


@dataclass(frozen=True)
class GatewayConfig:
    host: str = DEFAULT_GATEWAY_HOST
    port: int = DEFAULT_GATEWAY_PORT


@dataclass(frozen=True)
class AgentProfileConfig:
    name: str
    provider: str | None = None
    model: str | None = None
    openai_base_url: str | None = None
    fallbacks: tuple[str, ...] = ()
    enabled_toolsets: tuple[str, ...] = ()
    disabled_toolsets: tuple[str, ...] = ()
    max_risk: str | None = None
    allow_private_only: bool | None = None
    roe_profile: str | None = None


@dataclass(frozen=True)
class AgentRouteConfig:
    agent: str
    target_schemes: tuple[str, ...] = ()
    target_contains: tuple[str, ...] = ()
    match_private: bool | None = None


@dataclass(frozen=True)
class AgentsConfig:
    default_agent: str = "default"
    active_agent: str = "default"
    profiles: dict[str, AgentProfileConfig] = field(default_factory=lambda: {"default": AgentProfileConfig(name="default")})
    routes: tuple[AgentRouteConfig, ...] = ()


@dataclass(frozen=True)
class AppConfig:
    home: Path
    llm: LLMConfig
    policy: PolicyConfig
    ui: UIConfig = field(default_factory=UIConfig)
    hooks: HooksConfig = field(default_factory=HooksConfig)
    gateway: GatewayConfig = field(default_factory=GatewayConfig)
    agents: AgentsConfig = field(default_factory=AgentsConfig)


def _env_bool(name: str, default: bool) -> bool:
    raw = os.getenv(name)
    if raw is None:
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}


def resolve_home(home: Path | str | None = None) -> Path:
    if home is not None:
        return Path(home).expanduser()
    return Path(os.getenv("ARES_HOME", DEFAULT_HOME)).expanduser()


def config_file_path(home: Path | str | None = None) -> Path:
    return resolve_home(home) / "config.json"


def available_llm_profiles() -> dict[str, dict[str, str]]:
    return {name: dict(values) for name, values in LLM_PROFILE_PRESETS.items()}


def resolve_llm_profile(profile: str) -> dict[str, str]:
    key = profile.strip().lower()
    if key not in LLM_PROFILE_PRESETS:
        raise ValueError(f"unknown model profile: {profile}")
    return dict(LLM_PROFILE_PRESETS[key])


def infer_llm_profile(llm: LLMConfig) -> str | None:
    if llm.fallbacks:
        return None
    provider = llm.provider.strip().lower()
    model = llm.model.strip()
    base_url = llm.openai_base_url.strip()
    for name, preset in LLM_PROFILE_PRESETS.items():
        if (
            preset["provider"] == provider
            and preset["model"] == model
            and preset.get("openai_base_url", "") == base_url
        ):
            return name
    return None


def _load_config_document(home: Path | str | None = None) -> dict[str, Any]:
    path = config_file_path(home)
    if not path.exists():
        return {}
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}
    return data if isinstance(data, dict) else {}


def _write_config_document(document: dict[str, Any], *, home: Path | str | None = None) -> Path:
    path = config_file_path(home)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(document, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return path


def _normalize_provider_or_raise(provider: str | None) -> str:
    normalized = str(provider or "").strip().lower()
    if not normalized:
        raise ValueError("provider is required")
    if not provider_exists(normalized):
        raise ValueError(f"unknown provider: {provider}")
    return resolve_provider(normalized).name


def _normalize_fallbacks(values: Any) -> tuple[str, ...]:
    if not isinstance(values, (list, tuple)):
        return ()
    normalized: list[str] = []
    seen: set[str] = set()
    for raw in values:
        candidate = str(raw or "").strip()
        if not candidate:
            continue
        if "/" in candidate:
            provider_hint, model_name = candidate.split("/", 1)
            model_name = model_name.strip()
            if not model_name:
                raise ValueError(f"invalid fallback model reference: {candidate}")
            canonical_provider = _normalize_provider_or_raise(provider_hint)
            candidate = f"{canonical_provider}/{model_name}"
        if candidate in seen:
            continue
        normalized.append(candidate)
        seen.add(candidate)
    return tuple(normalized)


def _normalize_strings(values: Any) -> tuple[str, ...]:
    if isinstance(values, str):
        values = [values]
    if not isinstance(values, (list, tuple)):
        return ()
    normalized: list[str] = []
    for raw in values:
        value = str(raw or "").strip()
        if value:
            normalized.append(value)
    return tuple(normalized)


def save_llm_config(
    *,
    home: Path | str | None = None,
    provider: str | None = None,
    model: str | None = None,
    openai_base_url: str | None = None,
    fallbacks: list[str] | tuple[str, ...] | None = None,
    profile: str | None = None,
) -> Path:
    document = _load_config_document(home)
    llm = document.get("llm")
    if not isinstance(llm, dict):
        llm = {}
    previous_provider = str(llm.get("provider", "")).strip().lower() if isinstance(llm.get("provider"), str) else ""
    normalized_provider: str | None = None
    if provider is not None:
        normalized_provider = _normalize_provider_or_raise(provider)
        llm["provider"] = normalized_provider
    else:
        current_provider = llm.get("provider")
        if isinstance(current_provider, str) and current_provider.strip():
            normalized_provider = _normalize_provider_or_raise(current_provider)
            llm["provider"] = normalized_provider
    if model is not None:
        llm["model"] = model.strip()
    provider_changed = bool(normalized_provider and normalized_provider != previous_provider)
    if openai_base_url is not None:
        llm["openai_base_url"] = openai_base_url.strip()
    elif normalized_provider is not None and provider_changed:
        spec = resolve_provider(normalized_provider)
        if spec.openai_compatible:
            llm["openai_base_url"] = provider_default_base_url(normalized_provider, fallback=DEFAULT_OPENAI_BASE_URL)
        else:
            llm["openai_base_url"] = ""
    if fallbacks is not None:
        normalized_fallbacks = list(_normalize_fallbacks(fallbacks))
        if normalized_fallbacks:
            llm["fallbacks"] = normalized_fallbacks
        else:
            llm.pop("fallbacks", None)
    if profile is not None:
        normalized_profile = profile.strip().lower()
        if normalized_profile:
            llm["profile"] = normalized_profile
        else:
            llm.pop("profile", None)
    elif any(value is not None for value in (provider, model, openai_base_url, fallbacks)):
        llm.pop("profile", None)
    document["llm"] = llm
    return _write_config_document(document, home=home)


def apply_llm_profile(*, home: Path | str | None = None, profile: str) -> Path:
    preset = resolve_llm_profile(profile)
    return save_llm_config(
        home=home,
        provider=preset["provider"],
        model=preset["model"],
        openai_base_url=preset.get("openai_base_url", ""),
        fallbacks=[],
        profile=profile,
    )


def reset_llm_config(*, home: Path | str | None = None) -> Path:
    document = _load_config_document(home)
    document.pop("llm", None)
    return _write_config_document(document, home=home)


def save_ui_config(*, home: Path | str | None = None, theme: str | None = None) -> Path:
    document = _load_config_document(home)
    ui = document.get("ui")
    if not isinstance(ui, dict):
        ui = {}
    if theme is not None:
        ui["theme"] = normalize_theme(theme)
    document["ui"] = ui
    return _write_config_document(document, home=home)


def _load_agent_profiles(document: dict[str, Any]) -> AgentsConfig:
    raw_agents = document.get("agents") if isinstance(document.get("agents"), dict) else {}
    raw_profiles = raw_agents.get("profiles") if isinstance(raw_agents.get("profiles"), dict) else {}
    profiles: dict[str, AgentProfileConfig] = {}
    for name, payload in raw_profiles.items():
        values = payload if isinstance(payload, dict) else {}
        profile_name = str(values.get("name") or name).strip() or name
        provider = values.get("provider")
        normalized_provider = _normalize_provider_or_raise(provider) if provider else None
        profiles[name] = AgentProfileConfig(
            name=profile_name,
            provider=normalized_provider,
            model=str(values.get("model")).strip() if values.get("model") else None,
            openai_base_url=str(values.get("openai_base_url")).strip() if values.get("openai_base_url") is not None else None,
            fallbacks=_normalize_fallbacks(values.get("fallbacks")),
            enabled_toolsets=_normalize_strings(values.get("enabled_toolsets")),
            disabled_toolsets=_normalize_strings(values.get("disabled_toolsets")),
            max_risk=str(values.get("max_risk")).strip() if values.get("max_risk") else None,
            allow_private_only=bool(values.get("allow_private_only")) if values.get("allow_private_only") is not None else None,
            roe_profile=str(values.get("roe_profile")).strip() if values.get("roe_profile") else None,
        )
    if "default" not in profiles:
        profiles["default"] = AgentProfileConfig(name="default")
    raw_routes = raw_agents.get("routes") if isinstance(raw_agents.get("routes"), list) else []
    routes = tuple(
        AgentRouteConfig(
            agent=str(item.get("agent", "default")).strip() or "default",
            target_schemes=_normalize_strings(item.get("target_schemes")),
            target_contains=_normalize_strings(item.get("target_contains")),
            match_private=item.get("match_private") if item.get("match_private") in {True, False} else None,
        )
        for item in raw_routes
        if isinstance(item, dict)
    )
    default_agent = str(raw_agents.get("default_agent", "default")).strip() or "default"
    active_agent = str(raw_agents.get("active_agent", default_agent)).strip() or default_agent
    return AgentsConfig(default_agent=default_agent, active_agent=active_agent, profiles=profiles, routes=routes)


def load_config(home: Path | str | None = None) -> AppConfig:
    """Load the first-pass Ares config from env, persisted config, and defaults."""
    resolved_home = resolve_home(home)
    document = _load_config_document(resolved_home)
    persisted_llm = document.get("llm") if isinstance(document.get("llm"), dict) else {}
    persisted_ui = document.get("ui") if isinstance(document.get("ui"), dict) else {}
    persisted_hooks = document.get("hooks") if isinstance(document.get("hooks"), dict) else {}
    persisted_gateway = document.get("gateway") if isinstance(document.get("gateway"), dict) else {}

    provider = _normalize_provider_or_raise(
        os.getenv("ARES_LLM_PROVIDER", str(persisted_llm.get("provider", DEFAULT_LLM_PROVIDER)))
    )
    default_base_url = provider_default_base_url(provider, fallback=DEFAULT_OPENAI_BASE_URL)
    llm = LLMConfig(
        provider=provider,
        model=os.getenv("ARES_LLM_MODEL", str(persisted_llm.get("model", DEFAULT_LLM_MODEL))),
        openai_base_url=os.getenv(
            "ARES_OPENAI_BASE_URL",
            str(persisted_llm.get("openai_base_url", default_base_url)),
        ),
        fallbacks=_normalize_fallbacks(persisted_llm.get("fallbacks")),
    )
    default_mode = os.getenv("ARES_DEFAULT_MODE", DEFAULT_MODE)
    roe_profile = os.getenv("ARES_ROE_PROFILE", default_mode)
    profile = ROEProfileRegistry.builtin().get(roe_profile)
    policy = PolicyConfig(
        default_mode=default_mode,
        allow_private_only=_env_bool("ARES_ALLOW_PRIVATE_ONLY", True),
        max_risk=os.getenv("ARES_MAX_RISK", profile.max_risk),
        roe_profile=roe_profile,
    )
    ui = UIConfig(theme=normalize_theme(os.getenv("ARES_UI_THEME", str(persisted_ui.get("theme", DEFAULT_THEME)))))
    hooks = HooksConfig(auto_report_on_finish=_env_bool("ARES_AUTO_REPORT_ON_FINISH", bool(persisted_hooks.get("auto_report_on_finish", False))))
    gateway = GatewayConfig(
        host=str(persisted_gateway.get("host", DEFAULT_GATEWAY_HOST)),
        port=int(persisted_gateway.get("port", DEFAULT_GATEWAY_PORT)),
    )
    agents = _load_agent_profiles(document)
    return AppConfig(home=resolved_home, llm=llm, policy=policy, ui=ui, hooks=hooks, gateway=gateway, agents=agents)

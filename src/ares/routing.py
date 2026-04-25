from __future__ import annotations

import ipaddress
from dataclasses import replace
from typing import Any
from urllib.parse import urlparse

from ares.config.loader import (
    AgentProfileConfig,
    AgentRouteConfig,
    AgentsConfig,
    AppConfig,
    LLMConfig,
    PolicyConfig,
)
from ares.llm.providers import provider_default_base_url


class AgentResolution:
    def __init__(self, *, agent_name: str, profile: AgentProfileConfig, reason: str) -> None:
        self.agent_name = agent_name
        self.profile = profile
        self.reason = reason


class AgentRouter:
    def __init__(self, config: AgentsConfig | None = None) -> None:
        self.config = config or AgentsConfig()

    def resolve(self, *, target: str | None = None, requested_agent: str | None = None) -> AgentResolution:
        if requested_agent:
            profile = self._profile_for(requested_agent)
            return AgentResolution(agent_name=profile.name, profile=profile, reason="requested")
        for route in self.config.routes:
            if self._matches(route, target):
                profile = self._profile_for(route.agent)
                return AgentResolution(agent_name=profile.name, profile=profile, reason="route")
        profile = self._profile_for(self.config.default_agent)
        return AgentResolution(agent_name=profile.name, profile=profile, reason="default")

    def _profile_for(self, name: str) -> AgentProfileConfig:
        if name in self.config.profiles:
            return self.config.profiles[name]
        if name == "default":
            return AgentProfileConfig(name="default")
        raise KeyError(f"unknown agent profile: {name}")

    def _matches(self, route: AgentRouteConfig, target: str | None) -> bool:
        if target is None:
            return False
        parsed = urlparse(str(target))
        scheme = parsed.scheme.lower()
        raw_target = str(target).lower()
        if route.target_schemes and scheme not in {item.lower() for item in route.target_schemes}:
            return False
        if route.target_contains and not any(token.lower() in raw_target for token in route.target_contains):
            return False
        if route.match_private is not None:
            is_private = _target_is_private(target)
            if is_private != route.match_private:
                return False
        return True


def apply_agent_profile(config: AppConfig, resolution: AgentResolution) -> AppConfig:
    profile = resolution.profile
    provider = profile.provider or config.llm.provider
    openai_base_url = _resolve_base_url(config, profile, provider)
    llm = replace(
        config.llm,
        provider=provider,
        model=profile.model or config.llm.model,
        openai_base_url=openai_base_url,
        fallbacks=profile.fallbacks or config.llm.fallbacks,
    )
    policy = replace(
        config.policy,
        max_risk=profile.max_risk or config.policy.max_risk,
        allow_private_only=config.policy.allow_private_only if profile.allow_private_only is None else profile.allow_private_only,
        roe_profile=profile.roe_profile or config.policy.roe_profile,
    )
    agents = replace(config.agents, active_agent=resolution.agent_name)
    return AppConfig(
        home=config.home,
        llm=llm,
        policy=policy,
        ui=config.ui,
        hooks=config.hooks,
        gateway=config.gateway,
        agents=agents,
    )


def _resolve_base_url(config: AppConfig, profile: AgentProfileConfig, provider: str) -> str:
    if profile.openai_base_url is not None:
        return profile.openai_base_url
    if provider == config.llm.provider:
        return config.llm.openai_base_url
    return provider_default_base_url(provider, fallback=config.llm.openai_base_url)


def _target_is_private(target: str) -> bool:
    host = _target_to_host(target)
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        return False
    return ip.is_private or ip.is_loopback


def _target_to_host(target: str) -> str:
    parsed = urlparse(str(target))
    if parsed.scheme and parsed.hostname:
        return parsed.hostname
    return str(target).strip().strip("[]")

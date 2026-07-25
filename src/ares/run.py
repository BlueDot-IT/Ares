from __future__ import annotations

import json
import os
from dataclasses import replace
from pathlib import Path
from typing import Any

from ares.agent.context_builder import ContextBuilder
from ares.agent.dispatcher import ToolDispatcher
from ares.agent.prompt_builder import PromptBuilder
from ares.agent.runtime import AgentRuntime, ModelClient, RuntimeResult
from ares.agent.tool_result_indexer import should_index_tool_result, tool_result_to_memory_text
from ares.config.loader import AppConfig, DEFAULT_OPENAI_BASE_URL, config_file_path, infer_llm_profile, load_config, load_home_env
from ares.engagement_memory import build_engagement_memory_context
from ares.hooks import HookManager
from ares.llm import AnthropicModel, GeminiModel, OpenAICompatModel, resolve_api_key, resolve_provider
from ares.llm.failover import FailoverCandidate, FailoverModel
from ares.policy.context import PolicyContext
from ares.policy.roe import ROEProfileRegistry
from ares.playbooks.registry import PlaybookRegistry
from ares.reporting.markdown import render_session_report
from ares.routing import AgentRouter, apply_agent_profile
from ares.state.db import StateDB
from ares.tools.evidence_memory import register_evidence_tools
from ares.tools.ghostmcp_adapter import register_ghostmcp_tools
from ares.tools.onionclaw_adapter import register_onionclaw_tools
from ares.tools.registry import ToolRegistry


def build_policy(config: AppConfig) -> PolicyContext:
    return PolicyContext(
        max_risk=config.policy.max_risk,
        allow_private_only=config.policy.allow_private_only,
    )


def build_registry(
    config: AppConfig | None = None,
    *,
    state_db: StateDB | None = None,
    session_id: int | None = None,
    ghostmcp_engagement_policy_file: str | Path | None = None,
) -> ToolRegistry:
    config = config or load_config()
    registry = ToolRegistry()
    ghostmcp_options: dict[str, Any] = {
        "policy_allow_private_only": config.policy.allow_private_only,
    }
    if ghostmcp_engagement_policy_file is not None:
        ghostmcp_options["engagement_policy_file"] = (
            ghostmcp_engagement_policy_file
        )
    register_ghostmcp_tools(registry, **ghostmcp_options)
    register_onionclaw_tools(registry, config=config.onionclaw)
    from ares.mission.tools import register_mission_tools
    register_mission_tools(registry)
    if state_db is not None:
        register_evidence_tools(registry, state_db, session_id)
    return registry


def _build_single_model(
    *,
    home: Path,
    provider: str,
    model: str,
    openai_base_url: str,
    auth_mode: str = "api-key",
    oauth_token_command: str = "",
    oauth_project: str = "",
    oauth_location: str = "",
) -> ModelClient:
    load_home_env(home, override=False)
    spec = resolve_provider(provider)
    api_key = None if auth_mode == "oauth" else resolve_api_key(spec.name)
    if spec.family == "anthropic":
        return AnthropicModel(
            model=model,
            api_key=api_key,
            provider=spec.name,
        )
    if spec.family == "gemini":
        return GeminiModel(
            model=model,
            api_key=api_key,
            provider=spec.name,
            auth_mode=auth_mode,
            oauth_token_command=oauth_token_command,
            oauth_project=oauth_project,
            oauth_location=oauth_location,
            home=home,
        )
    return OpenAICompatModel(
        model=model,
        base_url=openai_base_url,
        api_key=None if auth_mode == "oauth" else (api_key or os.getenv("OPENAI_API_KEY", "lm-studio")),
        provider=spec.name,
        auth_mode=auth_mode,
        oauth_token_command=oauth_token_command,
        home=home,
    )


def _parse_model_reference(raw: str, *, default_provider: str) -> tuple[str, str]:
    reference = str(raw or "").strip()
    if not reference:
        raise ValueError("model reference must not be empty")
    if "/" not in reference:
        return resolve_provider(default_provider).name, reference
    provider_hint, model_name = reference.split("/", 1)
    provider = resolve_provider(provider_hint).name
    return provider, model_name.strip()


def _resolve_fallback_base_url(*, provider: str, primary_provider: str, primary_base_url: str) -> str:
    spec = resolve_provider(provider)
    if not spec.openai_compatible:
        return ""
    if spec.name == resolve_provider(primary_provider).name and primary_base_url.strip():
        return primary_base_url.strip()
    return spec.default_base_url or primary_base_url.strip() or DEFAULT_OPENAI_BASE_URL


def _dedupe_candidates(candidates: list[FailoverCandidate]) -> list[FailoverCandidate]:
    seen: set[tuple[str, str]] = set()
    unique: list[FailoverCandidate] = []
    for candidate in candidates:
        key = (candidate.provider.strip().lower(), candidate.model.strip())
        if key in seen:
            continue
        seen.add(key)
        unique.append(candidate)
    return unique


def build_model(config: AppConfig) -> ModelClient:
    primary_provider = resolve_provider(config.llm.provider).name
    if not config.llm.fallbacks:
        return _build_single_model(
            home=config.home,
            provider=primary_provider,
            model=config.llm.model,
            openai_base_url=config.llm.openai_base_url,
            auth_mode=config.llm.auth_mode,
            oauth_token_command=config.llm.oauth_token_command,
            oauth_project=config.llm.oauth_project,
            oauth_location=config.llm.oauth_location,
        )
    candidates = [
        FailoverCandidate(
            provider=primary_provider,
            model=config.llm.model,
            client=lambda provider=primary_provider, model=config.llm.model, openai_base_url=config.llm.openai_base_url, auth_mode=config.llm.auth_mode, oauth_token_command=config.llm.oauth_token_command, oauth_project=config.llm.oauth_project, oauth_location=config.llm.oauth_location: _build_single_model(
                home=config.home,
                provider=provider,
                model=model,
                openai_base_url=openai_base_url,
                auth_mode=auth_mode,
                oauth_token_command=oauth_token_command,
                oauth_project=oauth_project,
                oauth_location=oauth_location,
            ),
        )
    ]
    for reference in config.llm.fallbacks:
        provider, model = _parse_model_reference(reference, default_provider=primary_provider)
        fallback_base_url = _resolve_fallback_base_url(
            provider=provider,
            primary_provider=primary_provider,
            primary_base_url=config.llm.openai_base_url,
        )
        candidates.append(
            FailoverCandidate(
                provider=provider,
                model=model,
                client=lambda provider=provider, model=model, openai_base_url=fallback_base_url, auth_mode=config.llm.auth_mode, oauth_token_command=config.llm.oauth_token_command, oauth_project=config.llm.oauth_project, oauth_location=config.llm.oauth_location: _build_single_model(
                    home=config.home,
                    provider=provider,
                    model=model,
                    openai_base_url=openai_base_url,
                    auth_mode=auth_mode,
                    oauth_token_command=oauth_token_command,
                    oauth_project=oauth_project,
                    oauth_location=oauth_location,
                ),
            )
        )
    candidates = _dedupe_candidates(candidates)
    return FailoverModel(candidates)


def build_user_message(prompt: str, target: str | None = None, prompt_prefix: str | None = None) -> str:
    prompt = prompt.strip()
    if prompt_prefix:
        prompt = f"{prompt_prefix}{prompt}".strip()
    if target:
        return f"Target: {target.strip()}\n\nTask: {prompt}"
    return prompt


def list_registered_tools(registry: ToolRegistry) -> list[dict[str, Any]]:
    return [
        {
            "name": entry.name,
            "toolset": entry.toolset,
            "risk": entry.risk,
            "available": registry.check_tool_availability()[entry.name].available,
        }
        for entry in sorted(registry.iter_entries(), key=lambda item: item.name)
    ]


def build_doctor_snapshot(*, config: AppConfig | None = None, registry: ToolRegistry | None = None) -> dict[str, Any]:
    config = config or load_config()
    registry = registry or build_registry(config)
    return {
        "home": str(config.home),
        "llm_provider": config.llm.provider,
        "llm_model": config.llm.model,
        "ui_theme": config.ui.theme,
        "default_mode": config.policy.default_mode,
        "roe_profile": config.policy.roe_profile,
        "max_risk": config.policy.max_risk,
        "active_agent": config.agents.active_agent,
        "agent_profiles": len(config.agents.profiles),
        "gateway": f"{config.gateway.host}:{config.gateway.port}",
        "onionclaw_enabled": config.onionclaw.enabled,
        "auto_report_on_finish": config.hooks.auto_report_on_finish,
        "registered_tools": len(registry.check_tool_availability()),
    }


def build_model_snapshot(*, config: AppConfig | None = None) -> dict[str, Any]:
    config = config or load_config()
    path = config_file_path(config.home)
    spec = resolve_provider(config.llm.provider)
    persisted = {}
    if path.exists():
        try:
            loaded = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            loaded = {}
        if isinstance(loaded, dict) and isinstance(loaded.get("llm"), dict):
            persisted = loaded["llm"]

    def _source(env_name: str, persisted_key: str) -> str:
        if os.getenv(env_name) is not None:
            return f"env:{env_name}"
        if persisted_key in persisted:
            return f"config:{path}"
        if persisted_key == "profile":
            inferred = infer_llm_profile(config.llm)
            return "derived" if inferred else "none"
        if persisted_key == "openai_base_url":
            if not spec.openai_compatible:
                return "native"
            if spec.default_base_url and config.llm.openai_base_url == spec.default_base_url:
                return f"provider-default:{spec.name}"
        return "default"

    profile_name = str(persisted.get("profile", "")).strip().lower() or infer_llm_profile(config.llm) or "-"

    return {
        "profile": profile_name,
        "profile_source": _source("LLM_PROFILE", "profile"),
        "provider": config.llm.provider,
        "provider_source": _source("LLM_PROVIDER", "provider"),
        "model": config.llm.model,
        "model_source": _source("LLM_MODEL", "model"),
        "base_url": config.llm.openai_base_url or "-",
        "base_url_source": _source("OPENAI_BASE_URL", "openai_base_url"),
        "auth_mode": config.llm.auth_mode,
        "auth_mode_source": _source("LLM_AUTH_MODE", "auth_mode"),
        "fallbacks": list(config.llm.fallbacks),
        "fallbacks_source": f"config:{path}" if persisted.get("fallbacks") else "none",
        "config_path": str(path),
    }


def format_model_snapshot(snapshot: dict[str, Any]) -> str:
    fallback_chain = ", ".join(snapshot.get("fallbacks") or []) or "-"
    return "\n".join(
        [
            "Model",
            "=====",
            f"profile: {snapshot['profile']} ({snapshot['profile_source']})",
            f"provider: {snapshot['provider']} ({snapshot['provider_source']})",
            f"model: {snapshot['model']} ({snapshot['model_source']})",
            f"base_url: {snapshot['base_url']} ({snapshot['base_url_source']})",
            f"auth_mode: {snapshot['auth_mode']} ({snapshot['auth_mode_source']})",
            f"fallbacks: {fallback_chain} ({snapshot.get('fallbacks_source', 'none')})",
            f"config_path: {snapshot['config_path']}",
        ]
    )


def list_session_summaries(state_db: StateDB) -> list[dict[str, Any]]:
    return [
        {
            "id": int(session["id"]),
            "created_at": session.get("created_at"),
            "target": session.get("target"),
            "agent": session.get("agent") or "default",
            "model": session.get("model"),
            "mode": session.get("mode"),
            "status": session.get("status"),
        }
        for session in state_db.list_sessions()
    ]


def write_session_report(state_db: StateDB, session_id: int, output_dir: str | Path) -> Path:
    output = Path(output_dir)
    output.mkdir(parents=True, exist_ok=True)
    path = output / f"session-{session_id}.md"
    path.write_text(render_session_report(state_db, session_id), encoding="utf-8")
    return path


def run_once(
    *,
    prompt: str,
    target: str | None = None,
    requested_agent: str | None = None,
    config: AppConfig | None = None,
    model: ModelClient | None = None,
    registry: ToolRegistry | None = None,
    max_iterations: int = 20,
    state_db: StateDB | None = None,
    approve_dangerous: bool = False,
    policy_allow_private_only: bool | None = None,
    event_callback: callable | None = None,
    session_started_callback: callable | None = None,
    hook_manager: HookManager | None = None,
) -> RuntimeResult:
    """Run a single autonomous task through the new runtime stack."""
    config = config or load_config()
    router = AgentRouter(config.agents)
    resolution = router.resolve(
        prompt=prompt,
        target=target,
        requested_agent=requested_agent,
        roe_profile=config.policy.roe_profile,
    )
    config = apply_agent_profile(config, resolution)
    if policy_allow_private_only is not None:
        config = replace(config, policy=replace(config.policy, allow_private_only=policy_allow_private_only))
    policy = build_policy(config)
    model = model or build_model(config)
    state_db = state_db or StateDB(config.home / "state.db")
    hook_manager = hook_manager or HookManager(home=config.home, auto_report_on_finish=config.hooks.auto_report_on_finish)
    enabled_toolsets = set(resolution.profile.enabled_toolsets or ()) or None
    disabled_toolsets = set(resolution.profile.disabled_toolsets or ()) or None

    session_id = state_db.create_session(
        prompt=prompt,
        target=target,
        agent=resolution.agent_name,
        model=config.llm.model,
        mode=config.policy.default_mode,
    )

    registry = registry or build_registry(config, state_db=state_db, session_id=session_id)

    def emit_event(payload: dict[str, Any]) -> None:
        event = dict(payload)
        event.setdefault("target", target)
        event.setdefault("agent", resolution.agent_name)
        event.setdefault("requested_agent", requested_agent)
        event.setdefault("memory_tags", list(resolution.profile.memory_tags))
        event.setdefault("session_id", session_id)
        if event_callback is not None:
            event_callback(event)
        hook_manager.emit(event, state_db=state_db)

    if session_started_callback is not None:
        session_started_callback(session_id)
    emit_event(
        {
            "type": "session_started",
            "prompt": prompt,
            "message": f"session {session_id} started",
        }
    )
    emit_event(
        {
            "type": "route_selected",
            "route_reason": resolution.reason,
            "message": f"agent {resolution.agent_name} selected via {resolution.reason}",
        }
    )
    playbooks = PlaybookRegistry.builtin().select_for_context(target=target)
    system_prompt = PromptBuilder().build_system_prompt(
        target=target,
        policy=policy,
        playbooks=[playbook.content for playbook in playbooks],
    )
    context_summary = ContextBuilder(state_db, home=config.home).build_session_context(
        session_id,
        target=target,
        memory_tags=resolution.profile.memory_tags,
        query=prompt,
    )
    roe_profile = ROEProfileRegistry.builtin().get(config.policy.roe_profile)
    dispatcher = ToolDispatcher(
        registry=registry,
        policy=policy,
        recorder=state_db,
        session_id=session_id,
        approval_callback=(lambda _call, _entry: True) if approve_dangerous else None,
        approval_required_risks=set(roe_profile.approval_required_risks),
        engagement_id=f"ares-session-{session_id}",
    )
    runtime = AgentRuntime(
        model=model,
        registry=registry,
        policy=policy,
        max_iterations=max_iterations,
        system_prompt=system_prompt,
        context_summary=context_summary,
        dispatcher=dispatcher,
        event_callback=emit_event,
        enabled_toolsets=enabled_toolsets,
        disabled_toolsets=disabled_toolsets,
    )
    try:
        result = runtime.run(build_user_message(prompt, target, resolution.profile.prompt_prefix))
        persist_messages(state_db, session_id, result.messages)
        state_db.finish_session(session_id, result.stop_reason)
    except Exception as exc:
        state_db.finish_session(session_id, "error")
        emit_event(
            {
                "type": "session_failed",
                "error": str(exc),
                "message": str(exc),
            }
        )
        raise
    emit_event(
        {
            "type": "session_finished",
            "stop_reason": result.stop_reason,
            "final_response": result.final_response,
            "message": result.final_response or result.stop_reason,
        }
    )
    return result


def persist_messages(state_db: StateDB, session_id: int, messages: list[dict[str, Any]]) -> None:
    for message in messages:
        role = str(message.get("role", "unknown"))
        content = message.get("content", "")
        if not isinstance(content, str):
            content = json.dumps(content, sort_keys=True)
        state_db.record_message(
            session_id=session_id,
            role=role,
            content=content,
            message=message,
        )


def format_runtime_result(result: RuntimeResult) -> str:
    lines: list[str] = []
    lines.append(f"stop_reason: {result.stop_reason}")
    if result.final_response:
        lines.append(f"final_response: {result.final_response}")
    if result.tool_results:
        lines.append("tool_results:")
        for item in result.tool_results:
            if item.status == "ok":
                lines.append(f"- {item.tool}: ok")
            else:
                lines.append(f"- {item.tool}: error: {item.error}")
    return "\n".join(lines)

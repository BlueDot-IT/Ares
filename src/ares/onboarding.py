from __future__ import annotations

import secrets
from dataclasses import dataclass
from pathlib import Path

from ares.config.loader import (
    apply_llm_profile,
    load_config,
    save_gateway_config,
    save_hooks_config,
    save_llm_config,
    save_ui_config,
)
from ares.llm.oauth import build_oauth_broker
from ares.llm.provider_catalog import ProviderChoice, get_provider_choice, list_provider_choices
from ares.prompt_ui import Choice, ask_text, confirm, select_one


@dataclass(frozen=True)
class ModelSetupResult:
    profile_name: str
    provider_name: str
    model_name: str
    base_url: str
    auth_mode: str
    oauth_project: str = ""
    oauth_location: str = ""
    oauth_sign_in_complete: bool = False


@dataclass(frozen=True)
class FullOnboardingResult:
    model_setup: ModelSetupResult
    theme: str
    gateway_mode: str
    gateway_auth_enabled: bool
    allow_cidrs: tuple[str, ...]
    auto_report_on_finish: bool


def run_model_setup(*, home: Path) -> ModelSetupResult:
    cfg = load_config(home)
    provider_choices = list_provider_choices()
    default_profile = next((choice.key for choice in provider_choices if choice.key == "local"), provider_choices[0].key)
    selected_key = select_one(
        "Model profile",
        choices=[Choice(value=choice.key, label=choice.label, hint=choice.hint) for choice in provider_choices],
        default=default_profile,
    )
    selected = get_provider_choice(selected_key)

    if selected.persisted_profile:
        apply_llm_profile(home=home, profile=selected.key)
    current = load_config(home)
    model_name = ask_text("Model name", default=current.llm.model or selected.default_model)
    auth_mode = _prompt_auth_mode(selected, current=current)
    oauth_project = ""
    oauth_location = ""
    oauth_sign_in_complete = False
    if auth_mode == "oauth" and selected.provider == "gemini":
        oauth_project = ask_text("OAuth project", default=current.llm.oauth_project)
        oauth_location = ask_text("OAuth location", default=current.llm.oauth_location or "us-central1")
        if confirm("Sign in now?", default=False):
            build_oauth_broker(home=home).login("gemini")
            oauth_sign_in_complete = True

    base_url = _resolve_base_url(selected, current=current)
    save_llm_config(
        home=home,
        provider=selected.provider,
        model=model_name,
        openai_base_url=base_url,
        profile=selected.key if selected.persisted_profile else "",
        auth_mode=auth_mode,
        oauth_token_command="",
        oauth_project=oauth_project,
        oauth_location=oauth_location,
    )
    final_cfg = load_config(home)
    return ModelSetupResult(
        profile_name=selected.key,
        provider_name=final_cfg.llm.provider,
        model_name=final_cfg.llm.model,
        base_url=final_cfg.llm.openai_base_url,
        auth_mode=final_cfg.llm.auth_mode,
        oauth_project=final_cfg.llm.oauth_project,
        oauth_location=final_cfg.llm.oauth_location,
        oauth_sign_in_complete=oauth_sign_in_complete,
    )


def run_full_onboarding(*, home: Path) -> FullOnboardingResult:
    model_setup = run_model_setup(home=home)
    current = load_config(home)
    theme_name = ask_text("Theme", default=current.ui.theme)
    save_ui_config(home=home, theme=theme_name)

    gateway_mode = select_one(
        "Gateway mode",
        choices=[
            Choice(value="loopback", label="Loopback only", hint="Local browser and CLI access only."),
            Choice(value="lan", label="LAN only", hint="Accessible from your local network."),
            Choice(value="exposed", label="Remote / exposed", hint="Reachable from outside the local machine."),
        ],
        default=current.gateway.mode,
    )
    auth_enabled: bool | None = None
    operator_token: str | None = None
    allow_cidrs: tuple[str, ...] = ()
    if gateway_mode == "exposed":
        auth_enabled = confirm("Require gateway bearer auth in exposed mode?", default=True)
        if auth_enabled:
            operator_token = ask_text(
                "Operator token",
                default=current.gateway.operator_token or secrets.token_urlsafe(18),
                hide_input=True,
            )
        allow_cidrs = tuple(
            _split_csv_values(
                ask_text(
                    "Gateway allow CIDRs (comma-separated, blank for none)",
                    default=", ".join(current.gateway.allow_cidrs),
                    allow_empty=True,
                )
            )
        )
    save_gateway_config(
        home=home,
        mode=gateway_mode,
        auth_enabled=auth_enabled,
        operator_token=operator_token,
        allow_cidrs=list(allow_cidrs),
    )

    final_cfg = load_config(home)
    auto_report = confirm(
        "Auto-write Markdown reports after finished sessions?",
        default=final_cfg.hooks.auto_report_on_finish,
    )
    save_hooks_config(home=home, auto_report_on_finish=auto_report)
    final_cfg = load_config(home)
    return FullOnboardingResult(
        model_setup=model_setup,
        theme=final_cfg.ui.theme,
        gateway_mode=final_cfg.gateway.mode,
        gateway_auth_enabled=final_cfg.gateway.auth_enabled,
        allow_cidrs=final_cfg.gateway.allow_cidrs,
        auto_report_on_finish=final_cfg.hooks.auto_report_on_finish,
    )


def format_onboarding_summary(*, home: Path, result: FullOnboardingResult) -> list[str]:
    final_cfg = load_config(home)
    lines = [
        "",
        "Ares onboarding complete.",
        f"config: {final_cfg.home / 'config.json'}",
        f"profile: {result.model_setup.profile_name}",
        f"provider: {final_cfg.llm.provider}",
        f"model: {final_cfg.llm.model}",
        f"base_url: {final_cfg.llm.openai_base_url or '-'}",
        f"auth_mode: {final_cfg.llm.auth_mode}",
        f"oauth sign-in: {'complete' if result.model_setup.oauth_sign_in_complete else 'skipped'}",
        f"theme: {final_cfg.ui.theme}",
        f"gateway mode: {final_cfg.gateway.mode}",
        f"gateway auth: {'enabled' if final_cfg.gateway.auth_enabled else 'disabled'}",
        f"allow_cidrs: {', '.join(final_cfg.gateway.allow_cidrs) or '-'}",
        f"auto_report_on_finish: {'yes' if final_cfg.hooks.auto_report_on_finish else 'no'}",
    ]
    if result.model_setup.profile_name == "openrouter":
        lines.append("Remember to export OPENROUTER_API_KEY before running Ares.")
    elif result.model_setup.profile_name == "anthropic":
        lines.append("Remember to install '.[anthropic]' and export ANTHROPIC_API_KEY.")
    elif result.model_setup.profile_name == "gemini":
        if final_cfg.llm.auth_mode == "oauth":
            lines.append("Use 'ares auth login --provider gemini' if you skipped sign-in or need to refresh cached Google credentials.")
        else:
            lines.append("Remember to install '.[gemini]' and export GEMINI_API_KEY.")
    return lines


def _prompt_auth_mode(choice: ProviderChoice, *, current) -> str:
    if len(choice.auth_methods) == 1:
        return choice.auth_methods[0]
    return select_one(
        "Model auth mode",
        choices=[
            Choice(value="api-key", label="API key", hint="Use an environment variable such as GEMINI_API_KEY."),
            Choice(value="oauth", label="OAuth", hint="Use cached Google credentials with a real sign-in flow."),
        ],
        default=current.llm.auth_mode,
    )


def _resolve_base_url(choice: ProviderChoice, *, current) -> str | None:
    default_endpoint = choice.default_endpoint or current.llm.openai_base_url
    if choice.key == "custom":
        return ask_text("OpenAI-compatible base URL", default=default_endpoint, allow_empty=False)
    if choice.endpoint_mode == "native":
        return None
    return default_endpoint or None


def _split_csv_values(raw: str) -> list[str]:
    return [item.strip() for item in str(raw or "").split(",") if item.strip()]

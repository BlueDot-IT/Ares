from __future__ import annotations

import json
import secrets
from urllib import error as urllib_error
from urllib import request as urllib_request

import typer

from ares import APP_NAME, __version__
from ares.config.loader import (
    apply_llm_profile,
    gateway_mode_defaults,
    load_config,
    reset_llm_config,
    resolve_gateway_mode,
    save_gateway_config,
    save_hooks_config,
    save_llm_config,
    save_ui_config,
)
from ares.engagement_memory import list_engagement_memories
from ares.gateway import AresGateway, start_gateway_server
from ares.llm.oauth import build_oauth_broker
from ares.onboarding import format_onboarding_summary, run_full_onboarding, run_model_setup
from ares.prompt_ui import Choice, select_one
from ares.routing import AgentRouter, apply_agent_profile
from ares.run import (
    build_doctor_snapshot,
    build_model_snapshot,
    build_registry,
    format_model_snapshot,
    format_runtime_result,
    list_registered_tools,
    list_session_summaries,
    run_once,
    write_session_report,
)
from ares.state.db import StateDB
from ares.tui import launch_tui

app = typer.Typer(help=f"{APP_NAME} autonomous testing suite", invoke_without_command=True)
auth_app = typer.Typer(help="Manage cached OAuth credentials for supported model providers.")
app.add_typer(auth_app, name="auth")


@app.callback()
def main(
    ctx: typer.Context,
    version: bool = typer.Option(False, "--version", help="Show version and exit"),
) -> None:
    if version:
        typer.echo(__version__)
        raise typer.Exit(0)
    if ctx.invoked_subcommand is None:
        launch_tui(refresh_interval=0.5, yolo_mode=False)


@app.command("doctor")
def doctor() -> None:
    """Show runtime configuration and tool registry status."""
    snapshot = build_doctor_snapshot(registry=build_registry())
    for key, value in snapshot.items():
        typer.echo(f"{key}: {value}")


@app.command("model")
def model(
    provider: str | None = typer.Option(None, "--provider", help="Persist the default model provider."),
    model_name: str | None = typer.Option(None, "--model", help="Persist the default model name."),
    base_url: str | None = typer.Option(None, "--base-url", help="Persist the OpenAI-compatible base URL."),
    fallback: list[str] | None = typer.Option(None, "--fallback", help="Append a fallback model reference like openrouter/openai/gpt-4o-mini."),
    clear_fallbacks: bool = typer.Option(False, "--clear-fallbacks", help="Remove all persisted fallback models."),
    profile: str | None = typer.Option(None, "--profile", help="Apply a named model profile."),
    interactive: bool = typer.Option(False, "--interactive", help="Launch an interactive model setup wizard."),
    auth_mode: str | None = typer.Option(None, "--auth-mode", help="Persist the model auth mode: api-key or oauth."),
    oauth_token_command: str | None = typer.Option(None, "--oauth-token-command", help="Command that prints a fresh OAuth access token."),
    oauth_project: str | None = typer.Option(None, "--oauth-project", help="OAuth cloud project, used for Gemini Vertex AI auth."),
    oauth_location: str | None = typer.Option(None, "--oauth-location", help="OAuth cloud location, used for Gemini Vertex AI auth."),
    reset: bool = typer.Option(False, "--reset", help="Reset persisted model settings to defaults."),
) -> None:
    """Show or update the persisted model configuration."""
    cfg = load_config()
    if reset:
        reset_llm_config(home=cfg.home)
    elif interactive:
        run_model_setup(home=cfg.home)
        typer.echo("Model setup complete.")
    elif profile:
        apply_llm_profile(home=cfg.home, profile=profile)
    elif any(value is not None for value in (provider, model_name, base_url, auth_mode, oauth_token_command, oauth_project, oauth_location)) or fallback or clear_fallbacks:
        merged_fallbacks = [] if clear_fallbacks else [*cfg.llm.fallbacks, *(fallback or [])]
        save_llm_config(
            home=cfg.home,
            provider=provider,
            model=model_name,
            openai_base_url=base_url,
            fallbacks=merged_fallbacks if (fallback or clear_fallbacks) else None,
            auth_mode=auth_mode,
            oauth_token_command=oauth_token_command,
            oauth_project=oauth_project,
            oauth_location=oauth_location,
        )
    typer.echo(format_model_snapshot(build_model_snapshot(config=load_config(cfg.home))))


@app.command("theme")
def theme(
    name: str = typer.Argument(..., help="Theme name to persist for the TUI."),
) -> None:
    cfg = load_config()
    save_ui_config(home=cfg.home, theme=name)
    typer.echo(f"theme: {load_config(cfg.home).ui.theme}")


def _prompt_choice(prompt: str, *, choices: list[str], default: str) -> str:
    normalized_choices = [choice.strip().lower() for choice in choices]
    while True:
        candidate = typer.prompt(prompt, default=default).strip().lower()
        if candidate in normalized_choices:
            return candidate
        typer.echo(f"Invalid choice: {candidate or '-'}")
        typer.echo(f"Choose one of: {', '.join(normalized_choices)}")


def _split_csv_values(raw: str) -> list[str]:
    return [item.strip() for item in str(raw or "").split(",") if item.strip()]


def _resolve_oauth_login_provider(*, provider: str | None, broker) -> str:
    if provider:
        return provider.strip().lower()
    flows = list(getattr(broker, "available_flows", lambda: [])() or [])
    if not flows:
        raise typer.BadParameter("No OAuth providers are available")
    if len(flows) == 1:
        return _value_or_attr(flows[0], "provider", str(_value_or_attr(flows[0], "key", ""))).strip().lower()
    selected = select_one(
        "Choose an OAuth provider",
        choices=[
            Choice(
                value=str(_value_or_attr(flow, "provider", _value_or_attr(flow, "key", ""))).strip().lower(),
                label=str(_value_or_attr(flow, "label", _value_or_attr(flow, "provider", _value_or_attr(flow, "key", "")))),
                hint=str(_value_or_attr(flow, "method", "")),
            )
            for flow in flows
        ],
        default=str(_value_or_attr(flows[0], "provider", _value_or_attr(flows[0], "key", ""))).strip().lower(),
        use_tty=None,
    )
    return selected.strip().lower()


@app.command("onboard")
def onboard() -> None:
    """Interactive first-run setup for model, theme, gateway, and hooks."""
    cfg = load_config()
    typer.echo("Ares onboarding")
    typer.echo("================")
    typer.echo(f"home: {cfg.home}")
    typer.echo("Answer the prompts below to persist your first-run configuration.")

    result = run_full_onboarding(home=cfg.home)
    for line in format_onboarding_summary(home=cfg.home, result=result):
        typer.echo(line)


@auth_app.command("login")
def auth_login(
    provider: str | None = typer.Option(None, "--provider", help="OAuth provider to sign in for. If omitted, choose from supported OAuth providers."),
) -> None:
    cfg = load_config()
    broker = build_oauth_broker(home=cfg.home)
    provider_name = _resolve_oauth_login_provider(provider=provider, broker=broker)
    info = broker.describe(provider_name)
    if info is None:
        raise typer.BadParameter(f"No OAuth flow is configured for provider '{provider_name}'")
    entry = broker.login(provider_name)
    typer.echo(f"Logged in: {provider_name}")
    typer.echo(f"method: {_value_or_attr(info, 'method', '-')}")
    typer.echo(f"expires_at: {_value_or_attr(entry, 'expires_at', '-')}")


@auth_app.command("status")
def auth_status(
    provider: str | None = typer.Option(None, "--provider", help="Limit status to one provider."),
) -> None:
    cfg = load_config()
    broker = build_oauth_broker(home=cfg.home)
    rows = broker.status(provider=provider)
    if not rows:
        typer.echo("No cached OAuth credentials found.")
        return
    for index, row in enumerate(rows):
        if index:
            typer.echo("")
        provider_name = _value_or_attr(row, "provider", "-")
        has_token = bool(_value_or_attr(row, "has_token", False))
        typer.echo(f"provider: {provider_name}")
        typer.echo(f"has_token: {'yes' if has_token else 'no'}")
        typer.echo(f"expires_at: {_value_or_attr(row, 'expires_at', '-')}")
        typer.echo(f"method: {_value_or_attr(row, 'method', '-')}")
        typer.echo(f"expired: {'yes' if _value_or_attr(row, 'expired', False) else 'no'}")


@auth_app.command("logout")
def auth_logout(
    provider: str | None = typer.Option(None, "--provider", help="Provider to clear cached credentials for."),
) -> None:
    cfg = load_config()
    provider_name = (provider or cfg.llm.provider).strip().lower()
    broker = build_oauth_broker(home=cfg.home)
    broker.logout(provider_name)
    typer.echo(f"Logged out: {provider_name}")


def _value_or_attr(payload: object, name: str, default: object) -> object:
    if isinstance(payload, dict):
        return payload.get(name, default)
    return getattr(payload, name, default)


def format_route_snapshot(snapshot: dict[str, str]) -> str:
    memory_tags = snapshot.get("memory_tags") or "-"
    prompt_prefix = snapshot.get("prompt_prefix") or "-"
    return "\n".join(
        [
            "Route",
            "=====",
            f"agent: {snapshot['agent']}",
            f"reason: {snapshot['reason']}",
            f"provider: {snapshot['provider']}",
            f"model: {snapshot['model']}",
            f"prompt_prefix: {prompt_prefix}",
            f"memory_tags: {memory_tags}",
        ]
    )


@app.command("route")
def route(
    prompt: str = typer.Option("Enumerate the target and stop after useful initial findings.", "--prompt", help="Prompt to preview."),
    target: str | None = typer.Option(None, "--target", help="Target to route."),
    agent: str | None = typer.Option(None, "--agent", help="Explicit requested agent."),
) -> None:
    """Preview which agent profile would be selected for a task."""
    cfg = load_config()
    resolution = AgentRouter(cfg.agents).resolve(
        prompt=prompt,
        target=target,
        requested_agent=agent,
        roe_profile=cfg.policy.roe_profile,
    )
    effective = apply_agent_profile(cfg, resolution)
    typer.echo(
        format_route_snapshot(
            {
                "agent": resolution.agent_name,
                "reason": resolution.reason,
                "provider": effective.llm.provider,
                "model": effective.llm.model,
                "prompt_prefix": resolution.profile.prompt_prefix or "",
                "memory_tags": ", ".join(resolution.profile.memory_tags),
            }
        )
    )


@app.command("memory")
def memory(
    target: str | None = typer.Option(None, "--target", help="Filter memory entries by target substring."),
    tag: str | None = typer.Option(None, "--tag", help="Filter memory entries by tag."),
    query: str | None = typer.Option(None, "--query", help="Filter memory entries by free-text query."),
    limit: int = typer.Option(10, "--limit", min=1, help="Maximum entries to display."),
) -> None:
    """List engagement-memory entries captured from prior sessions."""
    cfg = load_config()
    entries = list_engagement_memories(cfg.home, target=target, tag=tag, query=query, limit=limit)
    if not entries:
        typer.echo("No engagement memory entries matched.")
        return
    blocks = []
    for entry in entries:
        blocks.append(
            "\n".join(
                [
                    f"session_id: {entry.get('session_id', '-')}",
                    f"target: {entry.get('target') or '-'}",
                    f"agent: {entry.get('agent') or 'default'}",
                    f"status: {entry.get('status') or '-'}",
                    f"memory_tags: {', '.join(entry.get('memory_tags') or []) or '-'}",
                    f"summary: {entry.get('summary') or '-'}",
                ]
            )
        )
    typer.echo("\n\n".join(blocks))


def format_gateway_snapshot(mode: str, host: str, port: int, exposure: str, *, auth_enabled: bool = False, allow_cidrs: tuple[str, ...] = ()) -> str:
    allow_cidrs_label = ", ".join(allow_cidrs) or "-"
    lines = [
        "Gateway",
        "=======",
        f"mode: {mode}",
        f"host: {host}",
        f"port: {port}",
        f"bind: http://{host}:{port}",
        f"exposure: {exposure}",
        f"auth_enabled: {'yes' if auth_enabled else 'no'}",
        f"allow_cidrs: {allow_cidrs_label}",
    ]
    if str(mode).strip().lower() == "exposed" and not auth_enabled:
        lines.append("WARNING: exposed gateway mode is unauthenticated; enable bearer auth before remote use.")
    return "\n".join(lines)


def _gateway_connect_host(host: str) -> str:
    candidate = str(host or "").strip()
    if candidate in {"", "0.0.0.0", "::", "[::]"}:
        return "127.0.0.1"
    return candidate


def _gateway_base_url(host: str, port: int) -> str:
    return f"http://{_gateway_connect_host(host)}:{int(port)}"


def _gateway_json_request(url: str, *, method: str = "GET", payload: dict | None = None, headers: dict[str, str] | None = None) -> dict:
    data = None if payload is None else json.dumps(payload).encode("utf-8")
    request = urllib_request.Request(
        url,
        data=data,
        headers={"Content-Type": "application/json", **(headers or {})},
        method=method,
    )
    with urllib_request.urlopen(request, timeout=5) as response:
        body = response.read().decode("utf-8")
    parsed = json.loads(body or "{}")
    return parsed if isinstance(parsed, dict) else {}


def issue_gateway_pairing_code(*, base_url: str, operator_token: str | None = None, label: str | None = None) -> dict[str, str]:
    normalized_base = base_url.rstrip("/")
    headers: dict[str, str] = {}
    token_candidate = str(operator_token or "").strip()
    if token_candidate:
        try:
            login_payload = _gateway_json_request(
                normalized_base + "/api/auth/login",
                method="POST",
                payload={"operator_token": token_candidate},
            )
            session_token = str(login_payload.get("session_token", "")).strip()
            if session_token:
                headers["Authorization"] = f"Bearer {session_token}"
        except urllib_error.HTTPError as exc:
            if exc.code != 401:
                raise
    payload = _gateway_json_request(
        normalized_base + "/api/auth/pairing-codes",
        method="POST",
        payload={"label": str(label or "").strip()},
        headers=headers,
    )
    return {
        "gateway": normalized_base,
        "label": str(label or "").strip(),
        "code": str(payload.get("code", "")).strip(),
        "pair_endpoint": normalized_base + "/api/auth/pair",
    }


@app.command("gateway-config")
def gateway_config(
    mode: str | None = typer.Option(None, "--mode", help="Persist gateway mode: loopback, lan, or exposed."),
    host: str | None = typer.Option(None, "--host", help="Persist a custom HTTP bind address."),
    port: int | None = typer.Option(None, "--port", help="Persist the HTTP bind port."),
    auth_enabled: bool | None = typer.Option(None, "--auth-enabled/--auth-disabled", help="Require bearer auth in exposed mode."),
    operator_token: str | None = typer.Option(None, "--operator-token", help="Persist the local operator bootstrap token."),
    allow_cidr: list[str] | None = typer.Option(None, "--allow-cidr", help="CIDR allowlist entry for gateway clients."),
) -> None:
    """Show or update the persisted gateway bind/exposure settings."""
    cfg = load_config()
    if any(value is not None for value in (mode, host, port, auth_enabled, operator_token)) or allow_cidr:
        save_gateway_config(
            home=cfg.home,
            mode=mode,
            host=host,
            port=port,
            auth_enabled=auth_enabled,
            operator_token=operator_token,
            allow_cidrs=allow_cidr,
        )
    updated = load_config(cfg.home)
    typer.echo(
        format_gateway_snapshot(
            updated.gateway.mode,
            updated.gateway.host,
            updated.gateway.port,
            updated.gateway.exposure,
            auth_enabled=updated.gateway.auth_enabled,
            allow_cidrs=updated.gateway.allow_cidrs,
        )
    )


@app.command("tools")
def tools() -> None:
    """List model-visible registered tools."""
    for item in list_registered_tools(build_registry()):
        available = "available" if item["available"] else "unavailable"
        typer.echo(f"{item['name']}\t{item['toolset']}\t{item['risk']}\t{available}")


@app.command("sessions")
def sessions() -> None:
    """List stored runtime sessions."""
    cfg = load_config()
    db = StateDB(cfg.home / "state.db")
    for item in list_session_summaries(db):
        typer.echo(
            f"{item['id']}\t{item.get('status') or 'unknown'}\t{item.get('agent') or 'default'}\t{item.get('mode') or 'unknown'}\t{item.get('target') or '-'}"
        )


@app.command("report")
def report(
    session_id: int = typer.Argument(..., help="Session ID to render"),
    output_dir: str | None = typer.Option(None, "--output-dir", "-o", help="Directory for Markdown report"),
) -> None:
    """Render a stored session report from the StateDB."""
    cfg = load_config()
    db = StateDB(cfg.home / "state.db")
    path = write_session_report(db, session_id, output_dir or (cfg.home / "reports"))
    typer.echo(str(path))


@app.command("run")
def run(
    prompt: str = typer.Option(
        "Enumerate the target and stop after useful initial findings.",
        "--prompt",
        "-p",
        help="Task prompt for the autonomous runtime",
    ),
    target: str | None = typer.Option(None, "--target", "-t", help="Authorized target to include in the task"),
    agent: str | None = typer.Option(None, "--agent", help="Named agent profile to force for this run."),
    max_iterations: int = typer.Option(20, "--max-iterations", help="Maximum model/tool loop iterations"),
    approve_dangerous: bool = typer.Option(
        False,
        "--approve-dangerous",
        help="Allow dispatcher approval for exploit/post-exploitation tools. Use only inside authorized ROE.",
    ),
    yolo: bool = typer.Option(
        False,
        "--yolo",
        help="YOLO mode: automatically approve dangerous tools during this run. Use only inside authorized ROE.",
    ),
) -> None:
    """Run a task through the registry, policy, and runtime stack."""
    result = run_once(
        prompt=prompt,
        target=target,
        requested_agent=agent,
        max_iterations=max_iterations,
        approve_dangerous=approve_dangerous or yolo,
    )
    typer.echo(format_runtime_result(result))


@app.command("gateway")
def gateway(
    host: str | None = typer.Option(None, "--host", help="HTTP bind address for the control plane."),
    port: int | None = typer.Option(None, "--port", help="HTTP bind port for the control plane."),
    mode: str | None = typer.Option(None, "--mode", help="Bind preset: loopback, lan, or exposed."),
) -> None:
    """Run the lightweight HTTP gateway/control plane."""
    cfg = load_config()
    bind_mode = resolve_gateway_mode(mode or cfg.gateway.mode)
    bind_defaults = gateway_mode_defaults(bind_mode)
    bind_host = host or (bind_defaults["host"] if mode is not None else cfg.gateway.host)
    bind_port = port or cfg.gateway.port
    gateway_instance = AresGateway(config=cfg)
    server = start_gateway_server(gateway_instance, host=bind_host, port=bind_port, mode=bind_mode)
    typer.echo(format_gateway_snapshot(bind_mode, bind_host, bind_port, bind_defaults["exposure"], auth_enabled=cfg.gateway.auth_enabled, allow_cidrs=cfg.gateway.allow_cidrs))
    try:
        server.serve_forever()
    finally:
        server.server_close()


@app.command("gateway-pair")
def gateway_pair(
    label: str | None = typer.Option(None, "--label", help="Optional label to associate with the issued pairing code."),
    url: str | None = typer.Option(None, "--url", help="Gateway base URL override, such as http://127.0.0.1:18791."),
    operator_token: str | None = typer.Option(None, "--operator-token", help="Bootstrap operator token override for gateway login."),
) -> None:
    """Issue a one-time pairing code from a running gateway."""
    cfg = load_config()
    pairing = issue_gateway_pairing_code(
        base_url=url or _gateway_base_url(cfg.gateway.host, cfg.gateway.port),
        operator_token=operator_token if operator_token is not None else cfg.gateway.operator_token,
        label=label,
    )
    typer.echo(
        "\n".join(
            [
                "Gateway pairing",
                "===============",
                f"gateway: {pairing['gateway']}",
                f"label: {pairing['label'] or '-'}",
                f"code: {pairing['code']}",
                f"pair_endpoint: {pairing['pair_endpoint']}",
            ]
        )
    )


@app.command("tui")
def tui(
    refresh_interval: float = typer.Option(0.5, "--refresh-interval", min=0.1, help="Seconds between screen refreshes"),
    yolo: bool = typer.Option(False, "--yolo", help="Start the operator shell with YOLO mode enabled."),
) -> None:
    """Launch the interactive Ares terminal UI."""
    launch_tui(refresh_interval=refresh_interval, yolo_mode=yolo)


if __name__ == "__main__":
    app()

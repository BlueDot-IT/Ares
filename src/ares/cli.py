from __future__ import annotations

from pathlib import Path

import typer

from ares import APP_NAME, __version__
from ares.config.loader import (
    apply_llm_profile,
    gateway_mode_defaults,
    load_config,
    reset_llm_config,
    resolve_gateway_mode,
    save_gateway_config,
    save_llm_config,
    save_ui_config,
)
from ares.gateway import AresGateway, start_gateway_server
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
    reset: bool = typer.Option(False, "--reset", help="Reset persisted model settings to defaults."),
) -> None:
    """Show or update the persisted model configuration."""
    cfg = load_config()
    if reset:
        reset_llm_config(home=cfg.home)
    elif profile:
        apply_llm_profile(home=cfg.home, profile=profile)
    elif any(value is not None for value in (provider, model_name, base_url)) or fallback or clear_fallbacks:
        merged_fallbacks = [] if clear_fallbacks else [*cfg.llm.fallbacks, *(fallback or [])]
        save_llm_config(
            home=cfg.home,
            provider=provider,
            model=model_name,
            openai_base_url=base_url,
            fallbacks=merged_fallbacks if (fallback or clear_fallbacks) else None,
        )
    typer.echo(format_model_snapshot(build_model_snapshot(config=load_config(cfg.home))))


@app.command("theme")
def theme(
    name: str = typer.Argument(..., help="Theme name to persist for the TUI."),
) -> None:
    cfg = load_config()
    save_ui_config(home=cfg.home, theme=name)
    typer.echo(f"theme: {load_config(cfg.home).ui.theme}")


def format_gateway_snapshot(mode: str, host: str, port: int, exposure: str) -> str:
    return "\n".join(
        [
            "Gateway",
            "=======",
            f"mode: {mode}",
            f"host: {host}",
            f"port: {port}",
            f"bind: http://{host}:{port}",
            f"exposure: {exposure}",
        ]
    )


@app.command("gateway-config")
def gateway_config(
    mode: str | None = typer.Option(None, "--mode", help="Persist gateway mode: loopback, lan, or exposed."),
    host: str | None = typer.Option(None, "--host", help="Persist a custom HTTP bind address."),
    port: int | None = typer.Option(None, "--port", help="Persist the HTTP bind port."),
) -> None:
    """Show or update the persisted gateway bind/exposure settings."""
    cfg = load_config()
    if any(value is not None for value in (mode, host, port)):
        save_gateway_config(home=cfg.home, mode=mode, host=host, port=port)
    updated = load_config(cfg.home)
    typer.echo(
        format_gateway_snapshot(
            updated.gateway.mode,
            updated.gateway.host,
            updated.gateway.port,
            updated.gateway.exposure,
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
    server = start_gateway_server(gateway_instance, host=bind_host, port=bind_port)
    typer.echo(format_gateway_snapshot(bind_mode, bind_host, bind_port, bind_defaults["exposure"]))
    try:
        server.serve_forever()
    finally:
        server.server_close()


@app.command("tui")
def tui(
    refresh_interval: float = typer.Option(0.5, "--refresh-interval", min=0.1, help="Seconds between screen refreshes"),
    yolo: bool = typer.Option(False, "--yolo", help="Start the operator shell with YOLO mode enabled."),
) -> None:
    """Launch the interactive Ares terminal UI."""
    launch_tui(refresh_interval=refresh_interval, yolo_mode=yolo)


if __name__ == "__main__":
    app()

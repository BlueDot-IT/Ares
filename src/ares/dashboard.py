from __future__ import annotations

import webbrowser
from dataclasses import dataclass
from http.server import ThreadingHTTPServer

import typer

from ares.webui import build_web_ui_css, build_web_ui_html, build_web_ui_js


def build_dashboard_html(*, auth_required: bool = False) -> str:
    return (
        build_web_ui_html(auth_required=auth_required)
        .replace("<title>Ares Web UI</title>", "<title>Ares Dashboard</title>")
        .replace("<h1>Ares Web UI</h1>", "<h1>Ares Dashboard</h1>")
        .replace(
            "Hermes-style runtime, OpenClaw-style operator control, focused on pentesting.",
            "Browser operator surface backed by the Ares gateway API/control plane.",
        )
    )


def build_dashboard_css() -> str:
    return build_web_ui_css()


def build_dashboard_js(*, auth_required: bool = False) -> str:
    return build_web_ui_js(auth_required=auth_required)


@dataclass(frozen=True)
class DashboardLaunch:
    server: ThreadingHTTPServer
    mode: str
    host: str
    port: int
    exposure: str
    auth_enabled: bool
    allow_cidrs: tuple[str, ...]
    url: str


def dashboard_connect_host(host: str) -> str:
    candidate = str(host or "").strip()
    if candidate in {"", "0.0.0.0", "::", "[::]"}:
        return "127.0.0.1"
    return candidate


def dashboard_url(host: str, port: int) -> str:
    return f"http://{dashboard_connect_host(host)}:{int(port)}/"


def format_dashboard_snapshot(launch: DashboardLaunch) -> str:
    allow_cidrs_label = ", ".join(launch.allow_cidrs) or "-"
    return "\n".join(
        [
            "Dashboard",
            "=========",
            f"url: {launch.url}",
            f"gateway_mode: {launch.mode}",
            f"gateway_bind: http://{launch.host}:{launch.port}",
            f"gateway_exposure: {launch.exposure}",
            f"gateway_auth_enabled: {'yes' if launch.auth_enabled else 'no'}",
            f"gateway_allow_cidrs: {allow_cidrs_label}",
        ]
    )


def launch_dashboard(
    *,
    host: str | None = None,
    port: int | None = None,
    mode: str | None = None,
    open_browser: bool = False,
) -> DashboardLaunch:
    from ares.config.loader import gateway_mode_defaults, load_config, resolve_gateway_mode
    from ares.gateway import AresGateway, start_gateway_server

    cfg = load_config()
    bind_mode = resolve_gateway_mode(mode or cfg.gateway.mode)
    bind_defaults = gateway_mode_defaults(bind_mode)
    bind_host = host or (bind_defaults["host"] if mode is not None else cfg.gateway.host)
    bind_port = int(port or cfg.gateway.port)
    gateway_instance = AresGateway(config=cfg)
    server = start_gateway_server(gateway_instance, host=bind_host, port=bind_port, mode=bind_mode)
    url = dashboard_url(bind_host, bind_port)
    if open_browser:
        webbrowser.open(url)
    return DashboardLaunch(
        server=server,
        mode=bind_mode,
        host=bind_host,
        port=bind_port,
        exposure=str(bind_defaults["exposure"]),
        auth_enabled=cfg.gateway.auth_enabled,
        allow_cidrs=cfg.gateway.allow_cidrs,
        url=url,
    )


dashboard_app = typer.Typer(help="Launch the Ares browser dashboard.", invoke_without_command=True)


@dashboard_app.callback()
def main(
    host: str | None = typer.Option(None, "--host", help="HTTP bind address for the gateway used by the dashboard."),
    port: int | None = typer.Option(None, "--port", help="HTTP bind port for the gateway used by the dashboard."),
    mode: str | None = typer.Option(None, "--mode", help="Gateway bind preset: loopback, lan, or exposed."),
    open_browser: bool = typer.Option(True, "--open/--no-open", help="Open the dashboard URL in the default browser."),
) -> None:
    try:
        launch = launch_dashboard(
            host=host,
            port=port,
            mode=mode,
            open_browser=open_browser,
        )
    except OSError as exc:
        typer.echo(f"Could not start dashboard gateway: {exc}", err=True)
        raise typer.Exit(1) from None
    typer.echo(format_dashboard_snapshot(launch))
    try:
        launch.server.serve_forever()
    finally:
        launch.server.server_close()

from __future__ import annotations

import json
import os
import sys
import time
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Dict, Optional

import typer

# Allow running CLI without installing as a package yet.
# (Repo currently uses a loose "src" folder rather than a python package.)
SRC_DIR = Path(__file__).resolve().parent
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

from lib.orchestrator import Orchestrator  # noqa: E402
from lib.ghostmcp_runner import GhostMCPToolRunner  # noqa: E402

app = typer.Typer(help="Ares operator CLI")


@dataclass
class RunRecord:
    started_at: float
    config: Dict[str, Any]
    lines: list[str]


def _load_config(path: Path) -> Dict[str, Any]:
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise typer.BadParameter("config JSON must be an object")
    return data


def _config_schema() -> Dict[str, Any]:
    # Mirrors ui/config.py keys.
    return {
        "type": "object",
        "required": ["targets", "resolve_dns", "enable_ipv6", "mode"],
        "properties": {
            "targets": {"type": "string"},
            "resolve_dns": {"type": "boolean"},
            "enable_ipv6": {"type": "boolean"},
            "mode": {"type": "string", "enum": ["enum", "exploit"]},
        },
        "additionalProperties": True,
    }


@app.command("tools")
def tools_list(
    json_out: bool = typer.Option(False, "--json", help="Emit tool list as JSON"),
):
    """List available GhostMCP tools."""
    runner = GhostMCPToolRunner()
    tools = runner.tools
    if json_out:
        typer.echo(json.dumps({"count": len(tools), "tools": tools}, indent=2))
        raise typer.Exit(0)

    typer.echo(f"Tools: {len(tools)}")
    for name in sorted(tools.keys()):
        sig = tools[name].get("signature")
        if sig:
            typer.echo(f"- {name} {sig}")
        else:
            typer.echo(f"- {name}")


@app.command("config-validate")
def config_validate(path: Path = typer.Argument(..., exists=True, dir_okay=False)):
    """Validate a JSON config file."""
    from jsonschema import validate
    from jsonschema.exceptions import ValidationError

    cfg = _load_config(path)
    try:
        validate(instance=cfg, schema=_config_schema())
    except ValidationError as exc:
        raise typer.BadParameter(f"Invalid config: {exc.message}") from exc

    typer.echo("OK")


@app.command("scan")
def scan(
    targets: Optional[str] = typer.Option(None, "--targets", help="Semicolon-delimited targets"),
    mode: str = typer.Option("enum", "--mode", help="enum|exploit"),
    resolve_dns: bool = typer.Option(True, "--resolve-dns/--no-resolve-dns"),
    enable_ipv6: bool = typer.Option(False, "--ipv6/--no-ipv6"),
    config_path: Optional[Path] = typer.Option(None, "--config", exists=True, dir_okay=False, help="Load config from JSON"),
    out: Optional[Path] = typer.Option(None, "--out", dir_okay=False, help="Write run record to JSON"),
):
    """Run a scan using the orchestrator."""
    cfg: Dict[str, Any] = {
        "targets": targets or "",
        "resolve_dns": resolve_dns,
        "enable_ipv6": enable_ipv6,
        "mode": mode,
    }

    if config_path is not None:
        cfg.update(_load_config(config_path))

    # CLI args should override config file when explicitly passed.
    if targets is not None:
        cfg["targets"] = targets
    if mode is not None:
        cfg["mode"] = mode

    lines: list[str] = []

    def emit(line: Any):
        text = str(line)
        lines.append(text)
        typer.echo(text)

    orchestrator = Orchestrator()
    orchestrator.run_scan(cfg, emit)

    if out is not None:
        record = RunRecord(started_at=time.time(), config=cfg, lines=lines)
        out.write_text(json.dumps(asdict(record), indent=2), encoding="utf-8")
        typer.echo(f"[*] Wrote run record: {out}")


@app.command("replay")
def replay(path: Path = typer.Argument(..., exists=True, dir_okay=False)):
    """Replay a previously saved run record (from --out)."""
    data = json.loads(path.read_text(encoding="utf-8"))
    lines = data.get("lines")
    if not isinstance(lines, list):
        raise typer.BadParameter("run record missing 'lines' list")
    for line in lines:
        typer.echo(str(line))


@app.command("doctor")
def doctor():
    """Show environment + dependency info useful for debugging."""
    typer.echo(f"python: {sys.version.splitlines()[0]}")
    typer.echo(f"cwd: {os.getcwd()}")
    typer.echo(f"src_dir: {SRC_DIR}")

    runner = GhostMCPToolRunner()
    typer.echo(f"ghostmcp tools: {len(runner.tools)}")


if __name__ == "__main__":
    app()

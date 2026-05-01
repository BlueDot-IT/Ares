from __future__ import annotations

import os
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from lib.mcp_session import MCPProcessSession, MCPServerParameters


@dataclass(frozen=True)
class OnionClawToolSpec:
    name: str
    raw_name: str
    description: str = ""
    input_schema: dict[str, Any] | None = None


class OnionClawRunner:
    """Thin MCP client for the bounded OnionClaw/SICRY integration.

    Ares intentionally treats OnionClaw as an external Tor intelligence provider
    with Ares-owned env/db paths rather than a repo-local drop-in skill.
    """

    def __init__(
        self,
        *,
        repo_path: str,
        python_bin: str = sys.executable,
        env_path: str = "",
        db_path: str = "",
        extra_env: dict[str, str] | None = None,
    ) -> None:
        repo = Path(repo_path).expanduser()
        if not repo_path.strip():
            raise ValueError("OnionClaw repo_path is required when integration is enabled")
        if not repo.exists() or not repo.is_dir():
            raise FileNotFoundError(f"OnionClaw repo not found: {repo}")
        script_path = repo / "sicry.py"
        if not script_path.exists():
            raise FileNotFoundError(f"OnionClaw entrypoint missing: {script_path}")

        env = os.environ.copy()
        env.setdefault("PYTHONUNBUFFERED", "1")
        env.update(_load_env_file(env_path))
        if db_path:
            env["SICRY_DB_PATH"] = str(Path(db_path).expanduser())
        if extra_env:
            env.update({str(key): str(value) for key, value in extra_env.items() if str(key).strip()})

        self.session = MCPProcessSession(
            MCPServerParameters(
                command=[python_bin, str(script_path), "serve"],
                cwd=str(repo),
                env=env,
                client_name="ares-onionclaw-runner",
            )
        )
        self.session.initialize()
        self._tools = {
            str(tool.get("name")): OnionClawToolSpec(
                name=str(tool.get("name")),
                raw_name=str(tool.get("name")),
                description=str(tool.get("description") or ""),
                input_schema=dict(tool.get("inputSchema")) if isinstance(tool.get("inputSchema"), dict) else None,
            )
            for tool in self.session.list_tools()
        }

    @property
    def tools(self) -> dict[str, dict[str, Any]]:
        return {
            name: {
                "name": spec.name,
                "raw_name": spec.raw_name,
                "description": spec.description,
                "inputSchema": dict(spec.input_schema) if isinstance(spec.input_schema, dict) else None,
            }
            for name, spec in sorted(self._tools.items())
        }

    def call(self, tool: str, args: dict[str, Any]) -> dict[str, Any]:
        if tool not in self._tools:
            raise RuntimeError(f"Unknown OnionClaw tool: {tool}")
        result = self.session.call_tool(tool, args or {})
        if isinstance(result, dict):
            return result
        return {"result": result}

    def close(self) -> None:
        self.session.close()

    def __del__(self) -> None:  # pragma: no cover - best effort cleanup
        session = getattr(self, "session", None)
        if session is not None:
            try:
                session.close()
            except Exception:
                pass


def _load_env_file(path: str) -> dict[str, str]:
    candidate = str(path or "").strip()
    if not candidate:
        return {}
    env_path = Path(candidate).expanduser()
    if not env_path.exists():
        return {}
    loaded: dict[str, str] = {}
    try:
        lines = env_path.read_text(encoding="utf-8").splitlines()
    except OSError:
        return {}
    for raw_line in lines:
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        if line.startswith("export "):
            line = line[len("export ") :].strip()
        key, value = line.split("=", 1)
        key = key.strip()
        if not key:
            continue
        value = value.strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in {"'", '"'}:
            value = value[1:-1]
        loaded[key] = value
    return loaded

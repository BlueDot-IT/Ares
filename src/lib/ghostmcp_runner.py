from __future__ import annotations

import importlib
import inspect
import json
import os
import subprocess
import sys
import types
from dataclasses import dataclass
from pathlib import Path
from types import ModuleType
from typing import Any, Callable, Dict

from lib.mcp_session import MCPProcessSession, MCPServerParameters


@dataclass(frozen=True)
class ToolSpec:
    name: str
    fn: Callable[..., Any] | None
    signature: str
    source: str
    raw_name: str
    description: str = ""
    input_schema: dict[str, Any] | None = None


class GhostMCPToolRunner:
    """GhostMCP tool runner with optional external stdio transport.

    Transport modes:
      - auto: prefer an external stdio bridge, fall back to in-process loading.
      - external-stdio: require the external stdio bridge.
      - inproc: load tools inside the current process.
    """

    def __init__(self, transport: str = "auto") -> None:
        self.transport = transport
        self._client: _ExternalGhostMCPClient | None = None
        self._tools: dict[str, ToolSpec] = {}
        if transport == "auto":
            try:
                self._init_external()
                self.transport = "external-stdio"
                return
            except Exception:
                self._close_client()
                self._init_inproc()
                self.transport = "inproc"
                return
        if transport == "external-stdio":
            self._init_external()
            return
        if transport == "inproc":
            self._init_inproc()
            return
        raise ValueError(f"unknown GhostMCP transport: {transport}")

    @property
    def tools(self) -> dict[str, dict[str, Any]]:
        return {
            name: {
                "name": name,
                "raw_name": spec.raw_name,
                "signature": spec.signature,
                "source": spec.source,
                "description": spec.description,
                "inputSchema": dict(spec.input_schema) if isinstance(spec.input_schema, dict) else None,
            }
            for name, spec in sorted(self._tools.items())
        }

    def call(self, tool: str, args: Dict[str, Any]) -> Dict[str, Any]:
        if tool not in self._tools:
            raise RuntimeError(f"Unknown tool: {tool}")
        if self._client is not None:
            return self._client.call(tool, args)

        fn = self._tools[tool].fn
        if fn is None:
            raise RuntimeError(f"Tool is unavailable in current transport: {tool}")
        try:
            sig = inspect.signature(fn)
            params = list(sig.parameters.values())
            if len(params) == 1 and params[0].name in {"args", "_"}:
                result = fn(args or {})
            else:
                result = fn(**(args or {}))
            if isinstance(result, dict):
                return result
            return {"result": result}
        except Exception as exc:
            return {
                "error": "tool_exception",
                "exception": str(exc),
                "exception_type": type(exc).__name__,
            }

    def close(self) -> None:
        self._close_client()

    def _close_client(self) -> None:
        if self._client is not None:
            self._client.close()
            self._client = None

    def _init_external(self) -> None:
        client = _ExternalGhostMCPClient()
        metadata = client.handshake()
        self._client = client
        self._tools = {
            name: ToolSpec(
                name=name,
                fn=None,
                signature=str(tool_info.get("signature") or "(…)"),
                source=str(tool_info.get("source") or "external-stdio"),
                raw_name=str(tool_info.get("raw_name") or name),
                description=str(tool_info.get("description") or ""),
                input_schema=dict(tool_info.get("inputSchema")) if isinstance(tool_info.get("inputSchema"), dict) else None,
            )
            for name, tool_info in metadata.items()
        }

    def _init_inproc(self) -> None:
        self._tools = {}
        for module, source in _load_tool_modules():
            for raw_name, fn in _iter_module_tools(module):
                name = _normalize_tool_name(raw_name)
                if name in self._tools:
                    continue
                try:
                    signature = str(inspect.signature(fn))
                except Exception:
                    signature = "(…)"
                self._tools[name] = ToolSpec(
                    name=name,
                    fn=fn,
                    signature=signature,
                    source=source,
                    raw_name=raw_name,
                    description=(inspect.getdoc(fn) or "").strip(),
                    input_schema={"type": "object", "additionalProperties": True},
                )

    def __del__(self) -> None:  # pragma: no cover - best effort cleanup
        self._close_client()


class _ExternalGhostMCPClient:
    def __init__(self) -> None:
        self.session: MCPProcessSession | None = None

    def handshake(self) -> dict[str, dict[str, Any]]:
        if self.session is not None:
            raise RuntimeError("GhostMCP external bridge already started")
        env = os.environ.copy()
        src_root = Path(__file__).resolve().parents[1]
        env["PYTHONPATH"] = str(src_root) + (os.pathsep + env["PYTHONPATH"] if env.get("PYTHONPATH") else "")
        env["GHOSTMCP_CHILD"] = "1"
        session = MCPProcessSession(
            MCPServerParameters(
                command=[sys.executable, "-m", "lib.ghostmcp_stdio_bridge"],
                cwd=str(src_root.parent),
                env=env,
                client_name="ares-ghostmcp-runner",
            )
        )
        session.initialize()
        tools = session.list_tools()
        self.session = session
        return {
            str(tool.get("name")): {
                "name": str(tool.get("name")),
                "raw_name": str(tool.get("name")),
                "signature": "(…)" ,
                "source": "external-stdio",
                "description": str(tool.get("description") or ""),
                "inputSchema": dict(tool.get("inputSchema")) if isinstance(tool.get("inputSchema"), dict) else {"type": "object", "additionalProperties": True},
            }
            for tool in tools
            if isinstance(tool, dict) and tool.get("name")
        }

    def call(self, tool: str, args: dict[str, Any]) -> dict[str, Any]:
        if self.session is None:
            raise RuntimeError("GhostMCP bridge session is not active")
        return self.session.call_tool(tool, args)

    def close(self) -> None:
        if self.session is None:
            return
        self.session.close()
        self.session = None


def _normalize_tool_name(name: str) -> str:
    normalized = name
    if normalized.startswith("tool_"):
        normalized = normalized[len("tool_") :]
    if normalized.endswith("_tool"):
        normalized = normalized[: -len("_tool")]
    return normalized


def _load_tool_modules() -> list[tuple[ModuleType, str]]:
    modules: list[tuple[ModuleType, str]] = []

    installed = _import_installed_ghostmcp()
    if installed is not None:
        modules.append((installed, "ghostmcp"))
    else:
        vendored = _import_vendored_ghostmcp()
        if vendored is not None:
            modules.append((vendored, "vendor.ghostmcp"))

    fallback = importlib.import_module("lib.mcp_server")
    modules.append((fallback, "lib.mcp_server"))
    return modules


def _import_installed_ghostmcp() -> ModuleType | None:
    try:
        return importlib.import_module("ghostmcp.server")
    except Exception:
        _clear_partial_ghostmcp_imports()

    _ensure_fastmcp_available()
    try:
        return importlib.import_module("ghostmcp.server")
    except Exception:
        _clear_partial_ghostmcp_imports()
        return None


def _import_vendored_ghostmcp() -> ModuleType | None:
    vendor_root = Path(__file__).resolve().parents[2] / "vendor" / "ghostmcp"
    if not vendor_root.exists():
        return None
    if str(vendor_root) not in sys.path:
        sys.path.insert(0, str(vendor_root))
    _clear_partial_ghostmcp_imports()
    _ensure_fastmcp_available()
    try:
        return importlib.import_module("ghostmcp.server")
    except Exception:
        _clear_partial_ghostmcp_imports()
        return None


def _clear_partial_ghostmcp_imports() -> None:
    sys.modules.pop("ghostmcp.server", None)
    sys.modules.pop("ghostmcp", None)


def _ensure_fastmcp_available() -> None:
    try:
        importlib.import_module("mcp.server.fastmcp")
        return
    except Exception:
        pass

    mcp_module = sys.modules.setdefault("mcp", types.ModuleType("mcp"))
    server_module = sys.modules.setdefault("mcp.server", types.ModuleType("mcp.server"))
    fastmcp_module = types.ModuleType("mcp.server.fastmcp")

    class FakeFastMCP:
        def __init__(self, *_args, **_kwargs) -> None:
            self._registered: dict[str, Callable[..., Any]] = {}

        def tool(self):
            def decorator(fn: Callable[..., Any]) -> Callable[..., Any]:
                self._registered[fn.__name__] = fn
                return fn

            return decorator

        def run(self, *_args, **_kwargs) -> None:
            return None

        def streamable_http_app(self):
            return None

    fastmcp_module.FastMCP = FakeFastMCP
    setattr(mcp_module, "server", server_module)
    setattr(server_module, "fastmcp", fastmcp_module)
    sys.modules["mcp.server.fastmcp"] = fastmcp_module


def _iter_module_tools(module: ModuleType) -> list[tuple[str, Callable[..., Any]]]:
    registry = _registry_from_module(module)
    if registry is not None:
        return sorted(registry.items())

    tools: dict[str, Callable[..., Any]] = {}
    for name, value in vars(module).items():
        if not callable(value):
            continue
        if name.startswith("tool_") or (name.endswith("_tool") and not name.startswith("_")):
            tools[name] = value
    return sorted(tools.items())


def _registry_from_module(module: ModuleType) -> dict[str, Callable[..., Any]] | None:
    mcp_obj = getattr(module, "mcp", None)
    registered = getattr(mcp_obj, "_registered", None)
    if isinstance(registered, dict) and registered:
        return {name: fn for name, fn in registered.items() if callable(fn)}

    tool_manager = getattr(mcp_obj, "_tool_manager", None)
    managed_tools = getattr(tool_manager, "_tools", None)
    if isinstance(managed_tools, dict) and managed_tools:
        extracted: dict[str, Callable[..., Any]] = {}
        for name, tool in managed_tools.items():
            fn = getattr(tool, "fn", None)
            if callable(fn):
                extracted[name] = fn
        if extracted:
            return extracted

    for attr in ("TOOL_REGISTRY", "TOOLS", "TOOLS_REGISTRY"):
        candidate = getattr(module, attr, None)
        if isinstance(candidate, dict):
            return {name: fn for name, fn in candidate.items() if callable(fn)}
    return None

from __future__ import annotations

import json
import sys
from typing import Any

from lib.ghostmcp_runner import GhostMCPToolRunner
from lib.mcp_session import read_rpc_message, write_rpc_message


def _mapping_copy(value: Any) -> dict[str, Any] | None:
    return dict(value) if isinstance(value, dict) else None


def _tool_inventory(runner: GhostMCPToolRunner) -> list[dict[str, Any]]:
    return [
        {
            "name": name,
            "description": str(tool_info.get("description") or ""),
            "inputSchema": _mapping_copy(tool_info.get("inputSchema"))
            or {"type": "object", "additionalProperties": True},
            "security": _mapping_copy(tool_info.get("security")),
        }
        for name, tool_info in sorted(runner.tools.items())
    ]


def _send_response(request_id: Any, *, result: dict[str, Any] | None = None, error: str | None = None, code: int = -32000) -> None:
    payload: dict[str, Any] = {"jsonrpc": "2.0", "id": request_id}
    if error is not None:
        payload["error"] = {"code": code, "message": error}
    else:
        payload["result"] = result or {}
    write_rpc_message(sys.stdout.buffer, payload)


def _call_tool(runner: GhostMCPToolRunner, params: dict[str, Any]) -> dict[str, Any]:
    tool = str(params.get("name") or "")
    arguments = params.get("arguments")
    if not isinstance(arguments, dict):
        arguments = {}
    result = runner.call(tool, arguments)
    if not isinstance(result, dict):
        result = {"result": result}
    return {
        "content": [{"type": "text", "text": json.dumps(result, sort_keys=True)}],
        "structuredContent": result,
        "isError": False,
    }


def main() -> None:
    runner = GhostMCPToolRunner(transport="inproc")
    should_exit = False
    while not should_exit:
        try:
            request = read_rpc_message(sys.stdin.buffer)
        except EOFError:
            runner.close()
            return
        request_id = request.get("id")
        method = str(request.get("method") or "")
        params = request.get("params")
        if not isinstance(params, dict):
            params = {}
        if request_id is None:
            if method == "exit":
                runner.close()
                return
            continue
        try:
            if method == "initialize":
                result: dict[str, Any] = {
                    "protocolVersion": params.get("protocolVersion") or "2024-11-05",
                    "capabilities": {"tools": {}},
                    "serverInfo": {"name": "ares-ghostmcp-bridge", "version": "0.1.0b0"},
                }
            elif method == "tools/list":
                result = {"tools": _tool_inventory(runner)}
            elif method == "tools/call":
                result = _call_tool(runner, params)
            elif method in {"ping", "shutdown"}:
                result = {}
            else:
                raise ValueError(f"Unknown method: {method}")
            _send_response(request_id, result=result)
            if method == "shutdown":
                should_exit = True
        except Exception as exc:
            _send_response(request_id, error=str(exc), code=-32603)
    runner.close()


if __name__ == "__main__":
    main()

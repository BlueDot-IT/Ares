from __future__ import annotations

import json
import os
import subprocess
from dataclasses import dataclass, field
from typing import Any, BinaryIO


JSONRPC_VERSION = "2.0"
DEFAULT_PROTOCOL_VERSION = "2024-11-05"


@dataclass(frozen=True)
class MCPServerParameters:
    command: list[str]
    cwd: str | None = None
    env: dict[str, str] = field(default_factory=dict)
    client_name: str = "ares"
    client_version: str = "0.1.0b0"


def write_rpc_message(handle: BinaryIO, payload: dict[str, Any]) -> None:
    body = json.dumps(payload, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    header = f"Content-Length: {len(body)}\r\nContent-Type: application/json\r\n\r\n".encode("ascii")
    handle.write(header)
    handle.write(body)
    handle.flush()


def read_rpc_message(handle: BinaryIO) -> dict[str, Any]:
    headers: dict[str, str] = {}
    while True:
        line = handle.readline()
        if not line:
            raise EOFError("stdio stream closed while waiting for MCP headers")
        if line in {b"\r\n", b"\n"}:
            break
        key, _, value = line.decode("ascii", errors="replace").partition(":")
        headers[key.strip().lower()] = value.strip()
    length = int(headers.get("content-length", "0"))
    if length <= 0:
        raise RuntimeError(f"invalid MCP Content-Length header: {headers!r}")
    body = handle.read(length)
    if len(body) != length:
        raise EOFError("stdio stream closed before full MCP payload was read")
    payload = json.loads(body.decode("utf-8"))
    if not isinstance(payload, dict):
        raise RuntimeError(f"expected JSON object MCP payload, got: {type(payload).__name__}")
    return payload


class MCPProcessSession:
    def __init__(self, params: MCPServerParameters) -> None:
        self.params = params
        self.process: subprocess.Popen[bytes] | None = None
        self._request_id = 0
        self._initialized = False
        self._pending_notifications: list[dict[str, Any]] = []

    def __enter__(self) -> MCPProcessSession:
        self.start()
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        self.close()

    def start(self) -> None:
        if self.process is not None:
            return
        env = dict(os.environ)
        env.update(self.params.env)
        self.process = subprocess.Popen(
            self.params.command,
            cwd=self.params.cwd,
            env=env,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )

    def initialize(self) -> dict[str, Any]:
        if self._initialized:
            return {"protocolVersion": DEFAULT_PROTOCOL_VERSION}
        result = self.request(
            "initialize",
            {
                "protocolVersion": DEFAULT_PROTOCOL_VERSION,
                "capabilities": {},
                "clientInfo": {
                    "name": self.params.client_name,
                    "version": self.params.client_version,
                },
            },
        )
        self.notify("notifications/initialized", {})
        self._initialized = True
        return result

    def list_tools(self) -> list[dict[str, Any]]:
        result = self.request("tools/list", {})
        tools = result.get("tools", [])
        return [dict(tool) for tool in tools if isinstance(tool, dict)]

    def call_tool(self, name: str, arguments: dict[str, Any] | None = None) -> dict[str, Any]:
        result = self.request("tools/call", {"name": name, "arguments": arguments or {}})
        structured = result.get("structuredContent")
        if isinstance(structured, dict):
            return structured
        content = result.get("content")
        if isinstance(content, list):
            for item in content:
                if not isinstance(item, dict):
                    continue
                text = item.get("text")
                if isinstance(text, str):
                    try:
                        parsed = json.loads(text)
                    except json.JSONDecodeError:
                        return {"result": text}
                    if isinstance(parsed, dict):
                        return parsed
                    return {"result": parsed}
        return {"result": result}

    def request(self, method: str, params: dict[str, Any] | None = None) -> dict[str, Any]:
        self.start()
        self._request_id += 1
        request_id = self._request_id
        self._write(
            {
                "jsonrpc": JSONRPC_VERSION,
                "id": request_id,
                "method": method,
                "params": params or {},
            }
        )
        while True:
            message = self._read()
            if message.get("id") != request_id:
                self._pending_notifications.append(message)
                continue
            if "error" in message:
                error = message["error"]
                if isinstance(error, dict):
                    raise RuntimeError(str(error.get("message") or error))
                raise RuntimeError(str(error))
            result = message.get("result")
            if isinstance(result, dict):
                return result
            return {"result": result}

    def notify(self, method: str, params: dict[str, Any] | None = None) -> None:
        self.start()
        self._write(
            {
                "jsonrpc": JSONRPC_VERSION,
                "method": method,
                "params": params or {},
            }
        )

    def close(self) -> None:
        if self.process is None:
            return
        try:
            if self._initialized:
                try:
                    self.request("shutdown", {})
                except Exception:
                    pass
                try:
                    self.notify("exit", {})
                except Exception:
                    pass
        finally:
            for handle_name in ("stdin", "stdout", "stderr"):
                handle = getattr(self.process, handle_name, None)
                if handle is not None:
                    try:
                        handle.close()
                    except Exception:
                        pass
            if self.process.poll() is None:
                try:
                    self.process.terminate()
                    self.process.wait(timeout=2)
                except Exception:
                    try:
                        self.process.kill()
                    except Exception:
                        pass
            self.process = None
            self._initialized = False

    def _write(self, payload: dict[str, Any]) -> None:
        if self.process is None or self.process.stdin is None:
            raise RuntimeError("MCP session stdin is unavailable")
        write_rpc_message(self.process.stdin, payload)

    def _read(self) -> dict[str, Any]:
        if self.process is None or self.process.stdout is None:
            raise RuntimeError("MCP session stdout is unavailable")
        try:
            return read_rpc_message(self.process.stdout)
        except EOFError as exc:
            stderr = self._stderr_snapshot()
            raise RuntimeError(stderr or str(exc)) from exc

    def _stderr_snapshot(self) -> str:
        if self.process is None or self.process.stderr is None:
            return ""
        try:
            return self.process.stderr.read().decode("utf-8", errors="replace").strip()
        except Exception:
            return ""

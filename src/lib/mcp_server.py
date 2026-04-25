#!/usr/bin/env python3
import json
import sys
import subprocess
import os
import shutil
from typing import Any, Dict, List

# -------------------------------------------------
# Helpers
# -------------------------------------------------

def _apply_tor_wrapper(cmd: List[str]) -> List[str]:
    if os.getenv("ARES_FORCE_TOR") != "1":
        return cmd
    if not cmd or cmd[0] in {"torsocks", "proxychains4", "proxychains"}:
        return cmd
    if shutil.which("torsocks"):
        return ["torsocks"] + cmd
    if shutil.which("proxychains4"):
        return ["proxychains4"] + cmd
    if shutil.which("proxychains"):
        return ["proxychains"] + cmd
    return cmd


def _run(cmd: List[str], timeout: int = 60) -> Dict[str, Any]:
    def _to_text(blob: Any) -> str:
        if blob is None:
            return ""
        if isinstance(blob, str):
            return blob
        if isinstance(blob, (bytes, bytearray)):
            return blob.decode(errors="replace")
        # subprocess can return memoryview in some cases; normalize to bytes
        if isinstance(blob, memoryview):
            return bytes(blob).decode(errors="replace")
        try:
            return str(blob)
        except Exception:
            return ""

    try:
        cmd = _apply_tor_wrapper(cmd)
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        return {
            "cmd": cmd,
            "returncode": proc.returncode,
            "stdout": proc.stdout,
            "stderr": proc.stderr,
        }
    except subprocess.TimeoutExpired as exc:
        stdout = _to_text(exc.stdout)
        stderr = _to_text(exc.stderr)
        return {
            "cmd": cmd,
            "returncode": None,
            "stdout": stdout,
            "stderr": stderr,
            "error": "timeout",
            "timeout_seconds": timeout,
        }
    except FileNotFoundError as exc:
        return {
            "cmd": cmd,
            "returncode": None,
            "stdout": "",
            "stderr": "",
            "error": "command_not_found",
            "exception": str(exc),
        }
    except Exception as exc:
        return {
            "cmd": cmd,
            "returncode": None,
            "stdout": "",
            "stderr": "",
            "error": "exception",
            "exception": str(exc),
            "exception_type": type(exc).__name__,
        }

def _coerce_port(raw: Any, name: str = "port") -> int:
    try:
        port = int(raw)
    except (TypeError, ValueError):
        raise ValueError(f"{name} must be an integer")
    if port < 1 or port > 65535:
        raise ValueError(f"{name} must be between 1 and 65535")
    return port

def _coerce_timeout(raw: Any, default: int = 3) -> int:
    if raw is None:
        return default
    try:
        timeout = int(raw)
    except (TypeError, ValueError):
        raise ValueError("timeout must be an integer")
    if timeout < 1 or timeout > 120:
        raise ValueError("timeout must be between 1 and 120 seconds")
    return timeout

def tool_banner_grab(args: Dict[str, Any]) -> Dict[str, Any]:
    target = args.get("target")
    if not target or not isinstance(target, str):
        raise ValueError("target required")
    port = _coerce_port(args.get("port"))
    timeout = _coerce_timeout(args.get("timeout"), default=3)
    return _run(["nc", "-w", str(timeout), target, str(port)], timeout=timeout + 2)

def tool_mysql_enum(args: Dict[str, Any]) -> Dict[str, Any]:
    target = args.get("target")
    if not target or not isinstance(target, str):
        raise ValueError("target required")
    port = _coerce_port(args.get("port", 3306))
    cmd = [
        "nmap",
        "-p", str(port),
        "--script", "mysql-info",
        target
    ]
    return _run(cmd)

def tool_nmap_scripts(args: Dict[str, Any]) -> Dict[str, Any]:
    target = args.get("target")
    ports = args.get("ports")
    if not target or not isinstance(target, str):
        raise ValueError("target required")
    if not ports or not isinstance(ports, str):
        raise ValueError("ports required")
    cmd = [
        "nmap",
        "-sV",
        "--script", "default,safe",
        "-p", ports,
        target
    ]
    return _run(cmd)

def tool_tor_check(args: Dict[str, Any]) -> Dict[str, Any]:
    target = args.get("target", "127.0.0.1")
    if not isinstance(target, str) or not target:
        raise ValueError("target must be a non-empty string")
    port = _coerce_port(args.get("port", 9050))
    return _run(
        [
            "curl",
            "--socks5-hostname", f"{target}:{port}",
            "https://check.torproject.org/",
        ],
        timeout=5,
    )



# -------------------------------------------------
# Identity / environment
# -------------------------------------------------

def tool_whoami(_: Dict[str, Any]) -> Dict[str, Any]:
    import getpass
    return {"user": getpass.getuser()}

def tool_uname(_: Dict[str, Any]) -> Dict[str, Any]:
    return _run(["uname", "-a"])

# -------------------------------------------------
# Target helpers
# -------------------------------------------------

def tool_split_targets(args: Dict[str, Any]) -> Dict[str, Any]:
    """
    Split semicolon-delimited targets into a list.
    """
    raw = args.get("targets", "")
    targets = [t.strip() for t in raw.split(";") if t.strip()]
    return {"targets": targets}

# -------------------------------------------------
# Network discovery
# -------------------------------------------------

def tool_ping_sweep(args: Dict[str, Any]) -> Dict[str, Any]:
    """
    ICMP discovery via nmap -sn
    """
    target = args.get("target")
    ipv6 = bool(args.get("ipv6", False))
    if not target:
        raise ValueError("target required")

    cmd = ["nmap", "-sn"]
    if ipv6:
        cmd.append("-6")
    cmd.append(target)
    return _run(cmd)

# -------------------------------------------------
# Port & service enumeration
# -------------------------------------------------

def tool_nmap_basic(args: Dict[str, Any]) -> Dict[str, Any]:
    """
    TCP SYN scan with service detection
    """
    target = args.get("target")
    ports = args.get("ports", "1-1000")
    ipv6 = bool(args.get("ipv6", False))

    if not target:
        raise ValueError("target required")

    cmd = [
        "nmap",
        "-sS",
        "-sV",
        "-Pn",
    ]
    if ipv6:
        cmd.append("-6")
    cmd += [
        "-p", str(ports),
        target,
    ]
    return _run(cmd, timeout=300)

def tool_nmap_full(args: Dict[str, Any]) -> Dict[str, Any]:
    """
    Full TCP port scan (slow)
    """
    target = args.get("target")
    ipv6 = bool(args.get("ipv6", False))
    if not target:
        raise ValueError("target required")

    cmd = [
        "nmap",
        "-p-",
        "-T4",
        "-Pn",
    ]
    if ipv6:
        cmd.append("-6")
    cmd += [
        target,
    ]
    return _run(cmd, timeout=900)

# -------------------------------------------------
# Web enumeration
# -------------------------------------------------

def tool_http_probe(args: Dict[str, Any]) -> Dict[str, Any]:
    """
    Probe HTTP services using httpx
    """
    targets = args.get("targets")
    if not isinstance(targets, list):
        raise ValueError("targets must be a list")

    return _run([
        "httpx",
        "-silent",
        "-status-code",
        "-title",
    ] + targets)

def tool_dir_bruteforce(args: Dict[str, Any]) -> Dict[str, Any]:
    """
    Directory brute force using ffuf
    """
    url = args.get("url")
    wordlist = args.get("wordlist", "/usr/share/wordlists/dirb/common.txt")

    if not url:
        raise ValueError("url required")

    return _run([
        "ffuf",
        "-u", f"{url}/FUZZ",
        "-w", wordlist,
        "-mc", "200,204,301,302,307,401,403",
    ], timeout=600)

# -------------------------------------------------
# DNS / subdomain enumeration
# -------------------------------------------------

def tool_dns_lookup(args: Dict[str, Any]) -> Dict[str, Any]:
    domain = args.get("domain")
    if not domain:
        raise ValueError("domain required")

    return _run(["dig", domain, "+short"])

def tool_subdomain_enum(args: Dict[str, Any]) -> Dict[str, Any]:
    """
    Subdomain enumeration via subfinder
    """
    domain = args.get("domain")
    if not domain:
        raise ValueError("domain required")

    return _run([
        "subfinder",
        "-silent",
        "-d", domain,
    ])

# -------------------------------------------------
# Vulnerability discovery
# -------------------------------------------------

def tool_nuclei_scan(args: Dict[str, Any]) -> Dict[str, Any]:
    """
    Run nuclei vulnerability templates
    """
    target = args.get("target")
    if not target:
        raise ValueError("target required")

    return _run([
        "nuclei",
        "-u", target,
        "-severity", "low,medium,high,critical",
    ], timeout=600)

# -------------------------------------------------
# Exploitation (GATED)
# -------------------------------------------------

def tool_msf_search(args: Dict[str, Any]) -> Dict[str, Any]:
    """
    Search Metasploit modules
    """
    query = args.get("query")
    if not query:
        raise ValueError("query required")

    return _run([
        "msfconsole",
        "-q",
        "-x", f"search {query}; exit",
    ], timeout=120)

# -------------------------------------------------
# Registry
# -------------------------------------------------

TOOLS = {
    # Identity
    "whoami": tool_whoami,
    "uname": tool_uname,

    # Targets
    "split_targets": tool_split_targets,

    # Discovery
    "ping_sweep": tool_ping_sweep,

    # Enumeration
    "nmap_basic": tool_nmap_basic,
    "nmap_full": tool_nmap_full,
    "http_probe": tool_http_probe,
    "dir_bruteforce": tool_dir_bruteforce,

    # DNS
    "dns_lookup": tool_dns_lookup,
    "subdomain_enum": tool_subdomain_enum,

    # Vulnerabilities
    "nuclei_scan": tool_nuclei_scan,

    # Exploitation (gate by mode)
    "msf_search": tool_msf_search,

    "nmap_scripts": tool_nmap_scripts,
    "banner_grab": tool_banner_grab,
    "mysql_enum": tool_mysql_enum,
    "tor_check": tool_tor_check,
}

# -------------------------------------------------
# MCP loop
# -------------------------------------------------

from lib.mcp_session import read_rpc_message, write_rpc_message


def _tool_inventory() -> list[Dict[str, Any]]:
    return [
        {
            "name": name,
            "description": (fn.__doc__ or "").strip(),
            "inputSchema": {"type": "object", "additionalProperties": True},
        }
        for name, fn in sorted(TOOLS.items())
    ]


def _result_payload(result: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "content": [{"type": "text", "text": json.dumps(result, sort_keys=True)}],
        "structuredContent": result,
        "isError": False,
    }


def _send_response(request_id: Any, *, result: Dict[str, Any] | None = None, error: str | None = None, code: int = -32000) -> None:
    payload: Dict[str, Any] = {"jsonrpc": "2.0", "id": request_id}
    if error is not None:
        payload["error"] = {"code": code, "message": error}
    else:
        payload["result"] = result or {}
    write_rpc_message(sys.stdout.buffer, payload)


def _handle_request(method: str, params: Dict[str, Any]) -> Dict[str, Any]:
    if method == "initialize":
        return {
            "protocolVersion": params.get("protocolVersion") or "2024-11-05",
            "capabilities": {"tools": {}},
            "serverInfo": {"name": "ares-lib-mcp", "version": "0.1.0"},
        }
    if method == "ping":
        return {}
    if method == "tools/list":
        return {"tools": _tool_inventory()}
    if method == "tools/call":
        tool = str(params.get("name") or "")
        arguments = params.get("arguments")
        if not isinstance(arguments, dict):
            arguments = {}
        if tool not in TOOLS:
            raise ValueError(f"Unknown tool: {tool}")
        result = TOOLS[tool](arguments)
        if not isinstance(result, dict):
            result = {"result": result}
        return _result_payload(result)
    if method == "shutdown":
        return {}
    raise ValueError(f"Unknown method: {method}")


def main() -> None:
    should_exit = False
    while not should_exit:
        try:
            request = read_rpc_message(sys.stdin.buffer)
        except EOFError:
            return
        request_id = request.get("id")
        method = str(request.get("method") or "")
        params = request.get("params")
        if not isinstance(params, dict):
            params = {}
        if request_id is None:
            if method in {"notifications/initialized", "initialized"}:
                continue
            if method == "exit":
                return
            continue
        try:
            result = _handle_request(method, params)
            _send_response(request_id, result=result)
            if method == "shutdown":
                should_exit = True
        except Exception as exc:
            _send_response(request_id, error=str(exc), code=-32603)


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
import json
import ipaddress
import re
import sys
import subprocess
import os
import shutil
from typing import Any, Dict, List

# -------------------------------------------------
# Helpers
# -------------------------------------------------

def _apply_tor_wrapper(cmd: List[str]) -> List[str]:
    if os.getenv("FORCE_TOR") != "1":
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


def _first_text(args: Dict[str, Any], *names: str) -> str | None:
    for name in names:
        value = args.get(name)
        if isinstance(value, str):
            stripped = value.strip()
            if stripped:
                return stripped
    return None


def _coerce_targets(raw: Any) -> list[str]:
    if raw is None:
        return []
    if isinstance(raw, str):
        return [part.strip() for part in re.split(r"[;,\s]+", raw) if part.strip()]
    if isinstance(raw, list):
        targets: list[str] = []
        for item in raw:
            if not isinstance(item, str) or not item.strip():
                raise ValueError("targets must be a list of strings")
            targets.append(item.strip())
        return targets
    raise ValueError("targets must be a list or string")


def _coerce_ports(raw: Any, default: str = "1-1000") -> str:
    if raw is None:
        return default
    if isinstance(raw, list):
        return ",".join(str(_coerce_port(item)) for item in raw)
    if isinstance(raw, int):
        return str(raw)
    if isinstance(raw, str):
        stripped = raw.strip()
        return stripped or default
    return str(raw)


def _coerce_hostish(raw: Any) -> str | None:
    value = _first_text({"value": raw}, "value")
    if not value:
        return None
    if "://" in value:
        from urllib.parse import urlparse

        parsed = urlparse(value)
        if parsed.hostname:
            return parsed.hostname.strip().rstrip(".")
    return value.strip().rstrip(".")


def _looks_like_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def _reverse_dns_name(ip: str) -> str | None:
    result = _run(["dig", "-x", ip, "+short"], timeout=10)
    if result.get("returncode") not in {0, None}:
        return None
    stdout = str(result.get("stdout") or "").strip().splitlines()
    if not stdout:
        return None
    hostname = stdout[0].strip().rstrip(".")
    return hostname or None


def _parent_domain(name: str) -> str | None:
    labels = [label for label in name.strip(".").split(".") if label]
    if len(labels) < 2:
        return None
    if len(labels) == 2:
        return ".".join(labels)
    return ".".join(labels[1:])


def _as_http_urls(value: str) -> list[str]:
    if value.startswith(("http://", "https://")):
        return [value]
    return [f"http://{value}", f"https://{value}"]


def tool_banner_grab(args: Dict[str, Any]) -> Dict[str, Any]:
    target = args.get("target")
    if not target or not isinstance(target, str):
        raise ValueError("target required")
    port = _coerce_port(args.get("port", 443))
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
    targets = _coerce_targets(args.get("targets")) or _coerce_targets(args.get("target"))
    ipv6 = bool(args.get("ipv6", False))
    if not targets:
        raise ValueError("target required")

    cmd = ["nmap", "-sn"]
    if ipv6:
        cmd.append("-6")
    cmd.extend(targets)
    return _run(cmd)

# -------------------------------------------------
# Port & service enumeration
# -------------------------------------------------

def tool_nmap_basic(args: Dict[str, Any]) -> Dict[str, Any]:
    """
    TCP SYN scan with service detection
    """
    targets = _coerce_targets(args.get("targets")) or _coerce_targets(args.get("target"))
    ports = _coerce_ports(args.get("ports"), default="1-1000")
    ipv6 = bool(args.get("ipv6", False))

    if not targets:
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
        "-p", ports,
    ]
    cmd.extend(targets)
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
    raw_targets = args.get("targets")
    if raw_targets is None:
        raw_targets = args.get("target") or args.get("url") or args.get("urls")
    targets = _coerce_targets(raw_targets)
    if not targets:
        raise ValueError("target required")

    urls: list[str] = []
    for target in targets:
        urls.extend(_as_http_urls(target))

    return _run([
        "httpx",
        "-silent",
        "-status-code",
        "-title",
    ] + urls)

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
    domain = _coerce_hostish(args.get("domain") or args.get("target") or args.get("host") or args.get("ip"))
    if not domain:
        raise ValueError("domain required")

    if _looks_like_ip(domain):
        return _run(["dig", "-x", domain, "+short"])
    return _run(["dig", domain, "+short"])

def tool_subdomain_enum(args: Dict[str, Any]) -> Dict[str, Any]:
    """
    Subdomain enumeration via subfinder
    """
    domain = _coerce_hostish(args.get("domain") or args.get("target") or args.get("host"))
    if not domain:
        raise ValueError("domain required")

    if _looks_like_ip(domain):
        reverse_name = _reverse_dns_name(domain)
        if reverse_name:
            parent = _parent_domain(reverse_name)
            if parent:
                domain = parent
            else:
                domain = reverse_name

    subfinder = shutil.which("subfinder")
    if subfinder:
        return _run([
            subfinder,
            "-silent",
            "-d", domain,
        ])

    amass = shutil.which("amass")
    if amass:
        return _run([
            amass,
            "enum",
            "-passive",
            "-d", domain,
        ])

    return {
        "cmd": ["subfinder", "-silent", "-d", domain],
        "returncode": None,
        "stdout": "",
        "stderr": "",
        "error": "command_not_found",
        "missing": ["subfinder", "amass"],
        "exception": "subfinder/amass not installed",
    }

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


TOOL_INPUT_SCHEMAS: Dict[str, Dict[str, Any]] = {
    "whoami": {"type": "object", "additionalProperties": False},
    "uname": {"type": "object", "additionalProperties": False},
    "split_targets": {
        "type": "object",
        "properties": {"targets": {"type": "string", "description": "Semicolon-delimited targets"}},
        "required": ["targets"],
        "additionalProperties": False,
    },
    "ping_sweep": {
        "type": "object",
        "properties": {
            "target": {"type": "string", "description": "Single target host/IP"},
            "targets": {"type": "array", "items": {"type": "string"}, "description": "One or more targets"},
            "ipv6": {"type": "boolean"},
        },
        "required": ["target"],
        "additionalProperties": True,
    },
    "nmap_basic": {
        "type": "object",
        "properties": {
            "target": {"type": "string", "description": "Single target host/IP"},
            "targets": {"type": "array", "items": {"type": "string"}, "description": "One or more targets"},
            "ports": {"type": ["string", "integer"], "description": "Ports or port range"},
            "ipv6": {"type": "boolean"},
        },
        "required": ["target"],
        "additionalProperties": True,
    },
    "nmap_full": {
        "type": "object",
        "properties": {
            "target": {"type": "string", "description": "Single target host/IP"},
            "ipv6": {"type": "boolean"},
        },
        "required": ["target"],
        "additionalProperties": True,
    },
    "http_probe": {
        "type": "object",
        "properties": {
            "target": {"type": "string", "description": "Host, IP, or URL"},
            "targets": {"type": "array", "items": {"type": "string"}, "description": "One or more hosts, IPs, or URLs"},
            "url": {"type": "string", "description": "Single URL"},
            "urls": {"type": "array", "items": {"type": "string"}, "description": "One or more URLs"},
        },
        "required": ["target"],
        "additionalProperties": True,
    },
    "dir_bruteforce": {
        "type": "object",
        "properties": {"url": {"type": "string"}, "wordlist": {"type": "string"}},
        "required": ["url"],
        "additionalProperties": True,
    },
    "dns_lookup": {
        "type": "object",
        "properties": {
            "domain": {"type": "string", "description": "Domain or hostname"},
            "target": {"type": "string", "description": "Alias for domain"},
            "host": {"type": "string"},
            "ip": {"type": "string"},
        },
        "required": ["domain"],
        "additionalProperties": True,
    },
    "subdomain_enum": {
        "type": "object",
        "properties": {
            "domain": {"type": "string", "description": "Base domain or hostname"},
            "target": {"type": "string", "description": "Alias for domain"},
            "host": {"type": "string"},
        },
        "required": ["domain"],
        "additionalProperties": True,
    },
    "nuclei_scan": {
        "type": "object",
        "properties": {"target": {"type": "string"}},
        "required": ["target"],
        "additionalProperties": True,
    },
    "msf_search": {
        "type": "object",
        "properties": {"query": {"type": "string"}},
        "required": ["query"],
        "additionalProperties": True,
    },
    "nmap_scripts": {
        "type": "object",
        "properties": {"target": {"type": "string"}, "ports": {"type": ["string", "integer"]}},
        "required": ["target", "ports"],
        "additionalProperties": True,
    },
    "banner_grab": {
        "type": "object",
        "properties": {"target": {"type": "string"}, "port": {"type": "integer"}, "timeout": {"type": "integer"}},
        "required": ["target"],
        "additionalProperties": True,
    },
    "mysql_enum": {
        "type": "object",
        "properties": {"target": {"type": "string"}, "port": {"type": "integer"}},
        "required": ["target"],
        "additionalProperties": True,
    },
    "tor_check": {
        "type": "object",
        "properties": {"target": {"type": "string"}, "port": {"type": "integer"}},
        "additionalProperties": True,
    },
}


def _tool_inventory() -> list[Dict[str, Any]]:
    return [
        {
            "name": name,
            "description": (fn.__doc__ or "").strip(),
            "inputSchema": TOOL_INPUT_SCHEMAS.get(name, {"type": "object", "additionalProperties": True}),
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
            "serverInfo": {"name": "ares-lib-mcp", "version": "0.1.0b0"},
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

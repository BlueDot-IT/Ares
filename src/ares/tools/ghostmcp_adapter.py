from __future__ import annotations

import re
from typing import Any
from threading import Lock

from lib.ghostmcp_runner import GhostMCPToolRunner

from .registry import ToolRegistry, registry as default_registry


_DEFAULT_RUNNERS: dict[bool | None, GhostMCPToolRunner] = {}
_DEFAULT_RUNNERS_LOCK = Lock()


def get_default_ghostmcp_runner(allow_private_only: bool | None = None) -> GhostMCPToolRunner:
    with _DEFAULT_RUNNERS_LOCK:
        runner = _DEFAULT_RUNNERS.get(allow_private_only)
        if runner is None:
            runner = GhostMCPToolRunner(allow_private_only=allow_private_only)
            _DEFAULT_RUNNERS[allow_private_only] = runner
        return runner


def reset_default_ghostmcp_runner_cache() -> None:
    with _DEFAULT_RUNNERS_LOCK:
        for runner in _DEFAULT_RUNNERS.values():
            try:
                runner.close()
            except Exception:
                pass
        _DEFAULT_RUNNERS.clear()


PASSIVE_TOOL_HINTS = (
    "whoami",
    "uname",
    "split_targets",
    "dns_lookup",
    "reverse_dns",
    "whois",
    "security_txt",
    "ioc_extract",
    "url_risk_score",
    "subdomain_candidates",
    "common_web_paths",
    "toolchain_status",
    "metrics",
    "runtime_probe",
    "server_health",
    "amass_passive",
)
ACTIVE_TOOL_HINTS = (
    "http_probe",
    "tls_certificate",
    "tcp_port_scan",
    "ping_sweep",
    "nmap_basic",
    "whatweb",
    "sslscan",
    "wafw00f",
    "tor_check",
    "banner_grab",
)
INTRUSIVE_TOOL_HINTS = (
    "nmap_full",
    "nmap_service_scan",
    "nmap_scripts",
    "nikto",
    "gobuster",
    "dir_bruteforce",
    "nuclei",
    "mysql_enum",
)
EXPLOIT_TOOL_HINTS = ("msf", "metasploit", "exploit", "searchsploit")


def register_ghostmcp_tools(
    registry: ToolRegistry = default_registry,
    *,
    toolset: str = "ghostmcp",
    runner: GhostMCPToolRunner | None = None,
    policy_allow_private_only: bool | None = None,
) -> int:
    """Discover GhostMCP tools and register them into a ToolRegistry.

    The default runner now prefers a persistent external stdio bridge and falls
    back to the in-process GhostMCP loader when needed.
    """
    if runner is None:
        runner = get_default_ghostmcp_runner(policy_allow_private_only)
    count = 0
    for name, tool_info in sorted(runner.tools.items()):
        schema = _schema_for_tool(name, tool_info)
        risk = risk_for_tool_name(name)
        registry.register(
            name=name,
            toolset=toolset,
            risk=risk,
            schema=schema,
            handler=lambda args, _tool=name, **_: runner.call(_tool, args),
            check_fn=lambda: True,
            requires=(),
            description=schema.get("description", name),
        )
        count += 1
    return count


def risk_for_tool_name(name: str) -> str:
    normalized = name.lower()
    if any(hint in normalized for hint in EXPLOIT_TOOL_HINTS):
        return "exploit"
    if any(hint in normalized for hint in INTRUSIVE_TOOL_HINTS):
        return "intrusive"
    if any(hint in normalized for hint in ACTIVE_TOOL_HINTS):
        return "active"
    if any(hint in normalized for hint in PASSIVE_TOOL_HINTS):
        return "passive"
    if normalized.endswith("_raw_tool") or normalized.endswith("_raw"):
        return "intrusive"
    return "active"


def _schema_for_tool(name: str, tool_info: dict[str, Any]) -> dict[str, Any]:
    description = tool_info.get("description") or tool_info.get("doc") or name
    input_schema = tool_info.get("inputSchema") or tool_info.get("input_schema")
    if isinstance(input_schema, dict) and input_schema.get("type") == "object":
        return {
            "name": name,
            "description": str(description).strip() or name,
            "parameters": dict(input_schema),
        }
    signature = tool_info.get("signature") or ""
    properties: dict[str, dict[str, str]] = {}
    required: list[str] = []
    for param in _params_from_signature(signature):
        if param in {"args", "_", "engagement_id", "engagement_mode", "auth_token"}:
            continue
        properties[param] = {"type": "string"}
        required.append(param)
    return {
        "name": name,
        "description": str(description).strip() or name,
        "parameters": {
            "type": "object",
            "properties": properties,
            "required": required,
        },
    }


def _params_from_signature(signature: str) -> list[str]:
    if not signature.startswith("(") or ")" not in signature:
        return []
    params_blob = signature[1 : signature.rfind(")")]
    params: list[str] = []
    for raw in params_blob.split(","):
        token = raw.strip()
        if not token:
            continue
        match = re.match(r"([A-Za-z_][A-Za-z0-9_]*)", token)
        if match:
            params.append(match.group(1))
    return params

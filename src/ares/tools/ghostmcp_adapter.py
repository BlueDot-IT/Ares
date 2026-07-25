from __future__ import annotations

import re
from pathlib import Path
from threading import Lock
from typing import Any

from lib.ghostmcp_runner import GhostMCPToolRunner

from ares.policy.risk import RISK_ORDER

from .registry import ToolRegistry, registry as default_registry


_DEFAULT_RUNNERS: dict[tuple[bool | None, str | None], GhostMCPToolRunner] = {}
_DEFAULT_RUNNERS_LOCK = Lock()


def get_default_ghostmcp_runner(
    allow_private_only: bool | None = None,
    engagement_policy_file: str | Path | None = None,
) -> GhostMCPToolRunner:
    resolved_policy = (
        str(Path(engagement_policy_file).expanduser().resolve())
        if engagement_policy_file is not None
        else None
    )
    cache_key = (allow_private_only, resolved_policy)
    with _DEFAULT_RUNNERS_LOCK:
        runner = _DEFAULT_RUNNERS.get(cache_key)
        if runner is None:
            runner_kwargs: dict[str, Any] = {
                "allow_private_only": allow_private_only,
            }
            if resolved_policy is not None:
                runner_kwargs["engagement_policy_file"] = resolved_policy
            runner = GhostMCPToolRunner(**runner_kwargs)
            _DEFAULT_RUNNERS[cache_key] = runner
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
POST_EXPLOITATION_TOOL_HINTS = (
    "bloodhound", "crackmapexec", "evil_winrm", "impacket_psexec",
    "impacket_secretsdump", "impacket_wmiexec", "netexec", "responder", "mitm6",
)
EXPLOIT_TOOL_HINTS = (
    "msf", "metasploit", "exploit", "searchsploit", "commix", "hydra",
    "medusa", "patator", "sqlmap", "smbclient", "smbmap", "rpcclient",
    "hashcat", "john",
)


def register_ghostmcp_tools(
    registry: ToolRegistry = default_registry,
    *,
    toolset: str = "ghostmcp",
    runner: GhostMCPToolRunner | None = None,
    policy_allow_private_only: bool | None = None,
    engagement_policy_file: str | Path | None = None,
) -> int:
    """Discover GhostMCP tools and register them into a ToolRegistry.

    The default runner now prefers a persistent external stdio bridge and falls
    back to the in-process GhostMCP loader when needed.
    """
    if runner is None:
        runner = get_default_ghostmcp_runner(
            policy_allow_private_only,
            engagement_policy_file,
        )
    count = 0
    for name, tool_info in sorted(runner.tools.items()):
        schema = _schema_for_tool(name, tool_info)
        risk = risk_for_tool(name, tool_info)
        security = tool_info.get("security")
        available = (
            bool(security.get("available", False))
            if isinstance(security, dict)
            else True
        )
        registry.register(
            name=name,
            toolset=toolset,
            risk=risk,
            schema=schema,
            handler=(
                lambda args, _tool=name, _security=security, **context:
                _call_ghostmcp(
                    runner,
                    _tool,
                    args,
                    security=_security,
                    engagement_id=context.get("engagement_id"),
                )
            ),
            check_fn=lambda _available=available: _available,
            requires=(),
            description=schema.get("description", name),
        )
        count += 1
    return count


def _call_ghostmcp(
    runner: GhostMCPToolRunner,
    name: str,
    args: dict[str, Any],
    *,
    security: dict[str, Any] | None = None,
    engagement_id: str | None = None,
) -> Any:
    effective_args = dict(args)
    if isinstance(security, dict):
        if not engagement_id:
            raise PermissionError(
                f"GhostMCP tool {name!r} requires an Ares engagement identifier"
            )
        effective_args["engagement_id"] = engagement_id
        effective_args["engagement_mode"] = str(security.get("risk") or "passive")
        effective_args.pop("auth_token", None)
    result = runner.call(name, effective_args)
    if isinstance(result, dict) and result.get("error"):
        detail = result.get("exception") or result.get("message") or result["error"]
        raise RuntimeError(f"GhostMCP tool {name!r} failed: {detail}")
    return result


def risk_for_tool_name(name: str) -> str:
    normalized = name.lower()
    if any(hint in normalized for hint in POST_EXPLOITATION_TOOL_HINTS):
        return "post-exploitation"
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


def risk_for_tool(name: str, tool_info: dict[str, Any]) -> str:
    """Map the versioned GhostMCP contract into Ares' richer risk model."""
    heuristic = risk_for_tool_name(name)
    security = tool_info.get("security")
    if not isinstance(security, dict):
        return heuristic
    if security.get("manifest_schema") != "1.0":
        raise RuntimeError(f"Unsupported GhostMCP manifest for tool {name!r}")
    manifest_risk = str(security.get("risk") or "")
    base = {
        "passive": "passive",
        "active": "active",
        "intrusive": "intrusive",
    }.get(manifest_risk)
    if base is None:
        raise RuntimeError(f"Invalid GhostMCP risk metadata for tool {name!r}")
    capabilities = {
        str(item) for item in security.get("capabilities", ())
    }
    if "remote_execution" in capabilities:
        base = "post-exploitation"
    elif capabilities & {"credential_access", "collection"}:
        base = "exploit"
    elif "raw_execution" in capabilities:
        base = "intrusive"
    return max((base, heuristic), key=lambda item: RISK_ORDER[item])


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

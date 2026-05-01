from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from ares.config.loader import OnionClawConfig
from lib.onionclaw_runner import OnionClawRunner

from .registry import ToolRegistry, registry as default_registry


@dataclass(frozen=True)
class OnionClawBoundedTool:
    name: str
    raw_name: str
    risk: str
    description: str


BOUNDED_ONIONCLAW_TOOLS: tuple[OnionClawBoundedTool, ...] = (
    OnionClawBoundedTool("onionclaw_check_tor", "sicry_check_tor", "passive", "Verify Tor is reachable before a dark-web operation."),
    OnionClawBoundedTool("onionclaw_renew_identity", "sicry_renew_identity", "passive", "Rotate the Tor circuit for a fresh identity."),
    OnionClawBoundedTool("onionclaw_check_engines", "sicry_check_engines", "passive", "Check dark-web search engine availability and reliability."),
    OnionClawBoundedTool("onionclaw_search", "sicry_search", "passive", "Search bounded .onion intelligence sources through Tor."),
    OnionClawBoundedTool("onionclaw_fetch", "sicry_fetch", "active", "Fetch a specific .onion or clearnet URL through Tor."),
    OnionClawBoundedTool("onionclaw_analyze_nollm", "sicry_analyze_nollm", "passive", "Offline keyword and entity extraction without external LLM access."),
    OnionClawBoundedTool("onionclaw_extract_keywords", "sicry_extract_keywords", "passive", "Extract weighted keywords from collected content."),
    OnionClawBoundedTool("onionclaw_to_stix", "sicry_to_stix", "passive", "Convert bounded results into STIX 2.1 JSON."),
    OnionClawBoundedTool("onionclaw_to_csv", "sicry_to_csv", "passive", "Convert bounded results into CSV."),
)


def register_onionclaw_tools(
    registry: ToolRegistry = default_registry,
    *,
    config: OnionClawConfig | None = None,
    toolset: str = "onionclaw",
    runner: Any | None = None,
) -> int:
    config = config or OnionClawConfig()
    if not config.enabled:
        return 0

    runner_instance = runner
    availability_error = ""
    inventory: dict[str, dict[str, Any]] = {}
    if runner_instance is None:
        try:
            runner_instance = OnionClawRunner(
                repo_path=config.repo_path,
                python_bin=config.python_bin,
                env_path=config.env_path,
                db_path=config.db_path,
            )
        except Exception as exc:
            availability_error = str(exc)
    if runner_instance is not None:
        inventory = dict(getattr(runner_instance, "tools", {}) or {})

    count = 0
    for spec in BOUNDED_ONIONCLAW_TOOLS:
        tool_info = inventory.get(spec.raw_name, {})
        reason = availability_error or ("" if tool_info else f"missing OnionClaw MCP tool: {spec.raw_name}")
        schema = _schema_for_tool(spec, tool_info)
        registry.register(
            name=spec.name,
            toolset=toolset,
            risk=spec.risk,
            schema=schema,
            handler=lambda args, _runner=runner_instance, _raw_name=spec.raw_name, **_: _dispatch(_runner, _raw_name, args),
            check_fn=_build_check_fn(reason=reason),
            requires=("tor", "onionclaw"),
            description=schema.get("description", spec.description),
        )
        count += 1
    return count


def _schema_for_tool(spec: OnionClawBoundedTool, tool_info: dict[str, Any]) -> dict[str, Any]:
    input_schema = tool_info.get("inputSchema") if isinstance(tool_info, dict) else None
    description = str(tool_info.get("description") or spec.description) if isinstance(tool_info, dict) else spec.description
    if isinstance(input_schema, dict) and input_schema.get("type") == "object":
        parameters = dict(input_schema)
    else:
        parameters = {"type": "object", "properties": {}, "required": []}
    return {
        "name": spec.name,
        "description": description,
        "parameters": parameters,
    }


def _dispatch(runner: Any | None, raw_name: str, args: dict[str, Any]) -> dict[str, Any]:
    if runner is None:
        raise RuntimeError(f"OnionClaw tool unavailable: {raw_name}")
    return runner.call(raw_name, args or {})


def _build_check_fn(*, reason: str):
    if not reason:
        return lambda: True

    def _raise_unavailable() -> bool:
        raise RuntimeError(reason)

    return _raise_unavailable

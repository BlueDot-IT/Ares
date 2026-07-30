from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable, Iterable

from ares.policy.risk import RISK_ORDER


def normalize_parameters_schema(schema: Any) -> dict[str, Any]:
    """Return an OpenAI-compatible JSON object parameters schema.

    Some MCP inventories emit `{\"type\": \"object\"}` for no-argument tools.
    OpenAI's function schema validator rejects object schemas that omit the
    `properties` member, so normalize root and nested object schemas here.
    """
    if not isinstance(schema, dict):
        schema = {"type": "object"}
    normalized = dict(schema)
    if normalized.get("type") != "object":
        normalized["type"] = "object"
    properties = normalized.get("properties")
    if not isinstance(properties, dict):
        properties = {}
    normalized["properties"] = {
        str(name): normalize_property_schema(property_schema)
        for name, property_schema in properties.items()
    }
    required = normalized.get("required")
    if not isinstance(required, list):
        required = []
    normalized["required"] = [str(item) for item in required]
    return normalized


def normalize_property_schema(schema: Any) -> dict[str, Any]:
    if not isinstance(schema, dict):
        return {"type": "string"}
    normalized = dict(schema)
    if normalized.get("type") == "object":
        return normalize_parameters_schema(normalized)
    if normalized.get("type") == "array" and isinstance(normalized.get("items"), dict):
        normalized["items"] = normalize_property_schema(normalized["items"])
    return normalized


@dataclass(frozen=True)
class ToolAvailability:
    name: str
    available: bool
    toolset: str
    risk: str
    requires: tuple[str, ...] = ()
    reason: str = ""


@dataclass(frozen=True)
class ToolEntry:
    name: str
    toolset: str
    risk: str
    schema: dict[str, Any]
    handler: Callable[..., Any]
    check_fn: Callable[[], bool] | None = None
    requires: tuple[str, ...] = field(default_factory=tuple)
    description: str = ""


class ToolRegistry:
    """Hermes-style central registry for model-visible pentest tools."""

    def __init__(self) -> None:
        self._tools: dict[str, ToolEntry] = {}

    def register(
        self,
        *,
        name: str,
        toolset: str,
        risk: str,
        schema: dict[str, Any],
        handler: Callable[..., Any],
        check_fn: Callable[[], bool] | None = None,
        requires: Iterable[str] | None = None,
        description: str = "",
    ) -> None:
        if not name:
            raise ValueError("tool name is required")
        if name in self._tools:
            raise ValueError(f"tool already registered: {name}")
        if risk not in RISK_ORDER:
            raise ValueError(f"unknown risk level: {risk}")
        source_schema = dict(schema)
        if "parameters" not in source_schema and source_schema.get("type") == "object":
            # Accept the JSON Schema shorthand used by internal tools. Without
            # this conversion their declared properties were retained only as
            # inert top-level metadata while models received an empty
            # parameters schema.
            normalized_schema = {
                "name": name,
                "description": description or name,
                "parameters": source_schema,
            }
        else:
            normalized_schema = source_schema
            normalized_schema.setdefault("name", name)
            normalized_schema.setdefault("description", description or name)
        normalized_schema["parameters"] = normalize_parameters_schema(
            normalized_schema.get("parameters", {"type": "object", "properties": {}})
        )
        self._tools[name] = ToolEntry(
            name=name,
            toolset=toolset,
            risk=risk,
            schema=normalized_schema,
            handler=handler,
            check_fn=check_fn,
            requires=tuple(requires or ()),
            description=description,
        )

    def check_tool_availability(self) -> dict[str, ToolAvailability]:
        return {name: self._availability(entry) for name, entry in self._tools.items()}

    def get_entry(self, name: str) -> ToolEntry | None:
        return self._tools.get(name)

    def iter_entries(self) -> list[ToolEntry]:
        return list(self._tools.values())

    def get_tool_definitions(
        self,
        *,
        enabled_toolsets: set[str] | None = None,
        disabled_toolsets: set[str] | None = None,
        max_risk: str = "post-exploitation",
    ) -> list[dict[str, Any]]:
        if max_risk not in RISK_ORDER:
            raise ValueError(f"unknown max risk level: {max_risk}")
        enabled_toolsets = set(enabled_toolsets or ())
        disabled_toolsets = set(disabled_toolsets or ())
        definitions: list[dict[str, Any]] = []
        for entry in self._tools.values():
            if enabled_toolsets and entry.toolset not in enabled_toolsets:
                continue
            if entry.toolset in disabled_toolsets:
                continue
            if RISK_ORDER[entry.risk] > RISK_ORDER[max_risk]:
                continue
            if not self._availability(entry).available:
                continue
            definitions.append({"type": "function", "function": entry.schema})
        return definitions

    def dispatch(self, name: str, args: dict[str, Any], **context: Any) -> Any:
        entry = self._tools.get(name)
        if entry is None:
            raise KeyError(f"unknown tool: {name}")
        policy = context.pop("policy", None)
        if policy is not None:
            policy.enforce_tool_call(entry.name, entry.risk, args or {})
        availability = self._availability(entry)
        if not availability.available:
            raise RuntimeError(f"tool unavailable: {name}: {availability.reason}")
        return entry.handler(args or {}, **context)

    def _availability(self, entry: ToolEntry) -> ToolAvailability:
        if entry.check_fn is None:
            return ToolAvailability(
                name=entry.name,
                available=True,
                toolset=entry.toolset,
                risk=entry.risk,
                requires=entry.requires,
            )
        try:
            available = bool(entry.check_fn())
        except Exception as exc:
            return ToolAvailability(
                name=entry.name,
                available=False,
                toolset=entry.toolset,
                risk=entry.risk,
                requires=entry.requires,
                reason=str(exc),
            )
        return ToolAvailability(
            name=entry.name,
            available=available,
            toolset=entry.toolset,
            risk=entry.risk,
            requires=entry.requires,
            reason="" if available else "availability check returned false",
        )


registry = ToolRegistry()

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable, Iterable

from ares.policy.risk import RISK_ORDER


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
        normalized_schema = dict(schema)
        normalized_schema.setdefault("name", name)
        normalized_schema.setdefault("description", description or name)
        normalized_schema.setdefault("parameters", {"type": "object", "properties": {}})
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

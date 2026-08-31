from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, ClassVar, Iterable, Mapping, Sequence

from ares.mission.contract import (
    ENGAGEMENT_CONTRACT_SCHEMA,
    EngagementContract,
    parse_engagement_contract,
)


class MissionStatus(str, Enum):
    CREATED = "created"
    RUNNING = "running"
    BLOCKED = "blocked"
    COMPLETED = "completed"
    FAILED = "failed"


class MissionPhase(str, Enum):
    PLAN = "plan"
    RECON = "recon"
    SCAN = "scan"
    WEAPONIZE = "weaponize"
    DELIVER = "deliver"
    EXPLOIT = "exploit"
    VALIDATE = "validate"
    POST_EXPLOITATION = "post-exploitation"
    PERSISTENCE = "persistence"
    ACTIONS = "actions"
    ANALYZE = "analyze"
    REPORT = "report"


class _MissionScopeList(list[str]):
    """List-compatible view that commits every mutation back to its scope."""

    __slots__ = ("_scope", "_field")

    def __init__(
        self,
        scope: MissionScope | Iterable[str],
        field_name: str | None = None,
    ) -> None:
        if field_name is None:
            self._scope: MissionScope | None = None
            self._field = ""
            super().__init__(scope)
            return
        if not isinstance(scope, MissionScope):
            raise TypeError("bound scope list requires a MissionScope")
        self._scope = scope
        self._field = field_name
        super().__init__(scope._list_snapshot(field_name))

    def _current(self) -> list[str]:
        if self._scope is None:
            return list(list.__iter__(self))
        return self._scope._list_snapshot(self._field)

    def _mutate(self, operation: Any) -> Any:
        values = self._current()
        result = operation(values)
        if self._scope is not None:
            self._scope._replace_list(self._field, values)
        list.clear(self)
        list.extend(
            self,
            self._current() if self._scope is not None else values,
        )
        return result

    def __iter__(self):  # type: ignore[no-untyped-def]
        return iter(self._current())

    def __len__(self) -> int:
        return len(self._current())

    def __getitem__(self, key: Any) -> Any:
        return self._current()[key]

    def __contains__(self, item: object) -> bool:
        return item in self._current()

    def __eq__(self, other: object) -> bool:
        if isinstance(other, _MissionScopeList):
            other = other._current()
        return self._current() == other

    def __ne__(self, other: object) -> bool:
        return not self == other

    def __repr__(self) -> str:
        return repr(self._current())

    def __str__(self) -> str:
        return str(self._current())

    def __add__(self, other: list[str]) -> list[str]:
        return self._current() + other

    def __radd__(self, other: list[str]) -> list[str]:
        return other + self._current()

    def __mul__(self, count: int) -> list[str]:
        return self._current() * count

    __rmul__ = __mul__

    def __reversed__(self):  # type: ignore[no-untyped-def]
        return reversed(self._current())

    def __deepcopy__(self, memo: dict[int, Any]) -> list[str]:
        del memo
        return self._current()

    def copy(self) -> list[str]:
        return self._current()

    def count(self, value: str) -> int:
        return self._current().count(value)

    def index(self, value: str, *args: int) -> int:
        return self._current().index(value, *args)

    def __setitem__(self, key: Any, value: Any) -> None:
        self._mutate(lambda values: values.__setitem__(key, value))

    def __delitem__(self, key: Any) -> None:
        self._mutate(lambda values: values.__delitem__(key))

    def append(self, value: str) -> None:
        self._mutate(lambda values: values.append(value))

    def clear(self) -> None:
        self._mutate(lambda values: values.clear())

    def extend(self, values: Sequence[str]) -> None:
        additions = list(values)
        self._mutate(lambda current: current.extend(additions))

    def insert(self, index: int, value: str) -> None:
        self._mutate(lambda values: values.insert(index, value))

    def pop(self, index: int = -1) -> str:
        return self._mutate(lambda values: values.pop(index))

    def remove(self, value: str) -> None:
        self._mutate(lambda values: values.remove(value))

    def reverse(self) -> None:
        self._mutate(lambda values: values.reverse())

    def sort(self, *, key: Any = None, reverse: bool = False) -> None:
        self._mutate(lambda values: values.sort(key=key, reverse=reverse))

    def __iadd__(self, values: Sequence[str]):  # type: ignore[no-untyped-def]
        self.extend(values)
        return self

    def __imul__(self, count: int):  # type: ignore[no-untyped-def]
        self._mutate(lambda values: values.__imul__(count))
        return self


@dataclass(init=False, repr=False, eq=False)
class MissionScope:
    """Mission-compatible view over one canonical engagement contract.

    The legacy constructor and field-shaped properties remain available. New
    callers can use ``from_contract_dict`` and ``to_contract_dict`` without
    adding a second contract representation to ``MissionRun``.
    """

    target: str
    allowed_paths: list[str]
    forbidden_paths: list[str]
    allowed_hosts: list[str]
    forbidden_actions: list[str]
    max_risk: str

    _LEGACY_KEYS: ClassVar[frozenset[str]] = frozenset(
        {
            "target",
            "allowed_paths",
            "forbidden_paths",
            "allowed_hosts",
            "forbidden_actions",
            "max_risk",
        }
    )
    _LIST_FIELDS: ClassVar[dict[str, str]] = {
        "allowed_paths": "allowed_paths",
        "forbidden_paths": "excluded_paths",
        "allowed_hosts": "allowed_hosts",
        "excluded_hosts": "excluded_hosts",
        "forbidden_actions": "forbidden_actions",
        "allowed_techniques": "allowed_techniques",
        "excluded_techniques": "excluded_techniques",
    }

    def __init__(
        self,
        target: str,
        allowed_paths: Sequence[str] | None = None,
        forbidden_paths: Sequence[str] | None = None,
        allowed_hosts: Sequence[str] | None = None,
        forbidden_actions: Sequence[str] | None = None,
        max_risk: str = "scan",
    ) -> None:
        legacy_allowed_paths = _legacy_paths(allowed_paths, "allowed_paths")
        legacy_forbidden_paths = _legacy_paths(
            forbidden_paths, "forbidden_paths"
        )
        self._contract = parse_engagement_contract(
            {
                "schema": ENGAGEMENT_CONTRACT_SCHEMA,
                "target": target,
                "allowed_paths": _effective_paths(legacy_allowed_paths),
                "excluded_paths": _effective_paths(legacy_forbidden_paths),
                "allowed_hosts": list(allowed_hosts or ()),
                "forbidden_actions": list(forbidden_actions or ()),
                "max_risk": max_risk,
            }
        )
        self._legacy_paths: dict[str, tuple[str, ...]] | None = {
            "allowed_paths": legacy_allowed_paths,
            "forbidden_paths": legacy_forbidden_paths,
        }

    @classmethod
    def from_contract_dict(cls, payload: Mapping[str, Any]) -> MissionScope:
        """Build a scope from strict v1 or legacy persisted scope JSON."""
        if not isinstance(payload, Mapping):
            raise ValueError("mission scope must be an object")
        if "schema" not in payload:
            non_string = [key for key in payload if not isinstance(key, str)]
            if non_string:
                raise ValueError("legacy mission scope keys must be strings")
            unknown = sorted(set(payload) - cls._LEGACY_KEYS)
            if unknown:
                raise ValueError(
                    "legacy mission scope has unknown fields: "
                    + ", ".join(unknown)
                )
            if "target" not in payload:
                raise ValueError("legacy mission scope missing fields: target")
            return cls(
                target=payload["target"],
                allowed_paths=_legacy_list(payload, "allowed_paths"),
                forbidden_paths=_legacy_list(payload, "forbidden_paths"),
                allowed_hosts=_legacy_list(payload, "allowed_hosts"),
                forbidden_actions=_legacy_list(payload, "forbidden_actions"),
                max_risk=payload.get("max_risk", "scan"),
            )

        instance = cls.__new__(cls)
        instance._contract = parse_engagement_contract(payload)
        instance._legacy_paths = None
        return instance

    def to_contract_dict(self) -> dict[str, Any]:
        return self._contract.to_dict()

    def to_legacy_dict(self) -> dict[str, Any]:
        """Return the pre-contract scope shape used by existing state rows."""
        return {
            "target": self.target,
            "allowed_paths": list(self.allowed_paths),
            "forbidden_paths": list(self.forbidden_paths),
            "allowed_hosts": list(self.allowed_hosts),
            "forbidden_actions": list(self.forbidden_actions),
            "max_risk": self.max_risk,
        }

    def _list_snapshot(self, field_name: str) -> list[str]:
        if field_name not in self._LIST_FIELDS:
            raise AttributeError(f"unknown MissionScope list field: {field_name}")
        if self._legacy_paths is not None and field_name in self._legacy_paths:
            return list(self._legacy_paths[field_name])
        return list(getattr(self._contract, self._LIST_FIELDS[field_name]))

    def _replace_list(
        self, field_name: str, values: Sequence[str]
    ) -> None:
        if isinstance(values, (str, bytes)):
            raise ValueError(f"{field_name} must be an array")
        payload = self._contract.to_dict(include_digest=False)
        next_legacy_paths = (
            dict(self._legacy_paths)
            if self._legacy_paths is not None
            else None
        )
        if next_legacy_paths is not None and field_name in next_legacy_paths:
            legacy_values = _legacy_paths(values, field_name)
            next_legacy_paths[field_name] = legacy_values
            payload[self._LIST_FIELDS[field_name]] = _effective_paths(
                legacy_values
            )
        else:
            payload[self._LIST_FIELDS[field_name]] = list(values)
        contract = parse_engagement_contract(payload)
        self._contract = contract
        self._legacy_paths = next_legacy_paths

    def _replace_scalar(self, field_name: str, value: Any) -> None:
        payload = self._contract.to_dict(include_digest=False)
        payload[field_name] = value
        self._contract = parse_engagement_contract(payload)

    @property
    def engagement_contract(self) -> EngagementContract:
        return self._contract

    @property
    def scope_digest(self) -> str:
        return self._contract.scope_digest

    @property
    def contract_digest(self) -> str:
        """Backward-compatible alias for the canonical scope digest."""
        return self.scope_digest

    @property
    def target(self) -> str:
        return self._contract.target

    @target.setter
    def target(self, value: str) -> None:
        self._replace_scalar("target", value)

    @property
    def allowed_paths(self) -> list[str]:
        return _MissionScopeList(self, "allowed_paths")

    @allowed_paths.setter
    def allowed_paths(self, values: Sequence[str]) -> None:
        self._replace_list("allowed_paths", values)

    @property
    def forbidden_paths(self) -> list[str]:
        return _MissionScopeList(self, "forbidden_paths")

    @forbidden_paths.setter
    def forbidden_paths(self, values: Sequence[str]) -> None:
        self._replace_list("forbidden_paths", values)

    @property
    def effective_allowed_paths(self) -> tuple[str, ...]:
        """Absolute paths bound into the canonical authorization digest."""
        return self._contract.allowed_paths

    @property
    def effective_forbidden_paths(self) -> tuple[str, ...]:
        """Absolute exclusions bound into the canonical authorization digest."""
        return self._contract.excluded_paths

    @property
    def allowed_hosts(self) -> list[str]:
        return _MissionScopeList(self, "allowed_hosts")

    @allowed_hosts.setter
    def allowed_hosts(self, values: Sequence[str]) -> None:
        self._replace_list("allowed_hosts", values)

    @property
    def excluded_hosts(self) -> list[str]:
        return _MissionScopeList(self, "excluded_hosts")

    @excluded_hosts.setter
    def excluded_hosts(self, values: Sequence[str]) -> None:
        self._replace_list("excluded_hosts", values)

    @property
    def forbidden_actions(self) -> list[str]:
        return _MissionScopeList(self, "forbidden_actions")

    @forbidden_actions.setter
    def forbidden_actions(self, values: Sequence[str]) -> None:
        self._replace_list("forbidden_actions", values)

    @property
    def allowed_techniques(self) -> list[str]:
        return _MissionScopeList(self, "allowed_techniques")

    @allowed_techniques.setter
    def allowed_techniques(self, values: Sequence[str]) -> None:
        self._replace_list("allowed_techniques", values)

    @property
    def excluded_techniques(self) -> list[str]:
        return _MissionScopeList(self, "excluded_techniques")

    @excluded_techniques.setter
    def excluded_techniques(self, values: Sequence[str]) -> None:
        self._replace_list("excluded_techniques", values)

    @property
    def max_risk(self) -> str:
        return self._contract.max_risk

    @max_risk.setter
    def max_risk(self, value: str) -> None:
        self._replace_scalar("max_risk", value)

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, MissionScope):
            return NotImplemented
        return self._contract == other._contract

    __hash__ = None

    def __repr__(self) -> str:
        return (
            "MissionScope("
            f"target={self.target!r}, "
            f"allowed_paths={self.allowed_paths!r}, "
            f"forbidden_paths={self.forbidden_paths!r}, "
            f"allowed_hosts={self.allowed_hosts!r}, "
            f"forbidden_actions={self.forbidden_actions!r}, "
            f"max_risk={self.max_risk!r})"
        )


def _legacy_list(payload: Mapping[str, Any], key: str) -> list[Any]:
    value = payload.get(key) or []
    if not isinstance(value, list):
        raise ValueError(f"legacy mission scope {key} must be an array")
    return value


def _legacy_paths(
    values: Sequence[str] | None, label: str
) -> tuple[str, ...]:
    if values is None:
        return ()
    if isinstance(values, (str, bytes)):
        raise ValueError(f"{label} must be an array")
    normalized: set[str] = set()
    for index, value in enumerate(values):
        if not isinstance(value, str):
            raise ValueError(f"{label}[{index}] must be a string")
        item = value.strip()
        if not item:
            raise ValueError(f"{label}[{index}] must not be empty")
        if any(ord(char) < 32 or ord(char) == 127 for char in item):
            raise ValueError(
                f"{label}[{index}] must not contain control characters"
            )
        normalized.add(item)
    return tuple(sorted(normalized))


def _effective_paths(values: Sequence[str]) -> list[str]:
    effective: list[str] = []
    for value in values:
        try:
            effective.append(str(Path(value).resolve(strict=False)))
        except (OSError, RuntimeError) as exc:
            raise ValueError(f"invalid legacy scope path: {value!r}") from exc
    return effective


@dataclass
class MissionRun:
    id: str
    profile_id: str
    scope: MissionScope
    status: MissionStatus = MissionStatus.CREATED
    phase: MissionPhase = MissionPhase.PLAN
    metadata: dict[str, Any] = field(default_factory=dict)

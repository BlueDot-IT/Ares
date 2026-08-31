from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, ClassVar, Mapping, Sequence

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

    def __init__(
        self,
        target: str,
        allowed_paths: Sequence[str] | None = None,
        forbidden_paths: Sequence[str] | None = None,
        allowed_hosts: Sequence[str] | None = None,
        forbidden_actions: Sequence[str] | None = None,
        max_risk: str = "scan",
    ) -> None:
        self._contract = parse_engagement_contract(
            {
                "schema": ENGAGEMENT_CONTRACT_SCHEMA,
                "target": target,
                "allowed_paths": list(allowed_paths or ()),
                "excluded_paths": list(forbidden_paths or ()),
                "allowed_hosts": list(allowed_hosts or ()),
                "forbidden_actions": list(forbidden_actions or ()),
                "max_risk": max_risk,
            }
        )

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
        return instance

    def to_contract_dict(self) -> dict[str, Any]:
        return self._contract.to_dict()

    def to_legacy_dict(self) -> dict[str, Any]:
        """Return the pre-contract scope shape used by existing state rows."""
        return {
            "target": self.target,
            "allowed_paths": self.allowed_paths,
            "forbidden_paths": self.forbidden_paths,
            "allowed_hosts": self.allowed_hosts,
            "forbidden_actions": self.forbidden_actions,
            "max_risk": self.max_risk,
        }

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

    @property
    def allowed_paths(self) -> list[str]:
        return list(self._contract.allowed_paths)

    @property
    def forbidden_paths(self) -> list[str]:
        return list(self._contract.excluded_paths)

    @property
    def allowed_hosts(self) -> list[str]:
        return list(self._contract.allowed_hosts)

    @property
    def excluded_hosts(self) -> list[str]:
        return list(self._contract.excluded_hosts)

    @property
    def forbidden_actions(self) -> list[str]:
        return list(self._contract.forbidden_actions)

    @property
    def allowed_techniques(self) -> list[str]:
        return list(self._contract.allowed_techniques)

    @property
    def excluded_techniques(self) -> list[str]:
        return list(self._contract.excluded_techniques)

    @property
    def max_risk(self) -> str:
        return self._contract.max_risk

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


@dataclass
class MissionRun:
    id: str
    profile_id: str
    scope: MissionScope
    status: MissionStatus = MissionStatus.CREATED
    phase: MissionPhase = MissionPhase.PLAN
    metadata: dict[str, Any] = field(default_factory=dict)

from __future__ import annotations

import hashlib
import hmac
import json
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Callable, ClassVar, Mapping

from ares.policy.risk import RISK_ORDER


ENGAGEMENT_CONTRACT_SCHEMA = "ares.engagement-contract.v1"
MAX_ALLOWED_PORTS = 1024
MAX_REQUESTS = 1_000_000
MAX_RETENTION_DAYS = 3650

_CONTRACT_KEYS = frozenset(
    {
        "schema",
        "target",
        "allowed_paths",
        "excluded_paths",
        "allowed_hosts",
        "excluded_hosts",
        "forbidden_actions",
        "allowed_techniques",
        "excluded_techniques",
        "max_risk",
        "starts_at",
        "ends_at",
        "allowed_ports",
        "max_requests",
        "credential_policy",
        "retention",
        "evidence_sensitivity",
        "stop_conditions",
        "approval_authorities",
        "scope_digest",
    }
)
_CREDENTIAL_POLICY_KEYS = frozenset(
    {"allow_use", "allow_collection", "allow_storage", "allowed_references"}
)
_RETENTION_KEYS = frozenset({"days", "delete_on_expiry"})
_APPROVAL_AUTHORITY_KEYS = frozenset({"id", "kind", "allowed_risks"})
_APPROVAL_AUTHORITY_KINDS = frozenset({"human", "policy", "service"})
_EVIDENCE_SENSITIVITY = frozenset(
    {"public", "internal", "confidential", "restricted"}
)
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_RFC3339_RE = re.compile(
    r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}"
    r"(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})$"
)
_CONTROL_RE = re.compile(r"[\x00-\x1f\x7f]")


@dataclass(frozen=True)
class CredentialPolicy:
    """Explicit credential permissions. Every permission defaults to denied."""

    allow_use: bool = False
    allow_collection: bool = False
    allow_storage: bool = False
    allowed_references: tuple[str, ...] = ()


@dataclass(frozen=True)
class RetentionPolicy:
    """Evidence-retention declaration for later enforcement surfaces."""

    days: int = 30
    delete_on_expiry: bool = True


@dataclass(frozen=True)
class ApprovalAuthority:
    """An identity that may approve work at the listed risk levels."""

    id: str
    kind: str
    allowed_risks: tuple[str, ...]


@dataclass(frozen=True)
class EngagementContract:
    """Normalized, versioned authorization boundary for one engagement."""

    target: str
    allowed_paths: tuple[str, ...] = ()
    excluded_paths: tuple[str, ...] = ()
    allowed_hosts: tuple[str, ...] = ()
    excluded_hosts: tuple[str, ...] = ()
    forbidden_actions: tuple[str, ...] = ()
    allowed_techniques: tuple[str, ...] = ()
    excluded_techniques: tuple[str, ...] = ()
    max_risk: str = "scan"
    starts_at: str | None = None
    ends_at: str | None = None
    allowed_ports: tuple[int, ...] = ()
    max_requests: int | None = None
    credential_policy: CredentialPolicy = field(default_factory=CredentialPolicy)
    retention: RetentionPolicy = field(default_factory=RetentionPolicy)
    evidence_sensitivity: str = "restricted"
    stop_conditions: tuple[str, ...] = ()
    approval_authorities: tuple[ApprovalAuthority, ...] = ()
    schema: ClassVar[str] = ENGAGEMENT_CONTRACT_SCHEMA

    def to_dict(self, *, include_digest: bool = True) -> dict[str, Any]:
        """Return the canonical JSON-compatible representation."""
        normalized = _parse_contract_payload(_model_payload(self))
        payload = _model_payload(normalized)
        if include_digest:
            payload["scope_digest"] = _digest_payload(payload)
        return payload

    @property
    def scope_digest(self) -> str:
        return _digest_payload(self.to_dict(include_digest=False))


def parse_engagement_contract(payload: Any) -> EngagementContract:
    """Parse a strict v1 contract and verify a supplied scope digest."""
    data = _object(payload, "engagement contract")
    _check_keys(
        data,
        allowed=_CONTRACT_KEYS,
        required={"schema", "target"},
        label="engagement contract",
    )
    supplied_digest = data.get("scope_digest")
    if supplied_digest is not None:
        if not isinstance(supplied_digest, str) or _SHA256_RE.fullmatch(
            supplied_digest
        ) is None:
            raise ValueError("scope_digest must be a lowercase SHA-256 digest")
    contract = _parse_contract_payload(data)
    if supplied_digest is not None and not hmac.compare_digest(
        supplied_digest, contract.scope_digest
    ):
        raise ValueError("scope_digest does not match the canonical contract")
    return contract


def canonicalize_engagement_contract(payload: Any) -> dict[str, Any]:
    """Parse and return one stable, digest-bearing JSON representation."""
    return parse_engagement_contract(payload).to_dict()


def engagement_contract_digest(
    value: EngagementContract | Mapping[str, Any],
) -> str:
    """Return the digest of a model or strict v1 contract mapping."""
    contract = (
        value
        if isinstance(value, EngagementContract)
        else parse_engagement_contract(value)
    )
    return contract.scope_digest


def _parse_contract_payload(payload: Mapping[str, Any]) -> EngagementContract:
    schema = payload.get("schema")
    if schema != ENGAGEMENT_CONTRACT_SCHEMA:
        raise ValueError(
            f"schema must be {ENGAGEMENT_CONTRACT_SCHEMA!r}"
        )

    target = _text(payload.get("target"), "target")
    allowed_paths = _string_list(
        payload.get("allowed_paths", []), "allowed_paths", _path
    )
    excluded_paths = _string_list(
        payload.get("excluded_paths", []), "excluded_paths", _path
    )
    allowed_hosts = _string_list(
        payload.get("allowed_hosts", []), "allowed_hosts", _host
    )
    excluded_hosts = _string_list(
        payload.get("excluded_hosts", []), "excluded_hosts", _host
    )
    forbidden_actions = _string_list(
        payload.get("forbidden_actions", []),
        "forbidden_actions",
        _token,
    )
    allowed_techniques = _string_list(
        payload.get("allowed_techniques", []),
        "allowed_techniques",
        _token,
    )
    excluded_techniques = _string_list(
        payload.get("excluded_techniques", []),
        "excluded_techniques",
        _token,
    )

    _reject_overlap(
        allowed_paths, excluded_paths, "allowed_paths", "excluded_paths"
    )
    _reject_overlap(
        allowed_hosts, excluded_hosts, "allowed_hosts", "excluded_hosts"
    )
    _reject_overlap(
        allowed_techniques,
        excluded_techniques,
        "allowed_techniques",
        "excluded_techniques",
    )

    max_risk = _token(payload.get("max_risk", "scan"), "max_risk")
    if max_risk not in RISK_ORDER:
        raise ValueError(f"unknown max_risk: {max_risk!r}")

    starts_at = _timestamp(payload.get("starts_at"), "starts_at")
    ends_at = _timestamp(payload.get("ends_at"), "ends_at")
    if (starts_at is None) != (ends_at is None):
        raise ValueError("starts_at and ends_at must be provided together")
    if starts_at is not None and ends_at is not None:
        if _timestamp_value(ends_at) <= _timestamp_value(starts_at):
            raise ValueError("ends_at must be later than starts_at")

    allowed_ports = _ports(payload.get("allowed_ports", []))
    max_requests = _optional_bounded_int(
        payload.get("max_requests"),
        "max_requests",
        minimum=1,
        maximum=MAX_REQUESTS,
    )
    credential_policy = _credential_policy(
        payload.get(
            "credential_policy",
            {
                "allow_use": False,
                "allow_collection": False,
                "allow_storage": False,
                "allowed_references": [],
            },
        )
    )
    retention = _retention(
        payload.get("retention", {"days": 30, "delete_on_expiry": True})
    )
    evidence_sensitivity = _token(
        payload.get("evidence_sensitivity", "restricted"),
        "evidence_sensitivity",
    )
    if evidence_sensitivity not in _EVIDENCE_SENSITIVITY:
        allowed = ", ".join(sorted(_EVIDENCE_SENSITIVITY))
        raise ValueError(f"evidence_sensitivity must be one of: {allowed}")
    stop_conditions = _string_list(
        payload.get("stop_conditions", []),
        "stop_conditions",
        _condition,
        maximum=64,
    )
    approval_authorities = _approval_authorities(
        payload.get("approval_authorities", [])
    )

    return EngagementContract(
        target=target,
        allowed_paths=allowed_paths,
        excluded_paths=excluded_paths,
        allowed_hosts=allowed_hosts,
        excluded_hosts=excluded_hosts,
        forbidden_actions=forbidden_actions,
        allowed_techniques=allowed_techniques,
        excluded_techniques=excluded_techniques,
        max_risk=max_risk,
        starts_at=starts_at,
        ends_at=ends_at,
        allowed_ports=allowed_ports,
        max_requests=max_requests,
        credential_policy=credential_policy,
        retention=retention,
        evidence_sensitivity=evidence_sensitivity,
        stop_conditions=stop_conditions,
        approval_authorities=approval_authorities,
    )


def _model_payload(contract: EngagementContract) -> dict[str, Any]:
    return {
        "schema": ENGAGEMENT_CONTRACT_SCHEMA,
        "target": contract.target,
        "allowed_paths": list(contract.allowed_paths),
        "excluded_paths": list(contract.excluded_paths),
        "allowed_hosts": list(contract.allowed_hosts),
        "excluded_hosts": list(contract.excluded_hosts),
        "forbidden_actions": list(contract.forbidden_actions),
        "allowed_techniques": list(contract.allowed_techniques),
        "excluded_techniques": list(contract.excluded_techniques),
        "max_risk": contract.max_risk,
        "starts_at": contract.starts_at,
        "ends_at": contract.ends_at,
        "allowed_ports": list(contract.allowed_ports),
        "max_requests": contract.max_requests,
        "credential_policy": {
            "allow_use": contract.credential_policy.allow_use,
            "allow_collection": contract.credential_policy.allow_collection,
            "allow_storage": contract.credential_policy.allow_storage,
            "allowed_references": list(
                contract.credential_policy.allowed_references
            ),
        },
        "retention": {
            "days": contract.retention.days,
            "delete_on_expiry": contract.retention.delete_on_expiry,
        },
        "evidence_sensitivity": contract.evidence_sensitivity,
        "stop_conditions": list(contract.stop_conditions),
        "approval_authorities": [
            {
                "id": authority.id,
                "kind": authority.kind,
                "allowed_risks": list(authority.allowed_risks),
            }
            for authority in contract.approval_authorities
        ],
    }


def _digest_payload(payload: Mapping[str, Any]) -> str:
    canonical = json.dumps(
        payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    )
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _object(value: Any, label: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise ValueError(f"{label} must be an object")
    return value


def _check_keys(
    value: Mapping[str, Any],
    *,
    allowed: frozenset[str],
    required: set[str],
    label: str,
) -> None:
    non_string = [key for key in value if not isinstance(key, str)]
    if non_string:
        raise ValueError(f"{label} keys must be strings")
    unknown = sorted(set(value) - allowed)
    if unknown:
        raise ValueError(f"{label} has unknown fields: {', '.join(unknown)}")
    missing = sorted(required - set(value))
    if missing:
        raise ValueError(f"{label} missing fields: {', '.join(missing)}")


def _text(value: Any, label: str) -> str:
    if not isinstance(value, str):
        raise ValueError(f"{label} must be a string")
    normalized = value.strip()
    if not normalized:
        raise ValueError(f"{label} must not be empty")
    if _CONTROL_RE.search(normalized):
        raise ValueError(f"{label} must not contain control characters")
    return normalized


def _path(value: Any, label: str) -> str:
    return _text(value, label)


def _host(value: Any, label: str) -> str:
    normalized = _text(value, label).lower().rstrip(".")
    if not normalized or any(char.isspace() for char in normalized):
        raise ValueError(f"{label} must be a host, IP address, or CIDR")
    return normalized


def _token(value: Any, label: str) -> str:
    return " ".join(_text(value, label).lower().split())


def _condition(value: Any, label: str) -> str:
    return " ".join(_text(value, label).split())


def _string_list(
    value: Any,
    label: str,
    normalizer: Callable[[Any, str], str],
    *,
    maximum: int = 256,
) -> tuple[str, ...]:
    if not isinstance(value, list):
        raise ValueError(f"{label} must be an array")
    if len(value) > maximum:
        raise ValueError(f"{label} must contain at most {maximum} entries")
    normalized = {
        normalizer(item, f"{label}[{index}]")
        for index, item in enumerate(value)
    }
    return tuple(sorted(normalized))


def _reject_overlap(
    allowed: tuple[str, ...],
    excluded: tuple[str, ...],
    allowed_label: str,
    excluded_label: str,
) -> None:
    overlap = sorted(set(allowed) & set(excluded))
    if overlap:
        raise ValueError(
            f"{allowed_label} and {excluded_label} overlap: "
            + ", ".join(overlap)
        )


def _timestamp(value: Any, label: str) -> str | None:
    if value is None:
        return None
    raw = _text(value, label)
    if _RFC3339_RE.fullmatch(raw) is None:
        raise ValueError(f"{label} must be an RFC 3339 timestamp")
    try:
        parsed = datetime.fromisoformat(
            raw[:-1] + "+00:00" if raw.endswith("Z") else raw
        )
    except ValueError as exc:
        raise ValueError(f"{label} must be an RFC 3339 timestamp") from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ValueError(f"{label} must include a timezone offset")
    normalized = parsed.astimezone(timezone.utc).isoformat()
    return normalized.replace("+00:00", "Z")


def _timestamp_value(value: str) -> datetime:
    return datetime.fromisoformat(value[:-1] + "+00:00")


def _ports(value: Any) -> tuple[int, ...]:
    if not isinstance(value, list):
        raise ValueError("allowed_ports must be an array")
    if len(value) > MAX_ALLOWED_PORTS:
        raise ValueError(
            f"allowed_ports must contain at most {MAX_ALLOWED_PORTS} entries"
        )
    ports: set[int] = set()
    for index, port in enumerate(value):
        if type(port) is not int or not 1 <= port <= 65535:
            raise ValueError(
                f"allowed_ports[{index}] must be an integer from 1 to 65535"
            )
        ports.add(port)
    return tuple(sorted(ports))


def _optional_bounded_int(
    value: Any,
    label: str,
    *,
    minimum: int,
    maximum: int,
) -> int | None:
    if value is None:
        return None
    if type(value) is not int or not minimum <= value <= maximum:
        raise ValueError(
            f"{label} must be an integer from {minimum} to {maximum}"
        )
    return value


def _boolean(value: Any, label: str) -> bool:
    if type(value) is not bool:
        raise ValueError(f"{label} must be a boolean")
    return value


def _credential_policy(value: Any) -> CredentialPolicy:
    policy = _object(value, "credential_policy")
    _check_keys(
        policy,
        allowed=_CREDENTIAL_POLICY_KEYS,
        required=set(_CREDENTIAL_POLICY_KEYS),
        label="credential_policy",
    )
    allow_use = _boolean(policy["allow_use"], "credential_policy.allow_use")
    allow_collection = _boolean(
        policy["allow_collection"], "credential_policy.allow_collection"
    )
    allow_storage = _boolean(
        policy["allow_storage"], "credential_policy.allow_storage"
    )
    references = _string_list(
        policy["allowed_references"],
        "credential_policy.allowed_references",
        _text,
        maximum=64,
    )
    if references and not allow_use:
        raise ValueError(
            "credential references require credential_policy.allow_use"
        )
    if allow_storage and not (allow_use or allow_collection):
        raise ValueError(
            "credential storage requires use or collection permission"
        )
    return CredentialPolicy(
        allow_use=allow_use,
        allow_collection=allow_collection,
        allow_storage=allow_storage,
        allowed_references=references,
    )


def _retention(value: Any) -> RetentionPolicy:
    retention = _object(value, "retention")
    _check_keys(
        retention,
        allowed=_RETENTION_KEYS,
        required=set(_RETENTION_KEYS),
        label="retention",
    )
    days = _optional_bounded_int(
        retention["days"],
        "retention.days",
        minimum=1,
        maximum=MAX_RETENTION_DAYS,
    )
    assert days is not None
    return RetentionPolicy(
        days=days,
        delete_on_expiry=_boolean(
            retention["delete_on_expiry"], "retention.delete_on_expiry"
        ),
    )


def _approval_authorities(value: Any) -> tuple[ApprovalAuthority, ...]:
    if not isinstance(value, list):
        raise ValueError("approval_authorities must be an array")
    if len(value) > 64:
        raise ValueError("approval_authorities must contain at most 64 entries")
    authorities: list[ApprovalAuthority] = []
    seen_ids: set[str] = set()
    for index, item in enumerate(value):
        label = f"approval_authorities[{index}]"
        authority = _object(item, label)
        _check_keys(
            authority,
            allowed=_APPROVAL_AUTHORITY_KEYS,
            required=set(_APPROVAL_AUTHORITY_KEYS),
            label=label,
        )
        authority_id = _text(authority["id"], f"{label}.id")
        folded_id = authority_id.casefold()
        if folded_id in seen_ids:
            raise ValueError(f"duplicate approval authority id: {authority_id}")
        seen_ids.add(folded_id)
        kind = _token(authority["kind"], f"{label}.kind")
        if kind not in _APPROVAL_AUTHORITY_KINDS:
            allowed = ", ".join(sorted(_APPROVAL_AUTHORITY_KINDS))
            raise ValueError(f"{label}.kind must be one of: {allowed}")
        risks = _string_list(
            authority["allowed_risks"],
            f"{label}.allowed_risks",
            _token,
            maximum=len(RISK_ORDER),
        )
        if not risks:
            raise ValueError(f"{label}.allowed_risks must not be empty")
        unknown_risks = sorted(set(risks) - set(RISK_ORDER))
        if unknown_risks:
            raise ValueError(
                f"{label}.allowed_risks has unknown values: "
                + ", ".join(unknown_risks)
            )
        ordered_risks = tuple(
            sorted(risks, key=lambda risk: (RISK_ORDER[risk], risk))
        )
        authorities.append(
            ApprovalAuthority(
                id=authority_id, kind=kind, allowed_risks=ordered_risks
            )
        )
    return tuple(
        sorted(authorities, key=lambda item: (item.id.casefold(), item.kind))
    )

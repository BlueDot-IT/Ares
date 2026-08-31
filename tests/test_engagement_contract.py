from __future__ import annotations

import json
from copy import deepcopy
from dataclasses import asdict, is_dataclass
from pathlib import Path

import pytest

from ares.mission.contract import (
    ENGAGEMENT_CONTRACT_SCHEMA,
    MAX_ALLOWED_PORTS,
    canonicalize_engagement_contract,
    engagement_contract_digest,
    parse_engagement_contract,
)
from ares.mission.model import MissionScope


def _contract(**overrides: object) -> dict[str, object]:
    payload: dict[str, object] = {
        "schema": ENGAGEMENT_CONTRACT_SCHEMA,
        "target": "lab.example",
    }
    payload.update(overrides)
    return payload


def test_minimal_contract_has_fail_closed_stable_defaults() -> None:
    canonical = canonicalize_engagement_contract(_contract())

    assert canonical["target"] == "lab.example"
    assert canonical["max_risk"] == "scan"
    assert canonical["starts_at"] is None
    assert canonical["ends_at"] is None
    assert canonical["allowed_ports"] == []
    assert canonical["max_requests"] is None
    assert canonical["credential_policy"] == {
        "allow_use": False,
        "allow_collection": False,
        "allow_storage": False,
        "allowed_references": [],
    }
    assert canonical["retention"] == {
        "days": 30,
        "delete_on_expiry": True,
    }
    assert canonical["evidence_sensitivity"] == "restricted"
    assert len(canonical["scope_digest"]) == 64
    assert canonicalize_engagement_contract(_contract()) == canonical


@pytest.mark.parametrize(
    ("payload", "message"),
    [
        ([], "must be an object"),
        ({"target": "lab.example"}, "missing fields: schema"),
        (
            {"schema": "ares.engagement-contract.v2", "target": "lab.example"},
            "schema must be",
        ),
        (_contract(extra=True), "unknown fields: extra"),
        (_contract(target="  "), "target must not be empty"),
        (_contract(target=42), "target must be a string"),
    ],
)
def test_schema_rejects_malformed_or_unknown_root_fields(
    payload: object, message: str
) -> None:
    with pytest.raises(ValueError, match=message):
        parse_engagement_contract(payload)


def test_nested_schemas_reject_unknown_fields() -> None:
    with pytest.raises(ValueError, match="credential_policy has unknown fields"):
        parse_engagement_contract(
            _contract(
                credential_policy={
                    "allow_use": False,
                    "allow_collection": False,
                    "allow_storage": False,
                    "allowed_references": [],
                    "token": "must-not-be-accepted",
                }
            )
        )

    with pytest.raises(ValueError, match="retention has unknown fields"):
        parse_engagement_contract(
            _contract(retention={"days": 7, "delete_on_expiry": True, "mode": "archive"})
        )


def test_normalization_deduplicates_and_sorts_set_like_fields() -> None:
    canonical = canonicalize_engagement_contract(
        _contract(
            target="  LAB target  ",
            allowed_paths=[" /srv/z ", "/srv/a", "/srv/a"],
            excluded_paths=[" /srv/secret "],
            allowed_hosts=["B.EXAMPLE.", "a.example", "b.example"],
            excluded_hosts=[" ADMIN.EXAMPLE. "],
            forbidden_actions=["  Persist   Access ", "persist access"],
            allowed_techniques=[" Port Scan ", "dns enum"],
            excluded_techniques=["Password Spray"],
            max_risk=" ACTIVE ",
            stop_conditions=["  Customer asks to stop  ", "Evidence   corruption"],
        )
    )

    assert canonical["target"] == "LAB target"
    assert canonical["allowed_paths"] == ["/srv/a", "/srv/z"]
    assert canonical["excluded_paths"] == ["/srv/secret"]
    assert canonical["allowed_hosts"] == ["a.example", "b.example"]
    assert canonical["excluded_hosts"] == ["admin.example"]
    assert canonical["forbidden_actions"] == ["persist access"]
    assert canonical["allowed_techniques"] == ["dns enum", "port scan"]
    assert canonical["excluded_techniques"] == ["password spray"]
    assert canonical["max_risk"] == "active"
    assert canonical["stop_conditions"] == [
        "Customer asks to stop",
        "Evidence corruption",
    ]


def test_digest_is_stable_across_key_and_set_order() -> None:
    first = _contract(
        allowed_hosts=["B.EXAMPLE", "a.example"],
        allowed_ports=[443, 22],
        stop_conditions=["Operator stop", "Service instability"],
    )
    second = {
        "stop_conditions": ["Service   instability", "Operator stop"],
        "allowed_ports": [22, 443, 22],
        "target": " lab.example ",
        "allowed_hosts": ["a.example", "b.example."],
        "schema": ENGAGEMENT_CONTRACT_SCHEMA,
    }

    assert engagement_contract_digest(first) == engagement_contract_digest(second)
    assert (
        canonicalize_engagement_contract(first)["scope_digest"]
        == canonicalize_engagement_contract(second)["scope_digest"]
    )


def test_supplied_digest_is_verified_and_round_trips() -> None:
    canonical = canonicalize_engagement_contract(
        _contract(max_risk="active", allowed_ports=[443])
    )
    assert parse_engagement_contract(canonical).to_dict() == canonical

    tampered = deepcopy(canonical)
    tampered["max_risk"] = "exploit"
    with pytest.raises(ValueError, match="does not match"):
        parse_engagement_contract(tampered)

    uppercase = deepcopy(canonical)
    uppercase["scope_digest"] = str(uppercase["scope_digest"]).upper()
    with pytest.raises(ValueError, match="lowercase SHA-256"):
        parse_engagement_contract(uppercase)


@pytest.mark.parametrize(
    ("allowed_key", "excluded_key", "value"),
    [
        ("allowed_paths", "excluded_paths", "/srv/private"),
        ("allowed_hosts", "excluded_hosts", "ADMIN.EXAMPLE."),
        ("allowed_techniques", "excluded_techniques", "Password Spray"),
    ],
)
def test_exact_scope_exclusions_cannot_contradict_allowlists(
    allowed_key: str, excluded_key: str, value: str
) -> None:
    payload = _contract(**{allowed_key: [value], excluded_key: [value.lower()]})
    with pytest.raises(ValueError, match="overlap"):
        parse_engagement_contract(payload)


def test_time_window_is_timezone_aware_normalized_and_ordered() -> None:
    canonical = canonicalize_engagement_contract(
        _contract(
            starts_at="2026-09-01T09:00:00-04:00",
            ends_at="2026-09-01T18:00:00-04:00",
        )
    )
    assert canonical["starts_at"] == "2026-09-01T13:00:00Z"
    assert canonical["ends_at"] == "2026-09-01T22:00:00Z"

    for payload in (
        _contract(starts_at="2026-09-01T09:00:00Z"),
        _contract(
            starts_at="2026-09-01T09:00:00",
            ends_at="2026-09-01T10:00:00Z",
        ),
        _contract(
            starts_at="2026-09-01T10:00:00Z",
            ends_at="2026-09-01T10:00:00Z",
        ),
    ):
        with pytest.raises(ValueError):
            parse_engagement_contract(payload)


def test_allowed_ports_and_request_limit_are_bounded() -> None:
    canonical = canonicalize_engagement_contract(
        _contract(allowed_ports=[65535, 443, 1, 443], max_requests=2500)
    )
    assert canonical["allowed_ports"] == [1, 443, 65535]
    assert canonical["max_requests"] == 2500

    for invalid in (0, 65536, True, "443"):
        with pytest.raises(ValueError, match="integer from 1 to 65535"):
            parse_engagement_contract(_contract(allowed_ports=[invalid]))
    with pytest.raises(ValueError, match=f"at most {MAX_ALLOWED_PORTS}"):
        parse_engagement_contract(
            _contract(allowed_ports=list(range(1, MAX_ALLOWED_PORTS + 2)))
        )
    for invalid in (0, 1_000_001, True, "100"):
        with pytest.raises(ValueError, match="max_requests"):
            parse_engagement_contract(_contract(max_requests=invalid))


def test_approval_authorities_are_strict_normalized_and_sorted() -> None:
    canonical = canonicalize_engagement_contract(
        _contract(
            approval_authorities=[
                {
                    "id": " security-bot ",
                    "kind": " SERVICE ",
                    "allowed_risks": ["exploit", "scan", "scan"],
                },
                {
                    "id": "Alice",
                    "kind": "human",
                    "allowed_risks": ["post-exploitation", "active"],
                },
            ]
        )
    )
    assert canonical["approval_authorities"] == [
        {
            "id": "Alice",
            "kind": "human",
            "allowed_risks": ["active", "post-exploitation"],
        },
        {
            "id": "security-bot",
            "kind": "service",
            "allowed_risks": ["scan", "exploit"],
        },
    ]

    with pytest.raises(ValueError, match="duplicate approval authority"):
        parse_engagement_contract(
            _contract(
                approval_authorities=[
                    {"id": "Alice", "kind": "human", "allowed_risks": ["scan"]},
                    {"id": "alice", "kind": "human", "allowed_risks": ["active"]},
                ]
            )
        )
    with pytest.raises(ValueError, match="kind must be one of"):
        parse_engagement_contract(
            _contract(
                approval_authorities=[
                    {"id": "x", "kind": "model", "allowed_risks": ["scan"]}
                ]
            )
        )
    with pytest.raises(ValueError, match="unknown values"):
        parse_engagement_contract(
            _contract(
                approval_authorities=[
                    {"id": "x", "kind": "human", "allowed_risks": ["root"]}
                ]
            )
        )


def test_credential_permissions_are_explicit_and_fail_closed() -> None:
    canonical = canonicalize_engagement_contract(
        _contract(
            credential_policy={
                "allow_use": True,
                "allow_collection": False,
                "allow_storage": False,
                "allowed_references": [" vault://prod/read-only ", "vault://prod/read-only"],
            }
        )
    )
    assert canonical["credential_policy"] == {
        "allow_use": True,
        "allow_collection": False,
        "allow_storage": False,
        "allowed_references": ["vault://prod/read-only"],
    }

    with pytest.raises(ValueError, match="references require"):
        parse_engagement_contract(
            _contract(
                credential_policy={
                    "allow_use": False,
                    "allow_collection": False,
                    "allow_storage": False,
                    "allowed_references": ["vault://prod/read-only"],
                }
            )
        )
    with pytest.raises(ValueError, match="storage requires"):
        parse_engagement_contract(
            _contract(
                credential_policy={
                    "allow_use": False,
                    "allow_collection": False,
                    "allow_storage": True,
                    "allowed_references": [],
                }
            )
        )
    with pytest.raises(ValueError, match="must be a boolean"):
        parse_engagement_contract(
            _contract(
                credential_policy={
                    "allow_use": 1,
                    "allow_collection": False,
                    "allow_storage": False,
                    "allowed_references": [],
                }
            )
        )


def test_retention_evidence_sensitivity_and_stop_conditions_are_validated() -> None:
    canonical = canonicalize_engagement_contract(
        _contract(
            retention={"days": 90, "delete_on_expiry": False},
            evidence_sensitivity=" CONFIDENTIAL ",
            stop_conditions=["Loss of customer connectivity"],
        )
    )
    assert canonical["retention"] == {"days": 90, "delete_on_expiry": False}
    assert canonical["evidence_sensitivity"] == "confidential"

    with pytest.raises(ValueError, match="retention.days"):
        parse_engagement_contract(
            _contract(retention={"days": 0, "delete_on_expiry": True})
        )
    with pytest.raises(ValueError, match="evidence_sensitivity"):
        parse_engagement_contract(_contract(evidence_sensitivity="secret"))


def test_mission_scope_legacy_constructor_and_serialization_stay_compatible() -> None:
    scope = MissionScope(
        " repo ",
        ["src", "tests"],
        ["vendor"],
        ["LOCALHOST."],
        [" persistence "],
        " ACTIVE ",
    )

    assert scope.target == "repo"
    assert scope.allowed_paths == ["src", "tests"]
    assert scope.forbidden_paths == ["vendor"]
    assert scope.allowed_hosts == ["localhost"]
    assert scope.forbidden_actions == ["persistence"]
    assert scope.max_risk == "active"
    legacy = {
        "target": "repo",
        "allowed_paths": ["src", "tests"],
        "forbidden_paths": ["vendor"],
        "allowed_hosts": ["localhost"],
        "forbidden_actions": ["persistence"],
        "max_risk": "active",
    }
    assert json.loads(json.dumps(scope.to_legacy_dict())) == legacy
    assert is_dataclass(scope)
    assert asdict(scope) == legacy


def test_mission_scope_loads_legacy_scope_json() -> None:
    scope = MissionScope.from_contract_dict(
        {
            "target": "src",
            "allowed_paths": ["src"],
            "forbidden_paths": ["src/private"],
            "allowed_hosts": [],
            "forbidden_actions": ["persistence"],
            "max_risk": "scan",
        }
    )
    assert scope.to_legacy_dict()["forbidden_paths"] == ["src/private"]
    assert scope.to_contract_dict()["excluded_paths"] == ["src/private"]


def test_mission_scope_round_trip_preserves_full_contract() -> None:
    canonical = canonicalize_engagement_contract(
        _contract(
            excluded_hosts=["admin.example"],
            allowed_techniques=["dns enum"],
            excluded_techniques=["password spray"],
            starts_at="2026-09-01T13:00:00Z",
            ends_at="2026-09-01T22:00:00Z",
            allowed_ports=[53, 443],
            max_requests=1000,
            approval_authorities=[
                {"id": "Alice", "kind": "human", "allowed_risks": ["scan"]}
            ],
        )
    )
    scope = MissionScope.from_contract_dict(canonical)

    assert scope.excluded_hosts == ["admin.example"]
    assert scope.allowed_techniques == ["dns enum"]
    assert scope.excluded_techniques == ["password spray"]
    assert scope.contract_digest == canonical["scope_digest"]
    assert scope.to_contract_dict() == canonical


def test_strict_parser_does_not_silently_accept_legacy_contracts() -> None:
    with pytest.raises(ValueError, match="missing fields: schema"):
        parse_engagement_contract({"target": "legacy.example"})


@pytest.mark.parametrize(
    ("field", "changed"),
    [
        ("excluded_hosts", ["admin.example"]),
        ("allowed_ports", [443]),
        ("max_requests", 10),
        ("evidence_sensitivity", "confidential"),
        ("stop_conditions", ["Operator stop"]),
    ],
)
def test_digest_binds_each_authorization_surface(field: str, changed: object) -> None:
    baseline = engagement_contract_digest(_contract())
    assert engagement_contract_digest(_contract(**{field: changed})) != baseline


def test_documented_example_is_canonical_and_digest_valid() -> None:
    example = json.loads(
        Path("docs/examples/engagement-contract-v1.example.json").read_text(
            encoding="utf-8"
        )
    )
    assert canonicalize_engagement_contract(example) == example

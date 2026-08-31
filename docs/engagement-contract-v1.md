# Engagement Contract v1

The Engagement Contract is the canonical, digest-bound declaration of an
authorized assessment boundary. This first implementation provides strict
parsing, normalization, and a `MissionScope` bridge. Dispatcher, CLI, gateway,
receipt, report, database-schema, and retention enforcement are separate
follow-up work; declaring a field here does not yet claim that every runtime
surface enforces it.

The schema identifier is `ares.engagement-contract.v1`. Unknown fields,
malformed values, contradictory exact allow/exclude entries, naive timestamps,
out-of-range ports, unbounded request counts, implicit credential permissions,
and invalid approval authorities are rejected.

Set-like arrays are deduplicated and sorted. Hosts, risk names, technique names,
and action names are normalized to lowercase. Time windows are converted to
UTC. The `scope_digest` is SHA-256 over the canonical JSON representation with
the digest field omitted. A supplied digest must match after normalization.

Credential permissions default to denied. `allowed_references` should contain
opaque identifiers such as vault references, never credential values. A
reference is invalid unless `allow_use` is true. Storage permission is invalid
unless use or collection is also explicitly permitted.

Existing code can continue to construct `MissionScope(target=..., ...)` and
persist its legacy six-field representation. New code can load a strict
contract with `MissionScope.from_contract_dict()` and serialize the complete
canonical form with `MissionScope.to_contract_dict()`.

See [the versioned example](examples/engagement-contract-v1.example.json).

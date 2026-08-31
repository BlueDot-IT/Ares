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

Strict host entries are DNS names, IP addresses, or network CIDRs only. DNS
names are lowercase without a trailing dot, and IP/CIDR values use their
canonical textual form. URL schemes, user information, paths, queries,
fragments, bracket syntax, embedded ports, wildcard names, and CIDRs with host
bits set are rejected. Ports belong in `allowed_ports`; they are never parsed
out of a host entry.

Strict `allowed_paths` and `excluded_paths` entries are normalized absolute
POSIX paths. Relative paths, backslashes, double-leading slashes, and `.` or
`..` segments are rejected so the digest binds one lexical filesystem scope.
Repeated separators and trailing separators normalize to the same canonical
path.

`max_requests` defaults to the conservative bound of 1,000 requests. An
explicit value must be an integer from 1 through 1,000,000; `null`, zero,
booleans, and unbounded values are rejected.

Credential permissions default to denied. `allowed_references` should contain
opaque identifiers such as vault references, never credential values. A
reference is invalid unless `allow_use` is true. Storage permission is invalid
unless use or collection is also explicitly permitted.

Existing code can continue to construct `MissionScope(target=..., ...)` and
persist its legacy six-field representation. New code can load a strict
contract with `MissionScope.from_contract_dict()` and serialize the complete
canonical form with `MissionScope.to_contract_dict()`.
The canonical digest is also available as `MissionScope.scope_digest` for
binding later persistence, approval, dispatch, and reporting surfaces.

For deliberate compatibility, the legacy constructor continues to accept and
return relative path strings. It resolves them once when the scope is created
or changed, binds those absolute effective paths into the strict contract and
digest, and uses the effective paths for runtime authorization. Legacy list
mutation remains supported: `append`, item mutation, and whole-list assignment
are validated atomically and immediately regenerate the contract and digest.
An invalid mutation raises and leaves the prior scope unchanged.

See [the versioned example](examples/engagement-contract-v1.example.json).

# Security Policy

Ares is intended only for authorized security testing. Do not use it against systems you do not own or do not have explicit permission to assess.

## Supported versions

| Version | Support |
| --- | --- |
| 1.1.x | Active security and compatibility support |
| 1.0.x | Critical security fixes and upgrade guidance |
| 0.x beta | Unsupported except for migration guidance |

## Reporting vulnerabilities

Use GitHub private vulnerability reporting for `BlueDot-IT/Ares`. Do not open a public issue for an unresolved vulnerability.

A useful report includes:

- affected version or commit
- affected component
- reproduction steps using a local or explicitly authorized target
- expected behavior
- actual behavior
- impact assessment
- proposed remediation, when known
- logs with all secrets and customer data removed

Do not publish working exploit details before a fix and coordinated disclosure decision are available.

## Handling secrets and evidence

Never include API keys, OAuth tokens, bearer tokens, passwords, private hostnames, approval receipts, engagement policies, customer data, or raw engagement evidence in public issues, pull requests, or discussion threads.

Use `ares support-bundle` for diagnostics. The generated bundle excludes credentials and engagement evidence by design, but operators must still review it before sharing.

## Security issue scope

Security issues in Ares include bypasses or weaknesses involving:

- target, path, host, CIDR, or engagement scope
- risk ceilings and rules of engagement
- dispatcher or mission approval gates
- approval receipt binding, expiry, replay prevention, or evidence provenance
- gateway authentication, pairing, session provenance, and CIDR allowlists
- tool schema isolation and effective-argument validation
- cross-target or cross-mission evidence recall
- secret redaction and training export filters
- release provenance, artifact integrity, and package identity

Issues in third-party tools integrated through Ares should also be reported upstream when appropriate. An Ares report is still warranted when the integration weakens or misrepresents the third-party boundary.

## Disclosure expectations

The maintainers will acknowledge a complete private report, assess severity and affected versions, coordinate remediation, and publish release notes or an advisory when appropriate. Timing depends on reproducibility, impact, and dependency coordination.

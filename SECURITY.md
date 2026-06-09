# Security Policy

Ares is intended only for authorized security testing. Do not use it against systems you do not own or do not have explicit permission to assess.

## Supported versions

| Version | Supported |
|---------|-----------|
| 1.x | Yes |
| 0.x beta | No, except for upgrade guidance |

## Reporting vulnerabilities

Report security issues privately by opening a private advisory or contacting the maintainer directly. Do not publish working exploit details for unresolved issues.

A useful report should include:

- affected version or commit
- affected component
- reproduction steps using a local or explicitly authorized target
- expected behavior
- actual behavior
- impact assessment
- any logs with secrets removed

## Handling secrets

Do not include API keys, OAuth tokens, bearer tokens, passwords, private hostnames, or customer data in public issues. Redact logs before attaching them.

## Scope notes

Security issues in Ares include bypasses of scope enforcement, risk policy, approval gates, gateway authentication, gateway allowlists, secret redaction, memory isolation, or training export filters.

Issues in third-party tools integrated through Ares should also be reported upstream when appropriate.

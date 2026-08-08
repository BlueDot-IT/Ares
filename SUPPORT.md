# Ares Support

Ares is an open-source operator platform. Support is provided through the canonical `BlueDot-IT/Ares` repository and is limited to the documented support boundary.

## Before requesting help

Run:

```bash
ares --version
ares doctor
ares doctor --json
ares support-bundle --out ares-support-bundle.json
```

Review:

- [INSTALL.md](INSTALL.md)
- [docs/quickstart.md](docs/quickstart.md)
- [docs/troubleshooting.md](docs/troubleshooting.md)
- [docs/v1-support-boundary.md](docs/v1-support-boundary.md)

Search existing issues before opening a new one.

## Where to report

### Installation and usage problems

Use the installation support issue form. Include the Ares version, Python version, operating system, installation method, exact command, expected result, actual result, and a reviewed support bundle when useful.

### Reproducible defects

Use the bug report form. Provide the smallest local or explicitly authorized reproduction possible.

### Feature requests

Use the feature request form. Explain the operator problem, proposed behavior, effect on policy boundaries, and whether the request changes a supported contract.

### Security vulnerabilities

Do not open a public issue. Follow [SECURITY.md](SECURITY.md) and use private vulnerability reporting.

## Information that must not be posted publicly

Do not attach or paste:

- API keys, OAuth tokens, bearer tokens, passwords, or cookies
- private hostnames, customer addresses, or internal network maps
- raw engagement evidence or customer reports
- GhostMCP engagement policies
- approval receipts or approval digests tied to live work
- unredacted configuration files or SQLite databases

`ares support-bundle` excludes credentials and engagement evidence by design. Review it before sharing because local paths, provider names, model names, and bind addresses may still be sensitive in some environments.

## Supported scope

Supported commands and runtime behavior are defined in [docs/v1-support-boundary.md](docs/v1-support-boundary.md).

Support does not cover:

- testing systems without authorization
- unattended exploitation
- bypassing policy, scope, evidence, or approval controls
- third-party model availability, quotas, or provider account problems
- external security tools that are not installed or are unsupported on the operator platform
- modifications from unofficial forks unless the issue reproduces on canonical `main`
- multi-tenant hosting without an external isolation design

## Version policy

The current 1.1.x line receives active compatibility and security fixes. The 1.0.x line receives critical security fixes and migration guidance. Beta releases are unsupported except for upgrade assistance.

When reporting a problem, reproduce it on the newest supported patch release whenever possible.

## Response expectations

Open-source support has no guaranteed response time or service-level agreement. Complete, redacted, reproducible reports are prioritized over vague failure descriptions.

# Contributing to Ares

Ares accepts focused contributions that preserve its operator-supervised security model.

## Ground rules

- Work only with local, synthetic, or explicitly authorized targets.
- Do not weaken scope, risk, approval, evidence, route, timeout, or authorization checks for convenience.
- Treat tool output, target content, recalled evidence, and model output as untrusted data.
- Never commit credentials, live engagement policies, approval receipts, customer data, or raw private evidence.
- Keep gateway, dashboard, and TUI responsibilities distinct.
- Update tests and documentation when behavior changes.

## Development setup

```bash
git clone https://github.com/BlueDot-IT/Ares.git
cd Ares
git submodule update --init --recursive

python -m venv .venv
. .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -e '.[dev,anthropic,gemini,ghostmcp]' -e vendor/ghostmcp
```

## Required local checks

```bash
python -m pytest tests -q
python -m compileall -q src/ares
python -m build
python -m twine check dist/*
git diff --check
```

For security-sensitive changes, also run:

```bash
python -m pip install bandit pip-audit ruff
python -m ruff check src tests --select E9,F63,F7,F82
python -m bandit -q -lll -r src
python -m pip_audit
```

## Pull request scope

Keep pull requests reviewable. Separate unrelated refactors, product changes, and policy changes.

A pull request that changes model authority, tool exposure, target construction, approval behavior, evidence provenance, gateway access, database migrations, or release publishing must explain the security boundary before and after the change.

## Tests

Add regression coverage for every defect. Security-boundary tests should include both allowed and denied cases.

Useful test categories include:

- exact scope and target handling
- path traversal and symlink behavior
- risk and approval gates
- receipt expiry, replay, digest, mission, and evidence binding
- cross-target and cross-mission isolation
- malformed or adversarial model and tool output
- gateway auth, pairing, and allowlist behavior
- StateDB migration and reopen behavior
- wheel installation and command startup

Tests must not depend on public targets or live credentials.

## Documentation and release notes

Update the relevant files when changing a supported surface:

- `README.md`
- `CHANGELOG.md`
- `docs/v1-support-boundary.md`
- command-specific documentation
- release notes under `docs/releases/`

Use a minor or major version change when intentionally changing a supported compatibility contract. Patch releases must preserve the documented support boundary.

## Commit and PR hygiene

- Use clear, imperative commit messages.
- Do not include generated build artifacts.
- Run `git diff --check`.
- Review the final diff for secrets and private evidence.
- Complete the pull request checklist.

## Security reports

Do not use a pull request to disclose an unresolved vulnerability. Follow [SECURITY.md](SECURITY.md).

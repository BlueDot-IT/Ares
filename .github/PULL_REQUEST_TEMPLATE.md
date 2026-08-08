## Summary

Describe the operator problem and the change.

## Security boundary

State the before and after behavior for any affected boundary:

- model authority
- tool exposure or argument construction
- target, host, CIDR, or path scope
- risk and rules of engagement
- approvals and approval receipts
- evidence provenance or memory isolation
- gateway authentication or exposure
- StateDB migrations
- package publication or release provenance

Write `No boundary change` when none apply.

## Validation

- [ ] Tests added or updated
- [ ] `python -m pytest tests -q`
- [ ] `python -m compileall -q src/ares`
- [ ] `python -m build`
- [ ] `python -m twine check dist/*`
- [ ] `git diff --check`
- [ ] Wheel installation or command smoke test completed when packaging or CLI behavior changed
- [ ] Denied and allowed cases covered when a security boundary changed

## Documentation

- [ ] README or command documentation updated when operator behavior changed
- [ ] `CHANGELOG.md` updated
- [ ] Support boundary updated when a stable contract changed
- [ ] Release notes updated when the change is user-visible

## Data and authorization hygiene

- [ ] Tests use local, synthetic, or explicitly authorized targets
- [ ] No credentials, customer data, live engagement policies, approval receipts, or raw private evidence are included
- [ ] Tool output and model output remain treated as untrusted data

## Release impact

State whether this requires a patch, minor, major, or no release.

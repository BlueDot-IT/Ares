# Ares Evaluation Lab

The Evaluation Lab is a deterministic, fully offline check of a small set of
Ares invariants. It is intended for release regression checks and local
development. It is not a benchmark of a model or a claim about security
assessment effectiveness.

## Run it

Print a short, plain-language summary:

```bash
ares evaluate
```

Print reproducible JSON:

```bash
ares evaluate --json
```

Write the same JSON atomically to a mode-`0600` file:

```bash
ares evaluate --out ares-evaluation.json
```

The command exits with status `0` when every fixture matches its expected
outcome and status `1` when one or more fixtures fail.

## What v1 measures

Corpus `ares-offline-evaluation` version `1.0.0` contains 12 fixtures in three
suites:

- Mission and task outcomes: an offline report task completes, an out-of-scope
  task blocks its mission, and an intentional tool error fails its mission.
- Scope and policy decisions: allowed local work, local path and network host
  exclusions, forbidden-action matching, and the mission risk ceiling.
- Finding validation readiness: sufficient corroborated evidence, version-only
  evidence, unresolved contradictory evidence, and the confidence threshold.

The sole metric is `fixture_agreement`:

```text
fixture_pass_rate = fixtures with exact expected outcomes / total fixtures
```

All fixtures have equal weight. A passing case means the named deterministic
invariant produced the versioned expected value. The metric is not calibrated
against real vulnerabilities and must not be described as accuracy, recall,
coverage, or model quality.

## Reproducibility and data boundary

The JSON result contains no timestamp, machine identity, temporary path,
engagement state, fixture target, tool arguments, or exception text. It records
the corpus version and SHA-256 digest, exact expected and observed bounded
outcomes, and suite totals. Repeated runs against the same source and Python
behavior produce byte-for-byte identical JSON.

Evaluation uses only the package-owned fixture corpus. It does not load user
sessions or evidence, invoke a model, read an Ares home directory, or make a
network request. Mission outcome fixtures use a temporary SQLite database that
is deleted after each case. The intentional failing tool is an in-process stub
and performs no action.

## Limitations

A passing Evaluation Lab result establishes only agreement with these 12
fixtures. It does not measure:

- model reasoning or model behavior;
- behavior against a live target;
- vulnerability discovery, false positives, or false negatives;
- the completeness of Ares policy enforcement; or
- broad security efficacy or production readiness.

Normal focused tests, the full test suite, packaging checks, and release gates
remain required.

## Updating the corpus

Fixture changes are product-contract changes. Keep them small and reviewable,
bump `corpus_version` when expected behavior changes, document the exact metric
meaning, and add tests that keep JSON deterministic and bounded. Do not put
credentials, engagement data, real targets, or model-generated content in the
corpus.

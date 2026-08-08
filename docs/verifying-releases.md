# Verifying Ares Releases

Official Ares releases are published from `BlueDot-IT/Ares` and include Python distributions, checksums, release metadata, a CycloneDX SBOM, and GitHub artifact attestations.

Do not install an artifact that fails checksum or attestation verification.

## Requirements

- GitHub CLI with attestation support
- `sha256sum` or an equivalent SHA-256 utility
- network access to GitHub's attestation service

Authenticate the GitHub CLI when required:

```bash
gh auth login
```

## Download a release

```bash
mkdir ares-release
cd ares-release

gh release download v1.1.0 \
  --repo BlueDot-IT/Ares
```

Expected files include:

```text
bluedot_ares-1.1.0-py3-none-any.whl
bluedot_ares-1.1.0.tar.gz
bluedot-ares-v1.1.0.cdx.json
release-metadata.json
SHA256SUMS
```

## Verify checksums

```bash
sha256sum -c SHA256SUMS
```

Every listed file must report `OK`.

On macOS with GNU coreutils installed:

```bash
gsha256sum -c SHA256SUMS
```

## Verify GitHub build provenance

```bash
gh attestation verify \
  bluedot_ares-1.1.0-py3-none-any.whl \
  --repo BlueDot-IT/Ares

gh attestation verify \
  bluedot_ares-1.1.0.tar.gz \
  --repo BlueDot-IT/Ares
```

The verified attestation must identify `BlueDot-IT/Ares` and the tagged release workflow as the source.

## Verify the SBOM attestation

The release workflow binds the wheel and source distribution to the published CycloneDX SBOM through a GitHub SBOM attestation.

```bash
gh attestation verify \
  bluedot_ares-1.1.0-py3-none-any.whl \
  --repo BlueDot-IT/Ares \
  --predicate-type https://cyclonedx.org/bom
```

GitHub CLI predicate filtering may vary by version. When the installed CLI does not support that filter, verify the artifact normally and inspect its attestation bundle:

```bash
gh attestation verify \
  bluedot_ares-1.1.0-py3-none-any.whl \
  --repo BlueDot-IT/Ares \
  --format json > wheel-attestations.json
```

Confirm that one statement references the CycloneDX SBOM predicate and that the subject digest matches the wheel.

## Inspect release metadata

```bash
python -m json.tool release-metadata.json
```

Confirm:

- `project` is `bluedot-ares`
- `product` is `Ares`
- `version` matches the release tag without the leading `v`
- `tag` matches the requested release
- `repository` is `BlueDot-IT/Ares`
- `commit` is the commit expected for the tag

Compare the tag and commit:

```bash
git ls-remote https://github.com/BlueDot-IT/Ares.git refs/tags/v1.1.0
```

## Inspect the wheel before installation

```bash
python -m zipfile -l bluedot_ares-1.1.0-py3-none-any.whl
```

The distribution name is `bluedot-ares`, but the import package and command remain `ares`.

Install into an isolated environment only after verification:

```bash
pipx install ./bluedot_ares-1.1.0-py3-none-any.whl
```

## PyPI verification

PyPI publication is performed with Trusted Publishing from the tagged GitHub workflow. The PyPI project page should show provenance for the uploaded wheel and source distribution.

Confirm the installed distribution:

```bash
python -m pip show bluedot-ares
```

Do not substitute the unrelated PyPI distribution named `ares`.

## Failure handling

When a checksum or attestation fails:

1. Delete all downloaded artifacts.
2. Download the release again from `BlueDot-IT/Ares`.
3. Confirm the release tag and repository spelling.
4. Update GitHub CLI and retry.
5. Do not install the artifact if verification still fails.
6. Report the discrepancy privately when tampering or release compromise is plausible.

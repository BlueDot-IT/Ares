# Installing Ares

Ares requires Python 3.11, 3.12, or 3.13.

## Package identity

The official Python distribution is `bluedot-ares`. It installs:

- the `ares` Python package
- the `ares` command
- the `ares-dashboard` command
- the `ares-tui` command

The PyPI project named `ares` is unrelated. Do not install `ares` from PyPI expecting this project. Use an isolated tool environment so the two distributions cannot overwrite the same import package.

## Recommended installation

### pipx

```bash
python -m pip install --user pipx
python -m pipx ensurepath
pipx install bluedot-ares
```

Install an optional integration at the same time:

```bash
pipx install 'bluedot-ares[anthropic]'
pipx install 'bluedot-ares[gemini]'
pipx install 'bluedot-ares[ghostmcp]'
```

### uv

```bash
uv tool install bluedot-ares
```

With an extra:

```bash
uv tool install 'bluedot-ares[gemini]'
```

## Install from a GitHub release

Download the wheel and verify it before installation. The wheel name uses an underscore because Python wheel filenames normalize hyphens:

```bash
gh release download v1.1.0 \
  --repo BlueDot-IT/Ares \
  --pattern 'bluedot_ares-*.whl' \
  --pattern SHA256SUMS

sha256sum -c SHA256SUMS --ignore-missing
pipx install ./bluedot_ares-1.1.0-py3-none-any.whl
```

See [docs/verifying-releases.md](docs/verifying-releases.md) for provenance and SBOM verification.

## Install in a virtual environment

```bash
python -m venv .venv
. .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install bluedot-ares
```

On Windows PowerShell:

```powershell
py -3.12 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
python -m pip install bluedot-ares
```

## Install from source

Use the canonical repository and initialize the GhostMCP submodule:

```bash
git clone https://github.com/BlueDot-IT/Ares.git
cd Ares
git submodule update --init --recursive

python -m venv .venv
. .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -e '.[dev,anthropic,gemini,ghostmcp]' -e vendor/ghostmcp
```

Run the local gate:

```bash
python -m pytest tests -q
python -m compileall src/ares
python -m build
python -m twine check dist/*
```

## First run

```bash
ares --version
ares onboard
ares doctor
ares doctor --json
```

Ares stores its normal local state under `~/.ares` unless `APP_HOME` is set.

## Upgrade

### pipx

```bash
pipx upgrade bluedot-ares
```

### uv

```bash
uv tool upgrade bluedot-ares
```

### virtual environment

```bash
python -m pip install --upgrade bluedot-ares
```

Back up `~/.ares` before a major-version upgrade. Patch and minor releases perform supported schema migrations when StateDB opens the database.

## Migrate from the old GitHub wheel

Ares 1.0.x GitHub artifacts used the distribution name `ares`. Remove that distribution from the isolated environment before installing `bluedot-ares`:

```bash
pipx uninstall ares
pipx install bluedot-ares
```

For a virtual environment:

```bash
python -m pip uninstall -y ares
python -m pip install bluedot-ares
```

Do not uninstall a system package blindly. Confirm the environment and distribution metadata first:

```bash
python -m pip show ares
python -m pip show bluedot-ares
```

Ares state in `~/.ares` is not removed by uninstalling the Python distribution.

## Uninstall

```bash
pipx uninstall bluedot-ares
# or
uv tool uninstall bluedot-ares
```

Remove `~/.ares` separately only when you intentionally want to delete configuration, sessions, reports, OAuth state, and engagement history.

## Platform notes

### Linux

Ares itself is Python-based, but individual security tools exposed through GhostMCP may require operating-system packages. `ares doctor` reports registry availability without silently installing tools.

### Windows

The package installs `windows-curses` on Windows. The CLI, dashboard, and TUI are included in Windows package smoke tests. Some external assessment tools remain platform-specific.

### macOS

The Python package and operator surfaces are supported. External tool availability depends on the selected toolset and local package manager.

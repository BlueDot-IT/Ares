# ARES Mission CLI Subcommands

ARES includes command-line tools for defining, executing, and listing swarm testing missions.

## Commands

### Run a Swarm Mission
```bash
ares mission run \
  --profile [secrets-audit|dependency-audit|source-code-audit|report-only|authorized-operator-validation] \
  --target <target-directory> \
  [--allowed-path <allowed-path>] \
  [--forbidden-path <forbidden-path>] \
  [--allowed-host <host-or-cidr>] \
  [--forbidden-action <phrase>] \
  [--max-risk <risk>] \
  [--mission-id <engagement-id>] \
  [--initial-tasks <tasks.json>] \
  [--ghostmcp-policy <engagement-policy.json>] \
  [--approve-high-risk] \
  [--out <markdown-report-path>] \
  [--dry-run]
```
*(Alternatively, you can use the direct app subcommand `ares mission-run`)*

Options:
- `--profile`: Specify the profile to use (default: `secrets-audit`).
- `--target`: The target path to analyze (required).
- `--allowed-path`: Add one or more paths that are allowed in the validation scope.
- `--forbidden-path`: Add one or more paths that must be excluded (e.g. `.git`, `.env`).
- `--allowed-host`: Add an exact authorized host, domain, or CIDR.
- `--forbidden-action`: Reject tasks containing a prohibited action phrase.
- `--max-risk`: Set the mission risk ceiling. The default is `scan`.
- `--mission-id`: Supply a stable engagement identifier used by both Ares and GhostMCP.
- `--initial-tasks`: Load an explicit JSON task graph. This is mandatory for the advanced profile.
- `--ghostmcp-policy`: Use a mode-`0600` GhostMCP 1.0 engagement policy whose engagement key matches `--mission-id`.
- `--approve-high-risk`: Give the dispatcher an explicit operator approval for exploit and post-exploitation calls. GhostMCP authorization provenance is still independently required.
- `--out`: Path to write the markdown report (defaults to `~/.ares/reports/mission-report-<id>.md`).
- `--dry-run`: Evaluate task validation and print the execution plan without executing anything.

ARES never infers an advanced task graph. A typical validation sequence is:

```bash
ares mission run \
  --profile authorized-operator-validation \
  --mission-id engagement-2026-001 \
  --target 192.0.2.10 \
  --allowed-host 192.0.2.10 \
  --max-risk post-exploitation \
  --initial-tasks tasks.json \
  --dry-run

ares mission run \
  --profile authorized-operator-validation \
  --mission-id engagement-2026-001 \
  --target 192.0.2.10 \
  --allowed-host 192.0.2.10 \
  --max-risk post-exploitation \
  --initial-tasks tasks.json \
  --ghostmcp-policy engagement-policy.json \
  --approve-high-risk
```

The GhostMCP policy remains the authoritative effective-argument boundary.
Ares supplies the mission ID itself and overwrites any engagement identity
included in task arguments.

### List Missions
```bash
ares mission list
```
*(Or `ares mission-list`)*

Prints a tabular list of all swarm testing missions stored in the database.

### Retrieve Mission Report
```bash
ares mission report <mission-id> --out <report-path>
```
*(Or `ares mission-report`)*

Retrieves the recorded details of a completed mission and generates the Markdown report at the specified path.

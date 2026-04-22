# IAM Policy Sentinel

Offline AWS IAM policy validation and least-privilege enforcement tool. Works entirely without live AWS calls, using local SQLite databases for all lookups.

## What It Does

Takes an IAM policy as input and produces a tightened, least-privilege version through a four-step pipeline:

1. **Validate** -- Parse the policy, classify every action into Tier 1 (valid), Tier 2 (unknown), or Tier 3 (invalid).
2. **Analyze** -- Detect wildcards, privilege escalation paths, data exfiltration risks, and missing companion permissions.
3. **Rewrite** -- Generate a least-privilege policy with specific ARNs or clearly marked placeholders.
4. **Self-Check** -- Re-validate the rewritten policy. If issues remain, loop back and fix them automatically.

## Supported Input Formats

- **JSON** -- Standard IAM policy format (default).
- **YAML** -- Files with `.yaml` or `.yml` extension are auto-detected as YAML.

Format can also be set explicitly with `--input-format json` or `--input-format yaml`.

## Installation

Sentinel ships as a PEP 621 project and is installed from a clone. The
primary supported workflow uses [uv](https://github.com/astral-sh/uv); a
pip fallback is documented below for users on older tooling.

### Primary (uv, recommended)

```bash
git clone <repo-url>
cd klarna
uv sync                 # installs runtime + dev deps, generates .venv
uv run sentinel info    # confirm install
```

`uv` reads `pyproject.toml` and `uv.lock`, creates a project-local
virtualenv, and pins every transitive dep to the exact version recorded
in the lockfile. Requires Python 3.11 or later (the runtime guard in
`src/sentinel/__main__.py` enforces this).

### Pip fallback (for pip < 23.1 or environments without uv)

```bash
git clone <repo-url>
cd klarna
python -m venv .venv
source .venv/bin/activate    # or  .venv\Scripts\activate  on Windows
pip install -e .[dev]
sentinel info
```

The `[dev]` extra pulls in the same test / lint / type-check toolchain
that `uv sync` produces. For a reproducible pinned install matching
`uv.lock`, regenerate a `requirements-frozen.txt` via
`uv export --format requirements-txt > requirements-frozen.txt`
and install from it with `pip install -r requirements-frozen.txt`.

Python 3.11+ is required. No AWS SDK or network access is needed for the
offline validation pipeline; live-fetch features activate opt-in.

## Quick Start

```bash
# Run the full pipeline on a JSON policy
python -m sentinel run tests/fixtures/test_policies/wildcard_overuse.json

# Run on a YAML policy
python -m sentinel run tests/fixtures/test_policies/simple_policy.yaml

# Validate a policy
python -m sentinel validate policy.json

# Analyze for security risks
python -m sentinel analyze policy.json

# Rewrite for least privilege with developer intent
python -m sentinel rewrite policy.json --intent "read-only s3"

# Interactive mode -- approve or reject unknown actions before rewriting
python -m sentinel run policy.json --interactive

# Read policy from stdin
cat policy.json | python -m sentinel validate -
```

## CLI Commands

| Command | Description |
|---------|-------------|
| `sentinel validate <policy>` | Validate and classify all actions |
| `sentinel analyze <policy>` | Analyze for security risks |
| `sentinel rewrite <policy>` | Rewrite for least privilege |
| `sentinel run <policy>` | Run the full four-step pipeline |
| `sentinel refresh --source <src> --data-path <path>` | Refresh IAM actions database |
| `sentinel info` | Show database statistics |

Use `-` as the policy path to read from stdin.

### Flags

| Flag | Description |
|------|-------------|
| `--intent "read-only s3"` | Guide rewriting with developer intent |
| `--input-format auto\|json\|yaml` | Set input format (default: auto-detect) |
| `--interactive` | Approve or reject Tier 2 actions before rewriting |
| `--strict` | Treat warnings as failures |
| `--database <path>` | Path to a custom IAM actions database |
| `--output-format json\|text\|markdown` | Choose output format |

## Project Structure

```
src/sentinel/          Core pipeline modules
  parser.py            Policy parser and three-tier action classifier
  analyzer.py          Risk analysis, companion detection, HITL system
  rewriter.py          Least-privilege policy rewriter
  self_check.py        Self-check validator and pipeline orchestrator
  database.py          SQLite interface for IAM actions
  inventory.py         Resource inventory manager
  cli.py               Command-line interface
  constants.py         Shared constants and mappings
  formatters.py        Text, JSON, and Markdown output formatters

src/refresh/           Database refresh tools
  policy_sentry_loader.py   Load from policy_sentry data
  aws_docs_scraper.py       Load from AWS docs
  aws_examples.py           Fetch and benchmark AWS example policies

data/                  SQLite databases
  iam_actions.db       IAM actions database
  resource_inventory.db Resource inventory
  known_services.json  Exported service prefixes

tests/                 Test suite (519 tests)
  test_*.py            Unit tests for each module
  integration/         Pipeline and end-to-end tests
  fixtures/            Test policies in JSON and YAML
```

## Running Tests

```bash
# All tests
python -m pytest tests/ -v

# Unit tests only
python -m pytest tests/test_parser.py tests/test_analyzer.py tests/test_rewriter.py -v

# Integration tests
python -m pytest tests/integration/ -v
```

## Tech Stack

- Python 3.9+
- SQLite3 for local data storage
- PyYAML for YAML input support
- pytest for testing
- No AWS SDK dependencies -- fully offline

# IAM Policy Sentinel

Fully offline AWS IAM policy validation and least-privilege enforcement tool. No live AWS calls -- uses local SQLite databases for all lookups.

## What It Does

A four-step pipeline that takes an IAM policy and produces a least-privilege version:

1. **Validate** -- Parse policy JSON, classify every action into Tier 1 (valid), Tier 2 (unknown), or Tier 3 (invalid)
2. **Analyze** -- Detect wildcards, privilege escalation, data exfiltration risks, and missing companion permissions
3. **Rewrite** -- Generate a least-privilege policy with specific ARNs or placeholders
4. **Self-Check** -- Re-validate the rewritten policy and loop back if issues remain

## Quick Start

```bash
# Install dependencies
pip install -r requirements.txt

# Run the full pipeline on a policy
python -m sentinel run tests/fixtures/test_policies/wildcard_overuse.json

# Validate a policy
python -m sentinel validate tests/fixtures/test_policies/hallucinated_actions.json

# Analyze risks
python -m sentinel analyze tests/fixtures/test_policies/privilege_escalation.json

# Rewrite for least privilege
python -m sentinel rewrite tests/fixtures/test_policies/wildcard_overuse.json --intent "read-only s3"

# Interactive mode -- approve/reject unknown actions before rewriting
python -m sentinel run policy.json --interactive
```

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

tests/                 Test suite (500+ tests)
  test_*.py            Unit tests for each module
  integration/         Pipeline and end-to-end tests
  fixtures/            7 categories of test policies
```

## CLI Commands

| Command | Description |
|---------|-------------|
| `sentinel validate <policy>` | Validate and classify actions |
| `sentinel analyze <policy>` | Analyze for security risks |
| `sentinel rewrite <policy>` | Rewrite for least privilege |
| `sentinel run <policy>` | Full four-step pipeline |
| `sentinel refresh --source <src> --data-path <path>` | Refresh IAM database |
| `sentinel info` | Show database stats |

### Key Flags

- `--intent "read-only s3"` -- Guide rewriting with developer intent
- `--interactive` -- Approve/reject Tier 2 actions before rewriting
- `--strict` -- Treat warnings as failures
- `--database <path>` -- Custom IAM database path
- `--output-format json|text|markdown` -- Output format

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
- SQLite3 (no external database)
- pytest (testing)
- No AWS SDK dependencies -- fully offline

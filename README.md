# IAM Policy Sentinel

> Version 0.8.3 -- offline AWS IAM policy validator, analyzer, and least-privilege rewriter.

A fully offline IAM policy analyzer with fail-closed safety guarantees. Sentinel parses an IAM policy, classifies every action against a local SQLite corpus, reports risk findings (wildcards, privilege escalation, exfiltration, destruction), and rewrites the policy toward least privilege with specific ARNs or clearly marked placeholders. Every fetched policy is origin-tracked; every cache entry and every security-critical database row is HMAC-signed; every network request passes through a four-layer SSRF defense. The tool performs **zero live AWS API calls** during validation.

## What it does

Sentinel runs a four-step pipeline on an IAM policy document:

1. **Validate** -- parse JSON/YAML, classify every action as Tier 1 (known-valid), Tier 2 (unknown; preserved with WARNING), or Tier 3 (invalid / rejected).
2. **Analyze** -- detect wildcards, privilege escalation chains, data exfiltration patterns, destructive permissions, redundancy, and missing companion permissions.
3. **Rewrite** -- generate a least-privilege version with specific ARNs (from the resource inventory) or clearly-marked placeholders, add companion permissions, inject condition keys, and split read/write statements.
4. **Self-check** -- re-validate the rewrite for functional completeness; if issues remain, loop back to step 3 (bounded by `--max-retries`, default 3).

A policy input can be a local file, stdin, clipboard, URL, GitHub path, AWS sample page, AWS managed policy (local DB), CloudSplaining example, or a whole directory (batch mode).

## Quickstart

```bash
git clone <repo-url>
cd klarna
uv sync --all-extras             # installs runtime + dev deps
uv run sentinel info             # sanity-check the install
uv run sentinel run tests/fixtures/test_policies/wildcard_overuse.json
```

Python 3.11+ is required. `sentinel info` prints database stats and an empty-corpus banner if the IAM action corpus has not yet been loaded -- run `sentinel refresh --source policy-sentry --data-path <policy_sentry.json>` on first use.

## Features

### Policy analysis

- Four-step pipeline: validate -> analyze -> rewrite -> self-check, with bounded retry loop.
- Three-tier action classification. Tier 2 (unknown) actions are **preserved** in the rewrite with WARNING verdict (Amendment 10), not silently dropped.
- Risk detectors: wildcards, privilege escalation, data exfiltration, destruction, permissions management, redundancy.
- Intent-to-access-level mapping (natural-language hints such as `--intent "read-only s3"` guide the rewrite).
- Companion permission detection (e.g. `lambda:CreateFunction` requires `iam:PassRole`, `logs:*`).
- Placeholder ARN strategy: when the resource inventory is empty, use clearly-marked placeholders rather than wildcards.

### Input sources

- Local JSON or YAML file.
- Stdin (`-`).
- Clipboard (`--from-clipboard`; WSL falls back to `powershell.exe Get-Clipboard`).
- URL (`--url <https://...>`).
- GitHub (`--github owner/repo/path`).
- AWS sample page (scraped via selectolax, `--aws-sample <name>`).
- AWS managed policy from local DB (`--aws-managed <name>`).
- CloudSplaining examples (`--cloudsplaining <filename>`).
- Directory batch (`sentinel run --batch <dir>`).

### Output formats

- `text` (default) -- human-readable report: origin badge, findings, Tier-2 review block, rewritten policy.
- `json` (`--output-format json`) -- structured fields: `origin`, `final_verdict`, `findings`, `rewrite_result`, `self_check_result`, `tier2_preserved_actions`, `rewritten_policy`, `semantic`, `force_emit_rewrite_bypass` (when applicable).
- `markdown` (`--output-format markdown`) -- for reports and PR comments.

### Safety and security

- **Fail-closed** by default (parser, analyzer, rewriter, self-check raise `DatabaseError` / `ValidationError` / `ConfigError` rather than silently demoting results).
- **HMAC row signing** on security-critical DB rows (`dangerous_actions`, `companion_rules`, `managed_policies`) with domain-separated keys (`K_cache` vs `K_db` derived via NIST SP 800-108 KDF).
- **HMAC key file** refuses to load when POSIX mode is broader than `0o600`.
- **SSRF defense quartet** on every HTTP request: URL allow-list, private-IP block, scheme allow-list, redirect chaser with per-hop re-validation. NAT64 / 6to4 / Teredo / IPv4-mapped IPv6 blocked.
- **Ephemeral safety flags** (`--insecure`, `--allow-domain`, `--skip-migrations`) HARD-FAIL if persisted via TOML or env (with a `SENTINEL_SKIP_MIGRATIONS` env carve-out for read-only filesystems only).
- **TLS verify** on by default; `--insecure` emits an unsuppressable `[WARN]` on every request and cache writes are skipped while insecure.
- **Secret redaction** -- structlog `redact_sensitive` processor scrubs tokens, API keys, JWTs, Bearer tokens, and AWS access keys from logs; a companion `strip_url_credentials` helper strips RFC 3986 userinfo from log-URLs.

### Observability

- Structured logging via `structlog` (human or JSON format via `--log-format`).
- OpenTelemetry stub (`sentinel.telemetry.tracer`) that picks up a real SDK if one is installed at runtime.
- Audit-trail log events: `http_request`, `http_response`, `http_redirect_followed`, `cache_hit`, `cache_hmac_mismatch`, `force_emit_rewrite_bypass`.
- Origin tracking: every fetched policy carries a SHA-256 receipt (`PolicyOrigin`).

### CI and automation

- **5-level exit-code scheme** (see below) for pipeline gating.
- `--force-emit-rewrite` escape hatch bypasses FAIL suppression with an audit-log + JSON `force_emit_rewrite_bypass` field.
- `sentinel watch <dir>` re-validates on file change (watchfiles).
- `sentinel run --batch <dir>` with `--fail-fast` for bulk scanning.
- `sentinel fetch --alert-on-new` for hash-compare continuous-monitor runs.

## CLI reference

| Command | Description |
|---------|-------------|
| `sentinel info` | DB stats, alembic revision, empty-corpus banner |
| `sentinel validate <file>` | Policy structure validation only |
| `sentinel analyze <file>` | Validate + risk analysis |
| `sentinel rewrite <file>` | Validate + analyze + rewrite |
| `sentinel run <file>` | Full 4-step pipeline (validate -> analyze -> rewrite -> self-check) |
| `sentinel run --batch <dir>` | Directory batch analysis |
| `sentinel refresh --source {policy-sentry\|aws-docs\|managed-policies\|cloudsplaining}` | Refresh a single DB source |
| `sentinel refresh --all` | Refresh every known source in sequence |
| `sentinel fetch --url\|--github\|--aws-sample\|--aws-managed\|--cloudsplaining\|--from-clipboard` | Fetch + pipeline |
| `sentinel watch <dir>` | Re-validate on file change |
| `sentinel wizard` | Interactive intent-based policy builder |
| `sentinel compare <a> <b>` | Diff two policies' risk profiles |
| `sentinel search "<q>" --on-github` | Search GitHub for public IAM policies |
| `sentinel cache {stats\|ls\|purge\|rotate-key}` | Inspect or manage HMAC-signed cache |
| `sentinel managed {list\|show\|analyze}` | Browse AWS managed policies |
| `sentinel config {show\|path\|init}` | Inspect configuration |
| `sentinel export-services` | Export service prefix list to JSON |
| `sentinel fetch-examples` | Fetch + benchmark AWS example policies |

See [`docs/USAGE.md`](docs/USAGE.md) for detailed how-to guides and [`docs/FEATURES.md`](docs/FEATURES.md) for the full feature catalogue.

### Shared flags (applied to every subcommand)

| Flag | Description |
|------|-------------|
| `--profile <name>` | Activate a named config profile |
| `--config <path>` | Override config file path |
| `--log-format human\|json` | Log output format |
| `--log-level DEBUG\|INFO\|WARNING\|ERROR` | Log verbosity threshold |
| `--insecure` | Disable TLS verify (ephemeral; emits `[WARN]` per request) |
| `--allow-domain <domain>` | Extend allow-list for one invocation (ephemeral; repeatable) |
| `--skip-migrations` | Bypass Alembic auto-upgrade (ephemeral; also honors `SENTINEL_SKIP_MIGRATIONS=1`) |
| `--cache-dir <path>` | Override cache directory |
| `-f/--output-format text\|json\|markdown` | Output format (default: text) |
| `-o/--output <path>` | Write output to file instead of stdout |

`--force-emit-rewrite` is available on `run`, `fetch`, and `managed analyze` only (the three subcommands that emit a rewrite).

## Exit codes

Sentinel uses a 5-level scheme for CI gating:

| Code | Name | Meaning |
|------|------|---------|
| 0 | `EXIT_SUCCESS` | Clean run; verdict PASS; no warnings |
| 1 | `EXIT_ISSUES_FOUND` | Verdict WARNING (non-fatal risks) |
| 2 | `EXIT_INVALID_ARGS` | Bad CLI arguments or unparseable input |
| 3 | `EXIT_IO_ERROR` | DB / HMAC / filesystem / migration failure |
| 4 | `EXIT_CRITICAL_FINDING` | Verdict FAIL (CRITICAL or HIGH severity finding) |

Example CI usage:

```bash
# Allow warnings, block on FAIL verdict + IO errors
sentinel run policy.json || [ $? -le 1 ] || exit 1

# Strict mode -- any non-clean run fails
sentinel run --strict policy.json
```

## Architecture

Sentinel is a single-package Python project (`src/sentinel/`) with subpackages for network I/O (`net/`), fetchers (`fetchers/`), and DB refresh tools (`refresh/`). The four pipeline stages live in `parser.py`, `analyzer.py`, `rewriter.py`, and `self_check.py` respectively. Output formatters (text, JSON, Markdown) live in `formatters.py`. Configuration uses pydantic-settings with a 6-tier precedence chain. Alembic manages schema migrations for the dual-DB (`iam_actions.db` + `resource_inventory.db`) with WAL mode, filelock, and pre-migration backup.

See [`prod_imp.md`](prod_imp.md) for the full design record including all 12 amendments (A1 critical findings -> A12 v0.8.2 audit cycle + documentation release).

## Configuration

Settings layer in this precedence order (later wins):

1. Shipped `defaults.toml`.
2. System TOML -- `/etc/sentinel/config.toml` (or Windows `%ProgramData%\sentinel\config.toml`).
3. User TOML -- `~/.config/sentinel/config.toml` (or `%APPDATA%\sentinel\config.toml`).
4. Project-local `./.sentinel.toml`.
5. `SENTINEL_*` environment variables.
6. CLI flags.

Secrets such as `SENTINEL_GITHUB_TOKEN` are wrapped in `pydantic.SecretStr`; `sentinel config show` renders them as `**********`. Ephemeral flags (`--insecure`, `--allow-domain`, `--skip-migrations`) HARD-FAIL if found in TOML or as non-carve-out env variables. See [`docs/USAGE.md#advanced`](docs/USAGE.md#advanced) for profile setup.

## Documentation map

| Document | Purpose |
|----------|---------|
| [`README.md`](README.md) | This file -- landing page, quickstart, CLI reference |
| [`docs/FEATURES.md`](docs/FEATURES.md) | Comprehensive feature catalogue organized by domain |
| [`docs/USAGE.md`](docs/USAGE.md) | End-user how-to guide with CI integration examples |
| [`CONTRIBUTING.md`](CONTRIBUTING.md) | Local development loop, testing, release process |
| [`CHANGELOG.md`](CHANGELOG.md) | Per-release feature narrative (Keep-a-Changelog format) |
| [`prod_imp.md`](prod_imp.md) | Full design record + § 17 amendment log |
| [`CLAUDE.md`](CLAUDE.md) | AI-agent project context and thinking log |

## Known limitations

- **No live AWS API calls during validation.** The tool is offline-first by design (no boto3 dependency). Live fetches happen only via the explicit `fetch` / `refresh --live` paths, through a hardened HTTP client.
- **SQLite single-writer.** Concurrent writes serialize; WAL mode mitigates read/write contention but heavy parallel writes (e.g., multiple `refresh --live` processes) are not supported.
- **Python 3.11+ required.** Enforced at runtime in `src/sentinel/__init__.py` and `src/sentinel/__main__.py`; `pyproject.toml` sets `requires-python = ">=3.11"`.
- **The IAM actions corpus is not shipped.** `data/iam_actions.db` ships with the security-critical baselines (dangerous actions, companion rules, ARN templates) HMAC-signed with `source='shipped'`, but the bulk services/actions corpus itself must be loaded on first use via `sentinel refresh --source policy-sentry --data-path <policy_sentry.json>`. A `[WARN]` banner prompts for this at startup.

## Project structure

```
src/sentinel/
  parser.py              Policy parser and three-tier action classifier
  analyzer.py            Risk analysis, companion detection, HITL system
  rewriter.py            Least-privilege policy rewriter
  self_check.py          Self-check validator and pipeline orchestrator
  database.py            SQLite interface for IAM actions
  inventory.py           Resource inventory manager
  cli.py                 Argparse-based CLI (dispatches to cli_* modules)
  cli_fetch.py           Fetch subcommand + continuous-monitor
  cli_cache.py           Cache management subcommand
  cli_managed.py         AWS managed-policy subcommand
  cli_config.py          Config show/path/init subcommand
  cli_misc.py            watch / wizard / compare / search subcommands
  cli_utils.py           Shared CLI helpers
  config.py              pydantic-settings config with 6-tier precedence
  constants.py           Shared constants and mappings
  exit_codes.py          Canonical EXIT_* definitions (single source)
  formatters.py          Text, JSON, and Markdown output formatters
  hmac_keys.py           Root + domain-separated sub-key derivation
  logging_setup.py       structlog configuration + redaction
  migrations.py          Alembic auto-upgrade + WAL activation
  models.py              PolicyOrigin + shared dataclasses
  secrets_patterns.py    Single-source redaction patterns
  seed_data.py           Baseline seeder for security-critical rows
  telemetry.py           OpenTelemetry tracer stub
  net/                   Hardened HTTP client + cache + SSRF guards
  fetchers/              Input-source fetchers (url, github, aws-*, etc.)
  refresh/               DB refresh tools (policy-sentry, aws-docs, etc.)

data/                    SQLite databases (tracked; public-metadata only)
  iam_actions.db         Ships pre-seeded with security-critical baselines
  resource_inventory.db  Empty schema; populate via your own inventory loader
  known_services.json    Exported service prefix list

tests/                   pytest suite (856 tests, ruff + mypy clean)
  fixtures/              Test policies and snapshots
  integration/           Pipeline and end-to-end tests
```

## Running tests

```bash
uv run pytest -m "not live" -n auto     # parallel, ~45s
uv run pytest -m "not live"             # serial, ~110s -- catches xdist-hidden regressions
uv run ruff check .
uv run ruff format --check .
uv run mypy                             # scope fixed by pyproject.toml [tool.mypy].files
```

Both parallel and serial test-runs must pass before a release. See [`CONTRIBUTING.md`](CONTRIBUTING.md) for the full dev loop and release process.

## Tech stack

- Python 3.11+ (3.12 recommended).
- SQLite3 with WAL journal mode and Alembic migrations.
- `httpx` for HTTP; `tenacity` for retry; `filelock` for migration concurrency.
- `pydantic` + `pydantic-settings` for config; `structlog` for logging.
- `watchfiles` for `sentinel watch`; `selectolax` for AWS sample scraping.
- `pytest` + `pytest-xdist` + `pytest-cov` + `hypothesis` + `vcrpy` for testing.
- `ruff` for lint/format; `mypy` for type checking; `uv` for dependency management.
- No AWS SDK dependency.

## License

Project licensing TBD. Contributions follow the process in [`CONTRIBUTING.md`](CONTRIBUTING.md).

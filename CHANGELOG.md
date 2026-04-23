# Changelog

All notable changes to IAM Policy Sentinel are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.5.0] - 2026-04-22

The "production migration" release.  The tool evolved from a fully
offline library into a production-ready CLI with pluggable fetchers,
typed configuration, HMAC-signed caches and database rows, and a
hardened network layer.  Six phases of work land here; see
``prod_imp.md`` for the full design record.

### Added

- **Typed configuration** (`sentinel.config`) with six-tier precedence:
  shipped defaults -> system TOML -> user TOML -> project `.sentinel.toml`
  -> `SENTINEL_*` env vars -> CLI overrides.  Ephemeral flags
  (`--insecure`, `--allow-domain`, `--skip-migrations`) are HARD-FAILed
  when found in persistable sources.
- **`SENTINEL_SKIP_MIGRATIONS` env carve-out** (Amendment 6 Theme F3)
  for read-only filesystems / Docker `:ro` mounts.
- **Hardened HTTP client** (`sentinel.net.client.SentinelHTTPClient`):
  allow-list, SSRF guard (IPv4 + IPv6 + NAT64/6to4/Teredo), DNS
  resolve-and-validate, redirect-chaser re-validates every hop (H9),
  per-source retry budgets with `Retry-After` honoring.
- **Disk cache with HMAC integrity** (`sentinel.net.cache.DiskCache`):
  atomic writes, per-source TTL, domain-separated sub-keys
  (`K_cache` vs `K_db`), in-memory fallback for read-only filesystems,
  `rotate_key` admin command.
- **Eight fetchers** (URL, GitHub, AWS sample, AWS managed, cloudsplaining,
  clipboard, local file, stdin, batch) under a single `Fetcher`
  protocol with `FetchResult` + `PolicyOrigin` provenance records.
- **Alembic migrations** for both `iam_actions.db` and
  `resource_inventory.db` with auto-upgrade, pre-migration backup,
  and 60s filelock (`.migrate.lock`).
- **HMAC row signing** for security-critical DB tables
  (`dangerous_actions`, `companion_rules`, `managed_policies`, etc.)
  with `sign_row`/`verify_row` primitives.
- **WAL journal mode** on first read-write open.
- **Single-source secret patterns** (`sentinel.secrets_patterns`)
  consumed by structlog redaction, VCR cassette scrubbing, and
  pre-commit grep hook.
- **CLI subcommands** — `config show/validate`, `fetch <source>
  <spec>`, `refresh --all`, `cache list/purge/rotate-key`, `managed
  list/show`.
- **Pre-commit hooks** — ruff, ruff-format, mypy, detect-secrets,
  local sentinel secret-grep.
- **PR-gate CI** (matrix: Ubuntu + Windows × 3.11 + 3.12) and nightly
  live-tests workflow with automatic issue filing on failure.
- **Dev-dep drift check** (`scripts/check_dev_deps_match.py`)
  keeping `[project.optional-dependencies].dev` and
  `[dependency-groups].dev` in sync.
- **Renovate config** with weekly lock-file maintenance.

### Changed

- Migrations moved from `Database.__init__` to explicit
  `check_and_upgrade_all_dbs()` at CLI entry.  Library callers now
  construct throw-away `Database()` instances without triggering
  migrations.
- Performance gate (`tests/test_performance.py::MAX_ALLOWED_SECONDS`)
  tightened from 1.0s to 0.3s as the steady-state budget.
- `--insecure` flag now emits an unsuppressable `[WARN]` log on every
  request.
- Cron log path corrected from `/var/log/sentinel.log` to
  `/var/log/sentinel-cron.log` per § 5.4 spec.

### Deprecated

- `check_and_upgrade_db(db_path)` single-DB helper — retained for
  backwards compatibility; prefer `check_and_upgrade_all_dbs()`.

### Removed

- Nothing of consequence; Phase 1-5 all-additive.

### Fixed

- Pre-parse balanced-bracket depth guard (H12) now rejects
  pathological JSON before `json.loads` allocates.
- Cache dir fallback no longer leaks `.tmp` files on rename failure.
- Alembic downgrade path fully reversible — upgrade/downgrade/upgrade
  round-trip produces byte-identical `sqlite_master` (Amendment 6 E1).
- Two-fetcher races on `cache.key` derivation eliminated by
  per-xdist-worker `SENTINEL_DATA_DIR` isolation.

### Security

- **L7 — GitHub token redaction.** `SENTINEL_GITHUB_TOKEN` stored as
  `pydantic.SecretStr`; `sentinel config show` renders `**********`.
- **H9 — SSRF on every redirect.** Redirect chaser re-runs the full
  allow-list + SSRF guard chain on every hop.
- **H13 — Tunnel prefix rejection.** NAT64/6to4/Teredo/IPv4-mapped
  IPv6 addresses blocked; embedded IPv4 extracted and transitively
  checked against RFC 1918 / loopback / metadata ranges.
- **Theme D — Domain-separated HMAC keys.** `K_cache` and `K_db`
  derived via NIST SP 800-108 label-based KDF; compromise of one
  does not unlock the other.
- **detect-secrets baseline** committed; pre-commit hook blocks new
  secrets from reaching the working tree.

## [0.3.0] - 2026-02-12

Phase 3: policy rewriting with configurable least-privilege features.
86 new tests, 201/201 overall passing.

## [0.2.0] - 2026-02-12

Phase 2: risk analysis, intent mapping, companion permission detection,
human-in-the-loop Tier 2 flagging.

## [0.1.0] - 2026-02-12

Phase 1: parser, SQLite schema, resource inventory, offline validation.

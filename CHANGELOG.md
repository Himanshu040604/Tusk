# Changelog

All notable changes to IAM Policy Sentinel are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.6.1] - 2026-04-23

Phase 7.1 completeness pass.  Post-ship review by 6 agents identified
5 gaps in the Phase 7 fix set — this release closes all of them, adds
4 direct regression tests for previously-untested Phase 7 fixes, and
applies 3 cosmetic corrections.  No behaviour change for correct data
paths; three additional silent-failure modes now fail loudly.

### Fixed

- **self_check.py cold-start regression (P0-3 completion).** Module-level
  `from .constants import WRITE_PREFIXES, READ_INTENT_KEYWORDS` was
  missed by the original P0-3 α+γ pass and was still pulling
  `pydantic_settings` (~1.1s) on first import of `self_check.py`.
  Moved to function-scope inside `_find_write_actions` and
  `_check_functional_completeness` per the same pattern already applied
  in analyzer.py/rewriter.py/formatters.py.
- **`_validate_actions` shared DB connection (P1-8 completion).** P1-8 β
  shared the connection in `parser.validate_policy` but left the sibling
  self-check loop opening up to ~60 connections per 20-action policy.
  Now wraps the loop in `with self.database.get_connection() as conn:`
  and calls `_classify_action_with_conn(action, conn)` (helper already
  existed).  Extracted the tier->CheckFinding builder into
  `_append_validate_finding` so both the no-DB fallback and shared-
  connection hot path share one body.
- **conftest.py `try/except Exception: pass` on DB rebuild.** The shared
  SENTINEL_DATA_DIR fixture silently swallowed rebuild failures, letting
  the suite report 715/715 green while production was broken.  Replaced
  with `pytest.fail(f"Shared DB rebuild failed: {exc}")` so harness
  regressions abort loudly.
- **HMAC root-key silent regen on key loss (silent-failure B2).**
  `_load_or_create_root_key` would silently create a new key when the
  file was missing or truncated, invalidating every HMAC-signed DB row
  with zero ERROR event.  New probe `_db_has_signed_rows` scopes to the
  key's own data_dir; if signed rows exist and the key is missing/
  truncated, `HMACError` is raised with `rotate-key` recovery text.
  Auto-generation still runs on a genuine first-install state.
- **cli.main baseline seed failure → silent warn (silent-failure B3).**
  `try: seed_all_baseline(...) except Exception as e: print("[WARN]...")`
  let Sentinel proceed with an empty `dangerous_actions` table and zero
  risk findings on admin-privilege policies.  Replaced with `[ERROR]`
  output and `sys.exit(EXIT_IO_ERROR)`, matching the migration-error
  handler above it.

### Added

- **Regression test: P0-2 γ mis-stamped DB abort.** Creates a Phase-1-only
  DB, stamps it at Alembic HEAD via `command.stamp`, then asserts
  `check_and_upgrade_all_dbs` raises `DatabaseError` with
  "missing expected tables".
- **Regression test: P1-4 α wizard refuses unknown intent.** Subprocess
  invocation with bogus service+intent; asserts `EXIT_INVALID_ARGS`,
  "Recognized intents" in output, `"service:*"` NOT in stdout.
- **Regression test: P1-6 β `Database.is_empty` rejects injection.**
  Real-table / unknown-table / classic SQL-injection payload probe,
  verifies `actions` table still exists afterwards via sqlite_master.
- **Regression test: P2-13 β HMAC perm refuse-to-load.** chmod 0o644 on
  cache.key, asserts `HMACError` raised with `0o600` or `rotate-key`
  in the message.  Platform-skipped on Windows.

### Changed

- **CHANGELOG [0.6.0]** fix count prose corrected from "Fourteen" to
  "Sixteen" to match the 16 rows in the implementation report table.
- **prod_imp.md § 4.2** gained a forward-reference note for Amendment 7
  (§ 17) which relocated `fetchers/` and `refresh/` under
  `src/sentinel/`.  Historical layout listing preserved for traceability.
- **PEP 585 generics** — `typing.List/Dict/Set/Optional/Tuple` subscripts
  replaced with lowercase `list/dict/set/... | None/tuple` in the 3
  core modules (analyzer.py, rewriter.py, self_check.py).  Enforced
  project-wide via `UP006` added to `[tool.ruff.lint].select`; auto-fix
  rippled through constants.py, database.py, parser.py, formatters.py,
  inventory.py, and 3 `refresh/*` modules for consistency.

## [0.6.0] - 2026-04-22

Phase 7 hardening release.  Sixteen investigator-confirmed issues
fixed; Agents 1-3 + independent validation converged on a 14-step
application plan which landed here.  No behaviour change for correct
data+config paths; a number of previously-silent failure modes now
fail loudly and correctly.

### Fixed

- **P0-1 alpha - fail-open bulk-load removed.** Four `except Exception:
  return False/None` blocks that silently swallowed DatabaseError
  (including HMAC-mismatch) at the bulk-load sites in analyzer.py and
  rewriter.py were removed.  Corrupted rows now raise `DatabaseError`
  instead of producing zero findings.
- **P0-2 gamma - startup-time DB safe-stamp detect-and-abort.** A DB
  stamped at Alembic HEAD but missing Phase-2 tables (safe-stamp
  branch without backfill) is detected at migrations time and aborts
  with EXIT_IO_ERROR + recovery instructions (`delete data/iam_actions.db`
  then `sentinel info`).
- **P0-3 alpha + gamma - cold-start `sentinel --version` from ~885ms
  to ~158ms.** Module-level `from .constants import X` imports in
  analyzer.py, rewriter.py, and formatters.py triggered the
  pydantic-settings stack at import time.  Deferred to function
  scope; class attributes became lazy `@property` accessors.
- **P1-4 alpha - `cmd_wizard` no longer falls back to `service:*`.**
  When IntentMapper cannot classify the intent string, the wizard
  refuses to emit a policy, prints the recognized intent buckets,
  and exits EXIT_INVALID_ARGS.  Fail-closed per section 2.4.
- **P1-6 beta - `Database.is_empty` SQL-injection surface hardened.**
  Two-layer defense: (1) module-level `_EXPECTED_TABLES` frozenset
  whitelist check before any SQL; (2) even for whitelisted names, a
  parameterized sqlite_master round-trip validates the name before
  the row probe; the row probe interpolates `probe[0]` (SQLite's own
  validated identifier) inside ANSI double-quotes.
- **P1-7 alpha - cron script uses bash array form** (`read -ra` +
  `"${_SENTINEL_CMD[@]}"`) to prevent glob injection and IFS attacks.
- **P1-8 beta - `validate_policy` shares one DB connection** across
  all `classify_action` calls in its loop.  New
  `_classify_action_with_conn` helper + three `_with_conn` variants
  on Database (`_service_exists`, `_action_exists`, `_get_action`).
  Single-connection path for 100-action policies; public
  `classify_action` unchanged.
- **P2-9 alpha - profile `max_retries` now effective.** The
  profile-merge logic writes the value to all three
  `retries.budgets.{github, aws_docs, user_url}` keys in addition
  to the legacy `defaults.max_retries`.
- **P2-10 alpha - duplicate `EXIT_*` constants removed from
  `constants.py`.** Single source of truth in `exit_codes.py`.  Two
  test files updated to import from the canonical location.
- **P2-12 alpha - GitHub Search URL urlencoded.**  cmd_search now
  builds the URL via `urllib.parse.urlencode(params, quote_via=quote)`
  instead of naive f-string concatenation.
- **P2-13 beta - HMAC key file refuses to load on broad POSIX perms.**
  `_load_or_create_root_key` stats the key file; if `mode & 0o077`
  is non-zero, raises `HMACError` with a rotate-key recovery hint.
  Platform-conditionalized: Windows skips the check (chmod may
  silently no-op on non-POSIX filesystems).
- **P2-15 alpha - `IntentMapper` precompiles keyword patterns once.**
  Word-boundary regex patterns built in `__init__` into
  `self._compiled_keyword_patterns`; hot-path methods iterate the
  precompiled list instead of rebuilding regex strings per call.

### Changed

- **P1-5 alpha + Amendment 7 - fetchers + refresh relocated** from
  `src/fetchers/` and `src/refresh/` to `src/sentinel/fetchers/` and
  `src/sentinel/refresh/`.  Departure from section 4.2 peer-layout;
  Amendment 7 appended to prod_imp.md section 17 documents the
  decision.  30+ cross-package imports rewritten, 17+ test-mock
  string literals updated, `pyproject.toml` wheel packages collapsed
  to `["src/sentinel"]`.  Fixes a latent runtime bug where
  `sentinel refresh` crashed with `ImportError: attempted relative
  import beyond top-level package`.

### Added

- **P2-11 alpha - `migrated_db_template` fixture implemented.**
  Session-scoped per xdist worker; stamped at Alembic HEAD + seeded.
  Individual tests get a fast `shutil.copy2` via a new `template=`
  parameter on `make_test_db`.
- **P2-11 alpha - `signed_db_row(table, pk, row_data, *, key=None)`
  fixture implemented.**  Default path derives K_db from `cache.key`;
  custom `key` bytes override reimplements the canonical serialization
  for forgery tests.  Returns a dict ready for INSERT.

### Internal

- **P2-14 alpha - Pipeline eagerly constructs + reuses analyzer /
  companion detector instances.**  `SelfCheckValidator.__init__`
  gained two optional keyword-only DI slots; Pipeline passes its
  pre-built instances through so the self-check retry loop doesn't
  re-bulk-load the DB up to 3 times per policy.
- Test conftest reshaped for Group A: per-worker `SENTINEL_DATA_DIR`
  replaced by a shared session-scoped path so all xdist workers agree
  on the HMAC key for the shared `data/iam_actions.db`.

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

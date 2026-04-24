# IAM Policy Sentinel -- Feature catalogue

A domain-oriented feature reference for v0.8.2. Every entry carries a
one-sentence description and a pointer to the code that implements it.
Per-entry `(v0.8.x <id>)` labels document the release in which that
feature was introduced or last changed -- use them for source-history
context, not for "current" version. Target audience: engineers
evaluating whether Sentinel fits a specific use case.

## Policy analysis

| Feature | File | Description |
|---------|------|-------------|
| Four-step pipeline (validate -> analyze -> rewrite -> self-check) | `src/sentinel/self_check.py::Pipeline` | Orchestrator reuses a single analyzer + companion detector instance across the self-check retry loop (P2-14). |
| JSON policy parsing | `src/sentinel/parser.py::PolicyParser` | Enforces size caps, balanced-bracket depth guard (H12), fail-closed on DB errors (Amendment 8). |
| YAML policy parsing | `src/sentinel/parser.py::parse_policy_yaml` | YAML-to-JSON canonicalization; the PyYAML import is deferred to the callsite to keep cold-start below the perf budget (v0.8.1 C2). |
| Three-tier action classification | `src/sentinel/parser.py::classify_action` | Tier 1 = known-valid; Tier 2 = unknown (preserved with WARNING per Amendment 10); Tier 3 = invalid (rejected). |
| NotAction validation | `src/sentinel/parser.py::validate_policy` | Validates `NotAction` identically to `Action` (H2 cross-phase fix). |
| Risk analysis | `src/sentinel/analyzer.py::RiskAnalyzer` | Detects wildcards, privilege escalation, data exfiltration, destruction, permissions-management, redundancy; regex patterns compiled at `__init__` (H1-perf). |
| Companion permission detection | `src/sentinel/analyzer.py::CompanionPermissionDetector` | Identifies missing companions (e.g. `lambda:CreateFunction` + `iam:PassRole` + `logs:*`). |
| Intent-to-access-level mapping | `src/sentinel/analyzer.py::IntentMapper` | 8-bucket schema; keyword patterns precompiled in `__init__` (P2-15 α); service patterns precompiled (P2-15 β / H1-perf). |
| HITL Tier-2 approval | `src/sentinel/analyzer.py::HITLSystem` | `--interactive` prompts the operator for approve/reject on every Tier-2 action. |
| Dangerous-action severity escalation | `src/sentinel/analyzer.py::DangerousPermissionChecker` | Resource-aware: wildcard resources on dangerous actions escalate severity. |
| Policy rewriter | `src/sentinel/rewriter.py::PolicyRewriter` | Configurable via `RewriteConfig`: toggle wildcards, resources, companions, conditions, read/write split. |
| Unique Sid generation | `src/sentinel/rewriter.py::_generate_unique_sid` | Numeric-suffix dedup; AWS requires Sid uniqueness within a policy document (Issue 1 / M4). |
| Self-check loop-back | `src/sentinel/self_check.py::SelfCheckValidator` | Re-validates rewrite; if issues remain, loops back to rewriter bounded by `--max-retries` (default 3). |
| Tier-2 preservation | `src/sentinel/self_check.py::_apply_self_check_fixes` | Unknown actions preserved in rewrite; only Tier-3 (INVALID) actions removed. See Amendment 10 in `prod_imp.md § 17`. |
| `--strict` mode | `src/sentinel/self_check.py::Pipeline.run` | Escalates WARNING verdict -> FAIL; restores pre-v0.8.0 safety for Tier-2 presence. |
| Functional-completeness check | `src/sentinel/self_check.py::_check_functional_completeness` | Matches rewrite actions against the original intent's READ keywords (precompiled regex per v0.8.1 U27 / D2). |

## Input sources

Nine source types route through a single `Fetcher` protocol and normalize to a `FetchResult` with `PolicyOrigin` provenance.

| Source | File | Notes |
|--------|------|-------|
| Local file (JSON) | `src/sentinel/fetchers/local.py` | Default for positional `policy_file` argument. |
| Local file (YAML) | `src/sentinel/fetchers/local.py` | `.yaml` / `.yml` auto-detected; `--input-format yaml` forces. |
| Stdin (`-`) | `src/sentinel/cli.py::read_policy_input` | JSON only on stdin. |
| Clipboard | `src/sentinel/fetchers/clipboard.py` | Uses `pyperclip`; WSL falls back to `powershell.exe Get-Clipboard`. |
| URL (`--url`) | `src/sentinel/fetchers/url.py` | HTTPS only by default; runs through the SSRF quartet; cache-backed. |
| GitHub (`--github owner/repo/path`) | `src/sentinel/fetchers/github.py` | Token via `SENTINEL_GITHUB_TOKEN` (pydantic-`SecretStr`). |
| AWS sample page | `src/sentinel/fetchers/aws_sample.py` | Scraped via `selectolax`; domain allow-listed. |
| AWS managed policy | `src/sentinel/fetchers/aws_managed.py` | Local DB only; no network. |
| CloudSplaining examples | `src/sentinel/fetchers/cloudsplaining.py` | Fixture repo on GitHub; cached. |
| Directory batch | `src/sentinel/fetchers/batch.py` | `sentinel run --batch <dir>` iterates all JSON/YAML under DIR. |

Every fetched policy carries a SHA-256 receipt in `PolicyOrigin` (`src/sentinel/models.py`); text / JSON / markdown formatters render the origin badge at the top of every report.

## Output formats

| Format | Flag | File | Notes |
|--------|------|------|-------|
| Text (default) | (none) | `src/sentinel/formatters.py::TextFormatter` | Human-readable; includes origin badge, findings, Tier-2 review block, rewritten policy, force-emit banner. |
| JSON | `--output-format json` | `src/sentinel/formatters.py::JsonFormatter` | Machine-readable; schema below. |
| Markdown | `--output-format markdown` | `src/sentinel/formatters.py::MarkdownFormatter` | PR-comment-ready; blockquote banners for force-emit bypass. |

### JSON output schema (`sentinel run` / `fetch` / `managed analyze`)

| Field | Type | Presence | Description |
|-------|------|----------|-------------|
| `origin` | object | always | `PolicyOrigin` record: `source`, `source_spec`, `sha256`, `fetched_at`, `http_etag` (when applicable). |
| `final_verdict` | string | always | `PASS` / `WARNING` / `FAIL`. |
| `findings` | list[object] | always | RiskFinding records: `category`, `severity`, `statement_index`, `action`, `resource`, `message`. |
| `rewrite_result` | object | when emitted | Rewriter audit trail: `changes`, `assumptions`, `rewritten_statement_count`. |
| `self_check_result` | object | when emitted | `verdict`, `iterations`, `checks`, `suppressed`. |
| `tier2_preserved_actions` | list[string] | always | Unions `TIER2_IN_POLICY` + `TIER2_ACTION_KEPT` (M1 v0.8.1 fix). |
| `rewritten_policy` | object | when not suppressed | The least-privilege policy. Suppressed on FAIL unless `--force-emit-rewrite`. |
| `semantic` | string | when rewrite emitted | `"additions_only"` (operator should MERGE) or `"complete_policy"` (wholesale replace). See Amendment 10. |
| `force_emit_rewrite_bypass` | boolean | when bypass used | `true` when `--force-emit-rewrite` was set. Also present as `bypass_of_failure`: true on FAIL, false on PASS/WARNING (SEC-L4). |
| `bypass_reason` | string | when bypass used | Machine-readable reason string for SIEM correlation. |

## Safety and security

| Feature | File / location | Description |
|---------|-----------------|-------------|
| Fail-closed by default (§ 2 Principle 4) | parser / analyzer / rewriter / self_check | DB errors, HMAC mismatches, ConfigErrors propagate as raises rather than silent demotion (Amendments 8, 10, 11). |
| HMAC row signing | `src/sentinel/hmac_keys.py::sign_row`, `verify_row` | Security-critical rows (`dangerous_actions`, `companion_rules`, `managed_policies`) carry an HMAC-SHA256 signature over the canonicalized row. |
| Domain-separated keys | `src/sentinel/hmac_keys.py` | `K_cache = HMAC(root, b"sentinel-v1/cache")`, `K_db = HMAC(root, b"sentinel-v1/db-row")` per NIST SP 800-108. Compromise of one does not unlock the other (Theme D). |
| HMAC key permission refuse-to-load | `src/sentinel/hmac_keys.py::_load_or_create_root_key` | POSIX `mode & 0o077 != 0` raises `HMACError` with `rotate-key` hint (P2-13 β). Windows skipped. |
| Signed-row probe on regen | `src/sentinel/hmac_keys.py::_db_has_signed_rows` | Auto-regen only when DB has no signed rows; otherwise raises to force operator decision (B2). |
| URL allow-list | `src/sentinel/net/allow_list.py` | Per-source patterns; `--allow-domain` extends ephemerally. |
| Private-IP block | `src/sentinel/net/guards.py::resolve_and_validate` | RFC 1918 + loopback + link-local + metadata IP ranges blocked; NAT64 / 6to4 / Teredo / IPv4-mapped IPv6 extracted and transitively checked (H13). |
| Scheme allow-list | `src/sentinel/net/client.py` | HTTPS by default; HTTP only when explicitly allowed in config. |
| Redirect chaser with per-hop re-validation | `src/sentinel/net/client.py::_follow_redirects` | Every redirect hop re-runs allow-list + SSRF guards (H9). |
| TLS verify toggle | `src/sentinel/net/client.py` | `--insecure` flag (ephemeral; HARD-FAIL in TOML/env); emits unsuppressable `[WARN]` per request. |
| Cache write suppression under `--insecure` | `src/sentinel/net/cache.py::DiskCache.put` | MITM-poisoned HMAC entries cannot persist across sessions (SEC-M3). |
| Max download bytes enforcement | `src/sentinel/net/client.py::_one_attempt` | Preflight on `Content-Length`, post-check on body size; raises `ResponseTooLargeError` (SEC-M1). |
| Retry-After cap | `src/sentinel/net/retry.py::RetryPolicy._wait` | Hostile `Retry-After: 99999` capped to `max_total_wait_seconds` with `retry_after_cap_engaged` log event (SEC-M2). |
| URL credential stripping | `src/sentinel/net/urls.py::strip_url_credentials` | Applied at every structlog URL site so `user:token@host` in `--url` never leaks (SEC-L1). |
| Structured log redaction | `src/sentinel/logging_setup.py::redact_sensitive`, `secrets_patterns.py` | Single-source patterns scrub tokens, API keys, JWTs, Bearer, AWS access keys (M10). |
| Ephemeral-flag HARD-FAIL | `src/sentinel/config.py` | `--insecure`, `--allow-domain`, `--skip-migrations` in TOML/env abort with `ConfigError`. `SENTINEL_SKIP_MIGRATIONS` env is the single carve-out for read-only filesystems. |
| Baseline seed fail-closed | `src/sentinel/cli.py::main` | Seed failure aborts with `EXIT_IO_ERROR` (B3); no fallback to unsigned baseline. |
| WAL mode on first open | `src/sentinel/migrations.py::_activate_wal` | Persistent; handles read/write contention (H27). |
| Pre-migration backup | `src/sentinel/migrations.py::_checkpoint_and_backup` | `PRAGMA wal_checkpoint(FULL)` + `shutil.copy2`; deleted on success, kept on failure with restore instructions (H5). |
| Filelock migration concurrency | `src/sentinel/migrations.py::_with_filelock` | 60s `filelock.FileLock`; double-check revision inside the lock (C5). |
| SQL-injection hardening on `Database.is_empty` | `src/sentinel/database.py::is_empty` | Two-layer defense: whitelist + parameterized `sqlite_master` probe (P1-6 β). |
| Token redaction in `config show` | `src/sentinel/cli_config.py::_coerce`, `src/sentinel/config.py` | `SecretStr` renders as `**********`; no `.get_secret_value()` at render time (L7). |

## Observability

| Feature | File | Description |
|---------|------|-------------|
| structlog configuration | `src/sentinel/logging_setup.py::configure` | `--log-format human|json`, `--log-level DEBUG|INFO|WARNING|ERROR`, `NO_COLOR` / `FORCE_COLOR` env respected. |
| Redact-sensitive processor | `src/sentinel/logging_setup.py::redact_sensitive` | Runs on every log event; consumes `secrets_patterns` single-source list. |
| OpenTelemetry stub | `src/sentinel/telemetry.py::tracer` | Re-resolves the real SDK lazily on span creation; no code change needed when an exporter is installed (I2). |
| Audit-log events (partial) | `net/client.py`, `cli.py`, `self_check.py` | `http_request`, `http_response`, `http_redirect_followed`, `cache_hit`, `cache_hmac_mismatch`, `cache_write_suppressed_insecure`, `retry_after_cap_engaged`, `force_emit_rewrite_bypass`. |
| Origin badge | `src/sentinel/models.py::PolicyOrigin`, formatters | SHA-256 receipt of every fetched policy; rendered at the top of every text/JSON/markdown report (§ 8.4). |
| `ssl_cert_file_audit` | `src/sentinel/logging_setup.py` | Logs which CA bundle TLS verify is using (`SSL_CERT_FILE` env / certifi default). |

## CLI

Sentinel ships 14 subcommands plus `info` / `export-services` / `fetch-examples`.

| Subcommand | File | Notes |
|------------|------|-------|
| `info` | `cli.py::cmd_info` | DB stats, alembic revision, empty-corpus banner. Returns `EXIT_IO_ERROR` on alembic-probe failure (PE2). |
| `validate` | `cli.py::cmd_validate` | Parse + three-tier classify only. |
| `analyze` | `cli.py::cmd_analyze` | Validate + risk analysis. |
| `rewrite` | `cli.py::cmd_rewrite` | Validate + analyze + rewrite. |
| `run` | `cli.py::cmd_run` | Full pipeline. Gains `--batch` + `--fail-fast` + `--force-emit-rewrite`. |
| `refresh --source X` | `cli.py::_cmd_refresh_new_source` | Offline (default) or `--live` via the hardened client. |
| `refresh --all` | `cli.py::_cmd_refresh_all` | Runs all 4 sources in sequence. |
| `fetch` | `cli_fetch.py::cmd_fetch` | 6-source mutually-exclusive group; `--alert-on-new` continuous-monitor. |
| `watch <dir>` | `cli_misc.py::cmd_watch` | `watchfiles` re-validation on change. |
| `wizard` | `cli_misc.py::cmd_wizard` | Interactive intent-to-policy builder; refuses unknown intents (P1-4 α). |
| `compare <a> <b>` | `cli_misc.py::cmd_compare` | Diff two policies' risk profiles. |
| `search "<q>"` | `cli_misc.py::cmd_search` | GitHub Search API (urlencoded per P2-12); token required via env. |
| `cache {stats\|ls\|purge\|rotate-key}` | `cli_cache.py` | `rotate-key --yes` skips confirmation; purges all entries. |
| `managed {list\|show\|analyze}` | `cli_managed.py` | `analyze` inherits `--force-emit-rewrite`. |
| `config {show\|path\|init}` | `cli_config.py` | Resolved settings with secrets redacted; scaffold starter TOML. |
| `export-services` | `cli.py::cmd_export_services` | Emits `data/known_services.json`. |
| `fetch-examples` | `cli.py::cmd_fetch_examples` | Benchmark harness for AWS sample policies. |

### Shared (parent) flags

Applied to every subcommand:

| Flag | Persistable | Notes |
|------|-------------|-------|
| `-d/--database <path>` | CLI-only | Override IAM actions DB path. |
| `-i/--inventory <path>` | CLI-only | Override resource inventory path. |
| `-f/--output-format` | CLI + TOML | `text` (default), `json`, `markdown`. |
| `-o/--output <path>` | CLI-only | Write to file instead of stdout. |
| `--profile <name>` | CLI + TOML | Activate a named config profile. |
| `--config <path>` | CLI-only | Override config file path. |
| `--log-format` | CLI + env + TOML | `human` (default), `json`. |
| `--log-level` | CLI + env + TOML | `DEBUG`, `INFO`, `WARNING`, `ERROR`. |
| `--insecure` | **ephemeral** | HARD-FAIL in TOML / env. |
| `--allow-domain <domain>` | **ephemeral** | HARD-FAIL in TOML / env; repeatable. |
| `--skip-migrations` | **ephemeral + env carve-out** | `SENTINEL_SKIP_MIGRATIONS=1` honored for read-only filesystems (Amendment 6 Theme F3). |
| `--cache-dir <path>` | CLI + TOML | Override cache directory. |

### Subcommand-specific flags (selection)

| Flag | Subcommands | Notes |
|------|-------------|-------|
| `--intent "<text>"` | `analyze`, `rewrite`, `run`, `fetch` | Natural-language rewrite guidance. |
| `--input-format auto\|json\|yaml` | `validate`, `analyze`, `rewrite`, `run` | Default: auto-detect from suffix. |
| `--interactive` | `run` | HITL approve/reject Tier-2. |
| `--strict` | `run` | Escalate WARNING -> FAIL. |
| `--max-retries N` | `run` | Self-check loop-back budget (default 3). |
| `--no-companions` / `--no-conditions` | `rewrite`, `run` | Toggle individual rewrite features. |
| `--policy-type identity\|resource\|scp\|boundary` | `rewrite`, `run` | Default: auto-detect. |
| `--condition-profile strict\|moderate\|none` | `rewrite`, `run` | Condition injection profile. |
| `--allow-wildcard-actions` / `--allow-wildcard-resources` | `rewrite`, `run` | Downgrade wildcard errors to warnings. |
| `--account-id` / `--region` | `rewrite`, `run`, `fetch`, `managed analyze` | ARN generation template vars. |
| `--force-emit-rewrite` | `run`, `fetch`, `managed analyze` | Bypass FAIL-verdict suppression with audit trail (L2 + SEC-L4). |
| `--batch DIR` / `--fail-fast` | `run` | Directory mode; `--fail-fast` stops on first failure. |
| `--alert-on-new` | `fetch` | Hash-compare vs. last fetch; emit WARN on diff. |
| `--source` / `--all` / `--live` / `--dry-run` / `--data-path` | `refresh` | Offline / live mix; see `docs/USAGE.md#refresh`. |
| `--dry-run` | `refresh` | Parse and validate without writing. |

### Exit codes

Single source of truth: `src/sentinel/exit_codes.py`.

| Code | Name | Trigger |
|------|------|---------|
| 0 | `EXIT_SUCCESS` | Clean run; verdict PASS; no warnings. |
| 1 | `EXIT_ISSUES_FOUND` | Verdict WARNING (non-fatal risks). |
| 2 | `EXIT_INVALID_ARGS` | Bad CLI args, unparseable input, `httpx.InvalidURL`. |
| 3 | `EXIT_IO_ERROR` | DB / HMAC / filesystem / migration / alembic probe failure. |
| 4 | `EXIT_CRITICAL_FINDING` | Verdict FAIL (CRITICAL or HIGH severity finding). |

## Configuration

Six-tier precedence (later wins):

1. Shipped `defaults.toml` (inside the package; HARD-FAIL if missing per B4).
2. System TOML -- `/etc/sentinel/config.toml` (Windows `%ProgramData%\sentinel\config.toml`).
3. User TOML -- `~/.config/sentinel/config.toml` (Windows `%APPDATA%\sentinel\config.toml`).
4. Project-local `./.sentinel.toml`.
5. `SENTINEL_*` environment variables.
6. CLI flags.

Profiles live under `[profiles.<name>]` and are activated with `--profile <name>`. The `max_retries` field in a profile fans out to `retries.budgets.{github, aws_docs, user_url}` plus legacy `defaults.max_retries` (P2-9 α).

Secrets (`SENTINEL_GITHUB_TOKEN`, etc.) are wrapped in `pydantic.SecretStr`; `sentinel config show` renders them as `**********` via a `_coerce` helper that calls `str()` (never `.get_secret_value()` -- the contract per L7).

## Database layer

Dual-DB architecture: `iam_actions.db` (mandatory) + `resource_inventory.db` (opt-in).

| Feature | File | Notes |
|---------|------|-------|
| Alembic migrations | `src/sentinel/migrations.py`, `migrations/iam/`, `migrations/inventory/` | Auto-upgrade at CLI entry; safe-stamp branch for pre-Alembic DBs; downgrade() mandatory for every revision (Theme E1). |
| Alembic roundtrip test | `tests/test_alembic_roundtrip.py` | Upgrade -> downgrade -> upgrade produces byte-identical `sqlite_master`. |
| Per-test DB isolation | `tests/conftest.py::migrated_db_template` | Session-scoped template; per-test fast-copy via `shutil.copy2`. See Amendment 9. |
| `Database.is_corpus_populated` | `src/sentinel/database.py::is_corpus_populated` | Used by the empty-corpus banner (Issue 3). |
| Single-connection optimization | `src/sentinel/database.py::_with_conn` helpers | `validate_policy` and `_validate_actions` share one connection across the action loop (P1-8 α+β). |
| Resource inventory | `src/sentinel/inventory.py::ResourceInventory` | Optional; rewriter substitutes placeholder ARNs when inventory is empty. |
| Baseline seeder | `src/sentinel/seed_data.py::seed_all_baseline` | HMAC-signs dangerous actions, companion rules, ARN templates with `source='shipped'`. |

See `prod_imp.md § 6.1` for the full schema DDL + CHECK constraints (H15) and covering indexes (H14, H16).

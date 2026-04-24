# IAM Policy Sentinel — Production Migration Plan

| Field | Value |
|---|---|
| Document | `prod_imp.md` |
| Status | **Draft v7 — FINAL. All investigation amendments (A1–A5) applied; final 7-agent readiness review patches applied as Amendment 6. Implementation-ready.** |
| Date | 2026-04-22 |
| Target delivery | One week |
| Scope | Evolve Sentinel from local-file validator to production-grade CLI with online fetching, config-driven behavior, and zero hardcoded values in Python code |
| Amendments | Applied from `..._critical.md` (A1), `..._high.md` (A2), `..._decisions.md` (A3), `..._medium.md` (A4), `..._low_info.md` (A5), and `prod_imp_final_review.md` (A6) — see § 17. **All 67 original review findings addressed or formally deferred; all 13 final-readiness findings (1 CRITICAL + 12 HIGH) applied as Amendment 6.** D1–D5 resolved; D6 (re2 adoption) tracked as deferred. |

---

## 0. Executive summary

Sentinel today is a local-only IAM policy validator. In one week, it becomes a production-grade CLI that:

- Accepts policies from local files, stdin, URLs, GitHub repositories, a clipboard, or batch directories
- Fetches live data from AWS documentation, AWS sample repositories, CloudSplaining, and policy_sentry
- Reads team preferences from a TOML config file with multi-environment profiles
- Ships **zero values hardcoded in Python** — all values live in the database, in config files, or in shipped `defaults.toml`
- Enforces defense-in-depth security on network fetches (domain allow-list, private-IP blocking, size caps, TLS verification)
- Produces both a terse terminal summary and a detailed JSON/Markdown report artifact
- Supports continuous monitoring via cron and GitHub Actions

No PyPI release. No Docker image. No server mode. No HCL support. CLI-first, install-from-clone, everything else deferred.

---

## 1. Goals and non-goals

### 1.1 Goals

1. Eliminate every hardcoded value in `.py` files. Values move to the database or to TOML config files.
2. Add live fetching of IAM policies from seven source types (see § 4.1).
3. Add config system with TOML, environment variables, CLI flags, and named profiles.
4. Add `pyproject.toml` with `uv`-driven workflow; install via `uv sync` from a repo clone.
5. Add Alembic schema migrations so existing user databases survive upgrades.
6. Add caching, retry/backoff, rate-limit handling, SSRF guards.
7. Preserve backwards compatibility — `python -m sentinel run policy.json` must continue to work identically.
8. Ship a cron script and a GitHub Action template for continuous monitoring.

### 1.2 Explicit non-goals (deferred)

- **No server mode.** HTTP API, daemon mode, webhook receivers are out of scope.
- **No PyPI publishing.** Users clone and run `uv sync`.
- **No Docker image.**
- **No Terraform / HCL parsing.** Users convert HCL to JSON themselves.
- **No boto3.** AWS managed policies are scraped from documentation HTML pages only.
- **No logo, branding, or marketing copy.**
- **No `rich`, `click` or `typer` rewrite of the CLI surface.** The CLI stays pure `argparse`. New nested subcommand groups (e.g., `sentinel cache purge`, `sentinel managed list`, `sentinel config show`) are implemented as argparse subparsers of subparsers with `set_defaults(func=...)` dispatch. `click` is NOT a dependency.

---

## 2. Guiding principles

1. **No values in Python.** Python files contain *structure* (enums, dataclasses, SQL migrations, function definitions). All *values* live in the database, in `defaults.toml`, or in user-supplied config.
2. **Offline-first.** Network is a bonus. The tool must remain fully functional with no internet access, using cached and bundled data.
3. **Backwards compatible CLI.** No existing command is broken; we only add new commands and flags.
4. **Fail-closed on security.** SSL verify on by default, private IP block on by default, allow-list on by default. Escape hatches exist but shout warnings.
5. **Observable by default.** Structured logging and OpenTelemetry hooks are wired in from day one; exporters are optional.
6. **Degrade gracefully.** Missing config, missing cache, missing inventory — all mean "use defaults," never "crash."

---

## 3. Library stack (chosen from agent research)

| Concern | Library | Why picked |
|---|---|---|
| HTTP client | `httpx` | Only option with unified sync + async APIs, clean exception hierarchy for `tenacity` integration, leanest transitive deps |
| Retries | `tenacity` | Composable stop/wait/retry predicates; per-source budgets via `Retrying(...)` iterator; Retry-After support via callable `wait=` |
| HTML parsing | `selectolax` (LexborHTMLParser) | 5–25× faster than `bs4+lxml`, zero transitive deps, clean wheel coverage on Windows/WSL, CSS-selector API |
| Config | `pydantic-settings` | Native TOML reader, `settings_customise_sources` for exact CLI>env>local>XDG>default precedence, typed validation |
| CLI framework | Pure `argparse` with nested subparsers via `set_defaults(func=...)` | Cleanest fit — `cli.py:914–940` already uses this pattern; no new dep; zero existing-test disruption; auto-resolves the previously-proposed click/argparse hybrid underspec |
| Migration locking | `filelock >= 3.20.3` | Cross-process mutex wrapping the one-time Alembic upgrade (cron + GitHub Action + interactive user can all start concurrently). Version pin addresses CVE-2026-22701 |
| Logging | `structlog` | Single switch between `ConsoleRenderer` and `JSONRenderer` for the `--log-format json` flag; native `NO_COLOR` support |
| Testing | `pytest-recording` (VCR.py) + `pytest-httpserver` + `@pytest.mark.live` marker | HTTP-client-agnostic; cassettes for replay, real HTTP server for corner cases, scheduled live tests |
| Build backend | `hatchling` + PEP 735 `[dependency-groups]` | Ubiquitous, zero src-layout quirks, `uv`-native, dev deps kept out of wheel |
| SSRF guards | `httpx-secure` + stdlib `ipaddress` | Resolve-once-and-connect-by-IP pattern closes DNS rebinding; transport-layer integration |
| Telemetry | `opentelemetry-api` only (no SDK) | 50 KB dep, `ProxyTracerProvider` is a genuine no-op; auto-lights-up if user installs SDK + exporter later |
| Migrations | `Alembic` | Industry-standard, auto-upgrade on first run, rollback support, versioned migration history |

**Total new runtime deps:** `httpx`, `tenacity`, `selectolax`, `pydantic-settings`, `structlog`, `httpx-secure`, `opentelemetry-api`, `alembic` (pulls SQLAlchemy transitively, ~3 MB — acknowledged scope cost for migration support), `filelock>=3.20.3`, `tomli-w` (for writing config, tiny) — plus `pyyaml` already present. **`click` removed from stack (see § 1.2).**

**New dev deps:** `pytest-recording`, `pytest-httpserver`, `pytest-cov`, `mypy`, `ruff`.

---

## 4. Architecture overview

### 4.1 Policy input sources (all pass through one normalized pipeline)

| Source | How specified | Phase |
|---|---|---|
| Local file | `sentinel run path/to/policy.json` | Existing |
| Stdin | `cat policy.json \| sentinel run -` | Existing |
| Arbitrary URL | `sentinel fetch --url https://...` (canonical); `sentinel run --url` kept as deprecated alias | Phase 4 |
| GitHub file | `sentinel run --github owner/repo/path/policy.json` | Phase 4 |
| GitHub search | `sentinel search "AssumeRole" --on-github` | Phase 4 |
| AWS docs sample | `sentinel run --aws-sample <name>` | Phase 4 |
| AWS managed policy | `sentinel run --managed AdministratorAccess` | Phase 4 |
| CloudSplaining examples | `sentinel run --cloudsplaining <name>` | Phase 4 |
| Batch directory | `sentinel run --batch ./policies/` | Phase 4 |
| Clipboard | `sentinel run --from-clipboard` | Phase 5 |
| Interactive wizard | `sentinel wizard` | Phase 5 |

All sources produce the same normalized `(policy_text, source_origin_metadata)` tuple, which flows through the existing `Pipeline.run()`.

### 4.2 New directory layout after migration

> **Note:** Amendments 7 (fetchers/refresh relocation) and 10 (Tier-2 preservation semantics) supersede portions of this section. The listing below is historical; actual layout is `src/sentinel/fetchers/` and `src/sentinel/refresh/` with Tier-2 preservation per § 17 Amendment 10.

```
klarna/
├── pyproject.toml                   [NEW]
├── uv.lock                          [NEW — committed]
├── prod_imp.md                      [this file]
├── README.md
├── CLAUDE.md
├── defaults.toml                    [NEW — shipped default config]
├── .github/workflows/
│   └── sentinel-monitor.yml         [NEW — GitHub Action template]
├── scripts/
│   └── sentinel-cron.sh             [NEW — cron template]
├── migrations/
│   ├── env.py                       [NEW — Alembic env]
│   ├── script.py.mako               [NEW]
│   └── versions/
│       ├── 0001_initial_schema.py   [NEW — migrates current DB to Alembic]
│       ├── 0002_add_verb_prefixes.py
│       ├── 0003_add_dangerous_actions.py
│       └── 0004_add_companion_rules.py
├── alembic.ini                      [NEW]
├── src/
│   ├── sentinel/
│   │   ├── __init__.py              [MODIFY — export new classes]
│   │   ├── __main__.py              [keep]
│   │   ├── cli.py                   [MODIFY — add click subcommand groups]
│   │   ├── constants.py             [RESHAPE — only type definitions + exit codes]
│   │   ├── database.py              [MODIFY — add new table methods]
│   │   ├── parser.py                [keep]
│   │   ├── analyzer.py              [MODIFY — read dangerous_actions from DB]
│   │   ├── rewriter.py              [MODIFY — read ACTION_RESOURCE_MAP from DB]
│   │   ├── self_check.py            [MODIFY — add OTel spans]
│   │   ├── inventory.py             [keep]
│   │   ├── formatters.py            [MODIFY — add origin badge to reports]
│   │   ├── config.py                [NEW — pydantic-settings + profiles]
│   │   ├── logging_setup.py         [NEW — structlog + NO_COLOR]
│   │   ├── telemetry.py             [NEW — OTel stub]
│   │   ├── exit_codes.py            [NEW — 5-level exit code scheme]
│   │   └── net/
│   │       ├── __init__.py          [NEW]
│   │       ├── client.py            [NEW — httpx wrapper with SSRF + cache]
│   │       ├── allow_list.py        [NEW]
│   │       ├── cache.py             [NEW — disk cache with per-source TTL]
│   │       ├── retry.py             [NEW — tenacity policies]
│   │       └── guards.py            [NEW — ipaddress SSRF checks]
│   ├── refresh/
│   │   ├── __init__.py              [keep]
│   │   ├── policy_sentry_loader.py  [MODIFY — optionally fetch upstream live]
│   │   ├── aws_docs_scraper.py      [REWRITE — selectolax + live fetch]
│   │   ├── aws_examples.py          [MODIFY — use httpx not gh CLI]
│   │   ├── aws_managed_policies.py  [NEW — scrape AWS managed policy pages]
│   │   └── cloudsplaining.py        [NEW]
│   └── fetchers/
│       ├── __init__.py              [NEW]
│       ├── base.py                  [NEW — Fetcher protocol]
│       ├── url.py                   [NEW]
│       ├── github.py                [NEW]
│       ├── clipboard.py             [NEW]
│       ├── batch.py                 [NEW]
│       ├── aws_managed.py           [NEW]
│       ├── aws_sample.py            [NEW]
│       └── cloudsplaining.py        [NEW]
├── tests/
│   ├── cassettes/                   [NEW — vcrpy recordings]
│   ├── test_config.py               [NEW]
│   ├── test_net_client.py           [NEW]
│   ├── test_net_guards.py           [NEW]
│   ├── test_cache.py                [NEW]
│   ├── test_fetchers/               [NEW — per-fetcher tests]
│   ├── test_alembic.py              [NEW]
│   ├── test_cli_live.py             [NEW — @pytest.mark.live]
│   └── ... (existing tests preserved)
└── data/
    ├── iam_actions.db               [migrated in place by Alembic]
    ├── resource_inventory.db        [keep]
    └── known_services.json          [keep]
```

### 4.3 Files deleted after migration

- `advanced_examples.py`, `persistent_agent.py`, `quickstart.py`, `agent_config.py` — not part of Sentinel; historical experiments
- `verify_phase1.py`, `verify_phase2.py`, `verify_bug_fix.py` — pytest covers all this now
- `requirements.txt` — superseded by `pyproject.toml`
- `PHASE1_COMPLETE.md`, `PHASE2_SUMMARY.md`, `IMPLEMENTATION_SUMMARY.md`, `IMPLEMENTATION_PLAN.md`, `README_IMPLEMENTATION.md`, `DELIVERABLES.md`, `SUMMARY.md`, `INDEX.md` — development artifacts, stale

---

## 5. Configuration system

### 5.1 File format

**TOML.** Python's `tomllib` reads it; `tomli-w` writes it.

### 5.2 Precedence chain (highest wins)

1. CLI flag (e.g., `--max-retries 1`)
2. Environment variable (`SENTINEL_MAX_RETRIES=1`)
3. Project-local config (`./.sentinel.toml`)
4. User config (`$XDG_CONFIG_HOME/sentinel/config.toml`, Windows: `%APPDATA%\sentinel\config.toml`)
5. System config (`/etc/sentinel/config.toml`, Windows: `%ProgramData%\sentinel\config.toml`)
6. Shipped defaults (`defaults.toml` bundled with the package)

**Ephemeral flags — CLI-only (HARD-FAIL enforcement per D2 resolution).** The following flags can ONLY be supplied via CLI (source 1):

- `--insecure` (disable TLS verification)
- `--allow-domain <domain>` (extend allow-list)
- `--skip-migrations` (bypass Alembic auto-upgrade)

**Enforcement:** if any ephemeral key appears in a persistable source (TOML file or environment variable), Settings construction raises `ConfigError` with a message naming the exact source file/env var and the CLI-only replacement. Example:

```
ConfigError: Key 'insecure' is CLI-only and cannot be set in './.sentinel.toml:12'.
Use 'sentinel --insecure <subcommand>' instead. This restriction prevents accidental
persistence of security-sensitive flags (see § 5.2 of the plan).
```

Implemented via `pydantic-settings` `Field(json_schema_extra={"ephemeral": True})` annotation plus a custom `SettingsSource` subclass that **raises** (rather than silently drops) ephemeral keys found in non-CLI sources. The exception is raised before logging is configured, so error goes to `sys.stderr` directly via `print`.

**Rationale:** Sentinel is pre-v1 (no external users), so breaking-change cost is zero. Hard-fail matches Chromium's `--ignore-certificate-errors` persistent-policy rejection, MySQL 8.0's `--skip-ssl` removal, and pydantic-settings' `extra='forbid'` pattern. A committed `.sentinel.toml` with `insecure = true` would silently disable TLS on every CI run — unacceptable for a security tool.

**Env-var carve-out for `SENTINEL_SKIP_MIGRATIONS` (Amendment 6, Theme F3 resolution).** `--skip-migrations` is ephemeral in the CLI sense (never persisted to TOML — HARD-FAIL on TOML presence), but its corresponding env var `SENTINEL_SKIP_MIGRATIONS` IS honored (not hard-failed) because:

1. It is a panic-button for read-only filesystems / Docker `:ro` mounts where a one-off override is legitimately needed.
2. Its scope is operationally narrow (Alembic upgrade only) — it cannot silently disable security posture the way `--insecure` could.
3. Behavior when set: loud `[WARN]` to stderr naming the env var, proceed with upgrade skipped. Never silent.

**Rule formalized:** `--insecure` and `--allow-domain` HARD-FAIL on ANY non-CLI source (TOML OR env). `--skip-migrations` HARD-FAILs on TOML but LOUD-WARN-ACCEPTS on env. `SettingsSource` subclass must encode this per-field.

### 5.3 Profiles

```toml
# ~/.config/sentinel/config.toml

[defaults]
cache_ttl_hours = 24
max_retries = 3
log_level = "INFO"
log_format = "human"

[profiles.dev]
account_id = "123456789012"
region = "us-west-2"

[profiles.prod]
account_id = "123456789012"
region = "eu-west-1"
security_critical_services = ["iam", "sts", "kms", "secretsmanager", "cloudtrail"]
max_retries = 5

[profiles.ci]
log_format = "json"
max_retries = 1
fail_fast = true
```

Switch with `sentinel --profile prod run policy.json`.

### 5.4 Environment variables (complete list)

| Variable | Purpose |
|---|---|
| `SENTINEL_CONFIG` | Override path to config file |
| `SENTINEL_PROFILE` | Default profile name |
| `SENTINEL_DB_PATH` | IAM actions DB path |
| `SENTINEL_INVENTORY_PATH` | Resource inventory DB path |
| `SENTINEL_CACHE_DIR` | Cache directory |
| `SENTINEL_DATA_DIR` | Persistent data dir (HMAC cache-signing key lives at `$SENTINEL_DATA_DIR/cache.key`; defaults to `$XDG_DATA_HOME/sentinel/`) |
| `SENTINEL_SKIP_MIGRATIONS` | Set to `1` to bypass Alembic auto-upgrade on startup (for read-only filesystems / Docker :ro mounts); loud stderr warn emitted when active |
| `SENTINEL_LOG` | Override log file path for the shipped cron script (default: `/var/log/sentinel-cron.log`). Applies only to `scripts/sentinel-cron.sh`, not the CLI itself. |
| `SENTINEL_LOG_LEVEL` | `DEBUG`/`INFO`/`WARNING`/`ERROR` |
| `SENTINEL_LOG_FORMAT` | `human` / `json` |
| `SENTINEL_GITHUB_TOKEN` | GitHub personal access token (rate-limit lift) |
| `NO_COLOR` | Disable terminal colors (standard convention) |
| `FORCE_COLOR` | Force colors even when piped |
| `SSL_CERT_FILE` | Override system CA bundle (corporate MITM proxies) |
| `OTEL_EXPORTER_OTLP_ENDPOINT` | If set and SDK installed, traces activate (user-supplied) |

**AWS credentials (`AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, etc.) are NOT used.** No boto3.

### 5.5 Shipped `defaults.toml` (excerpt)

```toml
[network]
max_download_bytes = 10_485_760        # 10 MB
timeout_seconds = 10
max_redirects = 3
verify_tls = true

[network.allow_list]
domains = [
  "docs.aws.amazon.com",
  "raw.githubusercontent.com",
  "github.com",
  "api.github.com",
  "gist.githubusercontent.com",
  # "registry.terraform.io" removed — contradicts § 1.2 "no HCL" non-goal.
  # Users who need it extend with `--allow-domain registry.terraform.io` per-run or in user config.
]
github_orgs = [
  "aws-samples", "aws-labs",
  "salesforce",      # policy_sentry
  "bridgecrewio",    # CloudSplaining / Checkov
]

[retries.budgets]
github = 5
aws_docs = 3
user_url = 2

[retries]
max_total_wait_seconds = 300

[cache]
ttl_hours_aws_docs = 168               # 7 days
ttl_hours_policy_sentry = 72           # 3 days
ttl_hours_github = 24                  # 1 day
ttl_hours_user_url = 1
size_cap_mb = 500

[pipeline]
max_self_check_retries = 3
fail_fast = false

# M1 resolution: 8-bucket intent schema (was 2 buckets; see analyzer.py:124-174 for current mapping).
# Each bucket declares both `values` (keyword synonyms) and `levels` (AccessLevel enum members).
[intent.keywords.read]
values = ["read-only", "read only", "readonly", "view", "get"]
levels = ["READ"]

[intent.keywords.list]
values = ["list-only", "list", "enumerate"]
levels = ["LIST"]

[intent.keywords.read_write]
values = ["read-write", "rw"]
levels = ["READ", "WRITE"]

[intent.keywords.write]
values = ["write", "modify", "update", "create", "put"]
levels = ["WRITE"]

[intent.keywords.admin]
values = ["admin", "full", "full-access"]
levels = ["LIST", "READ", "WRITE", "PERMISSIONS_MANAGEMENT", "TAGGING"]

[intent.keywords.deploy]
values = ["deploy", "ci/cd", "deployment", "manage"]
levels = ["WRITE", "TAGGING"]

[intent.keywords.tagging]
values = ["tag", "tagging", "label"]
levels = ["TAGGING"]

[intent.keywords.permissions]
values = ["permissions", "grant", "attach-policy"]
levels = ["PERMISSIONS_MANAGEMENT"]

[security]
critical_services = ["iam", "sts", "organizations", "kms"]

[service_name_mappings]
bucket = "s3"
queue = "sqs"
# ... (full current set shipped as defaults; users extend via override)

[parser.limits]
max_json_nesting_depth = 32
max_statements_per_policy = 100
max_document_chars = 10_000
# M14 (ReDoS cap): condition values are capped before any regex match fires in RiskAnalyzer.
# 4096 accommodates legitimate multi-ARN condition lists; per-operator overrides live in [parser.limits.condition].
max_condition_value_chars = 4096

[parser.limits.condition]
# Per-operator caps — tighter bounds for operator types that never legitimately contain long values.
StringEquals = 4096
StringLike = 4096
ArnEquals = 8192           # ARN lists can be long
ArnLike = 8192
Bool = 64
NumericEquals = 128
DateEquals = 128

[condition_profiles.strict]
enabled_keys = ["aws:MultiFactorAuthPresent", "aws:SecureTransport", "aws:SourceIp"]

[condition_profiles.moderate]
enabled_keys = ["aws:SecureTransport"]

[condition_profiles.none]
enabled_keys = []
```

---

## 6. Database schema changes

### 6.1 New tables (Phases 2 and 4)

```sql
-- verb_prefixes: AWS action-name conventions (Get, List, Put, etc.)
CREATE TABLE verb_prefixes (
    prefix TEXT PRIMARY KEY,
    access_category TEXT NOT NULL
        CHECK (access_category IN ('read','write','admin')),
    source TEXT NOT NULL
        CHECK (source IN ('policy_sentry','aws-docs','shipped','managed-policies','cloudsplaining')),
    refreshed_at TIMESTAMP NOT NULL
);

-- dangerous_actions: flag individual actions as privilege-escalation, exfil, destruction, etc.
CREATE TABLE dangerous_actions (
    action_name TEXT NOT NULL,
    category TEXT NOT NULL
        CHECK (category IN ('privilege_escalation','exfiltration','destruction','permissions_mgmt')),
    severity TEXT NOT NULL
        CHECK (severity IN ('CRITICAL','HIGH','MEDIUM','LOW')),
    description TEXT NOT NULL,
    source TEXT NOT NULL
        CHECK (source IN ('policy_sentry','aws-docs','shipped','managed-policies','cloudsplaining')),
    refreshed_at TIMESTAMP NOT NULL,
    PRIMARY KEY (action_name, category)
);
-- H14: covering index for category-first queries (e.g., "find all privilege_escalation actions")
CREATE INDEX idx_dangerous_category ON dangerous_actions(category, action_name);

-- companion_rules: replaces COMPANION_PERMISSION_RULES
CREATE TABLE companion_rules (
    primary_action TEXT NOT NULL,
    companion_action TEXT NOT NULL,
    reason TEXT NOT NULL,
    severity TEXT NOT NULL
        CHECK (severity IN ('CRITICAL','HIGH','MEDIUM','LOW')),
    source TEXT NOT NULL
        CHECK (source IN ('policy_sentry','aws-docs','shipped','managed-policies','cloudsplaining')),
    refreshed_at TIMESTAMP NOT NULL,
    PRIMARY KEY (primary_action, companion_action)
);

-- dangerous_combinations: pairs that are safe alone, dangerous together
CREATE TABLE dangerous_combinations (
    action_a TEXT NOT NULL,
    action_b TEXT NOT NULL,
    severity TEXT NOT NULL
        CHECK (severity IN ('CRITICAL','HIGH','MEDIUM','LOW')),
    description TEXT NOT NULL,
    source TEXT NOT NULL
        CHECK (source IN ('policy_sentry','aws-docs','shipped','managed-policies','cloudsplaining')),
    refreshed_at TIMESTAMP NOT NULL,
    PRIMARY KEY (action_a, action_b)
);
-- H16: covering index for reverse-direction lookups (WHERE action_b = ?)
CREATE INDEX idx_dc_action_b ON dangerous_combinations(action_b, action_a);

-- action_resource_map: replaces rewriter.py ACTION_RESOURCE_MAP
CREATE TABLE action_resource_map (
    action_name TEXT NOT NULL,
    resource_type TEXT NOT NULL,
    PRIMARY KEY (action_name, resource_type)
);

-- arn_templates: replaces rewriter.py ARN_TEMPLATES
CREATE TABLE arn_templates (
    service_prefix TEXT NOT NULL,
    resource_type TEXT NOT NULL,
    arn_template TEXT NOT NULL,
    PRIMARY KEY (service_prefix, resource_type)
);

-- managed_policies: AWS managed policies fetched from docs
CREATE TABLE managed_policies (
    policy_name TEXT PRIMARY KEY,
    policy_arn TEXT NOT NULL,
    policy_document TEXT NOT NULL,   -- full JSON
    description TEXT,
    version TEXT,
    fetched_at TIMESTAMP NOT NULL,
    -- M12 resolution: HMAC-SHA256 of policy_document binds content to signing key (see Task 6a).
    policy_document_hmac TEXT NOT NULL
);
```

**M17 resolution — query discipline for `managed_policies`.** `sentinel managed list` MUST use an explicit column list excluding `policy_document` (~6 MB for 1000 rows):

```sql
SELECT policy_name, policy_arn, description, version, fetched_at
  FROM managed_policies;
```

A `ruff` custom rule (or CI grep) rejects `SELECT * FROM managed_policies` outside of `migrations/versions/` to prevent accidental full-document loads in list queries.

### 6.2 Alembic setup (Phase 2) — no-ORM mode

Sentinel's existing `database.py` uses raw `sqlite3` with no SQLAlchemy ORM. We use Alembic in its supported "no-ORM mode" to avoid introducing an ORM rewrite:

- `alembic init migrations` generates `alembic.ini`, `migrations/env.py`, and `migrations/versions/`.
- **`migrations/env.py` sets `target_metadata = None`.** All migrations are hand-written as raw DDL via `op.execute()` / `op.create_table()` / `op.add_column()`. `autogenerate` is disabled (it requires metadata); migrations are authored by hand.
- **`render_as_batch=True`** is set in `env.py.context.configure(...)`. Required for SQLite — lets Alembic use batch table recreation for `ALTER COLUMN` operations on SQLite < 3.35.
- `0001_initial_schema.py` reflects the current DB structure as "baseline." Existing users with a populated `iam_actions.db` (no `alembic_version` table yet) go through a **safe-stamp branch** in `check_and_upgrade_db()` (see § 6.3): if the `alembic_version` table is absent but data tables exist, we run `alembic stamp head` instead of `upgrade head`.
- Each subsequent migration is one file in `migrations/versions/`.
- **Transitive dep cost:** Alembic pulls SQLAlchemy (~3 MB) even though we don't use the ORM. Accepted; documented in § 3.
- **Schema drift guard:** `database.py::create_schema()` and `0001_initial_schema.py` must stay in lockstep. A Phase 6 test asserts the two produce identical `sqlite_master` output.

**M18 resolution — dual-DB Alembic (inventory DB also under version control).** `resource_inventory.db` gets its own migration tree. `alembic.ini` declares two named configurations:

```ini
[alembic]
databases = default, inventory

[alembic:default]
sqlalchemy.url = sqlite:///data/iam_actions.db
script_location = migrations

[alembic:inventory]
sqlalchemy.url = sqlite:///data/resource_inventory.db
script_location = migrations/inventory
```

`migrations/inventory/versions/0001_initial_inventory.py` baselines the current `resources` table. The same safe-stamp branch applies — users with an existing `resource_inventory.db` (no `alembic_version`) run stamp on first upgrade. **Idempotent no-op if `SENTINEL_INVENTORY_PATH` file is absent** (inventory is an opt-in feature; skip silently if no file).

### 6.3 Auto-upgrade on CLI startup (not in `Database.__init__`)

**Architectural decision:** the migration check runs at **CLI entry**, not in `Database.__init__`. Reason: `Database` is constructed by ~27 tests in `test_database.py` and by library API users (`demo.py`, notebooks) against throw-away paths where migrations are irrelevant. Putting the auto-upgrade in `__init__` would trigger it for every test fixture.

**New module: `src/sentinel/migrations.py`** exposing one function (renamed per M18 dual-DB resolution):

```python
def check_and_upgrade_all_dbs(
    iam_db_path: Path,
    inventory_db_path: Optional[Path] = None,
    skip: bool = False,
) -> None:
    """Called once from cli.main() before any Database()/ResourceInventory() is opened.

    Processes iam_actions.db unconditionally. Processes resource_inventory.db only
    if `inventory_db_path` exists on disk (inventory is an opt-in feature).
    """
```

**Flow:**
1. If `skip` (or `SENTINEL_SKIP_MIGRATIONS=1`): emit loud `[WARN]` to stderr, return.
2. Open a read-only connection (`?mode=ro`). Probe for `alembic_version` table.
3. **Three branches:**
   - **Pre-Alembic DB** (tables exist but no `alembic_version`): re-open read-write under file lock, run `alembic stamp head`, release — one-time migration for existing users.
   - **Up-to-date DB** (`alembic_version.version_num == head`): return immediately.
   - **Behind head**: re-open read-write under file lock, **checkpoint WAL** (`PRAGMA wal_checkpoint(FULL)`) then **create pre-migration backup** (`shutil.copy2(db_path, db_path.with_suffix(db_path.suffix + '.bak'))`), run `alembic.command.upgrade(cfg, "head")`, on success delete the backup; on failure, leave backup in place and emit restore instructions.
4. Acquire file lock at `<db_path>.migrate.lock` via `filelock.FileLock(timeout=60)`. Inside the lock, **double-check** the version before upgrading (another process may have upgraded while we waited).
5. On `FileLockTimeout`: emit clear stderr message ("Another migration in progress — if stuck, delete `<lock path>`") and exit with code 3.
6. Emit one-line stderr notification: `[INFO] upgrading database from revision X to Y...`
7. **First-time WAL initialization** (H27): once the read-write connection is open (either for stamp or upgrade), execute `PRAGMA journal_mode=WAL; PRAGMA synchronous=NORMAL;`. These settings are persistent (written to the DB file header) — no-op on subsequent runs after first application.

**Backup recovery** (on failure path):
- Clear stderr message: `[ERROR] Migration failed at revision X. Restore via: cp <db_path>.bak <db_path>`
- `.gitignore` ships `*.db.bak` and `*.db-wal`, `*.db-shm` patterns so accidental commits are blocked.
- On read-only filesystems (Docker `:ro` mounts): the pre-backup `shutil.copy2` raises `PermissionError` — re-emit as `EXIT_IO_ERROR` (code 3) with `SENTINEL_SKIP_MIGRATIONS=1` hint in the error message.

### 6.4 Refresh semantics (M16 resolution — source-partitioned truncate-and-reload)

`sentinel refresh --source <name> --live` uses **source-partitioned truncate-and-reload inside a `BEGIN IMMEDIATE` transaction** to guarantee atomicity:

```python
with db.get_connection() as conn:
    conn.execute("BEGIN IMMEDIATE")
    conn.execute("DELETE FROM dangerous_actions WHERE source = ?", (source_name,))
    conn.executemany(
        "INSERT INTO dangerous_actions (...) VALUES (?, ?, ?, ?, ?, ?, ?)",
        signed_rows_with_current_timestamp,  # rows already HMAC-signed via Task 6a
    )
    conn.commit()
```

**Cross-process refresh serialization (new `.refresh.lock`):** concurrent `sentinel refresh` invocations (e.g., cron + manual) are serialized via `filelock.FileLock(<db>.refresh.lock, timeout=60)`. Distinct from `<db>.migrate.lock` (C5) so migrations can run while a refresh is queued.

**Vintage exposure (`sentinel info`):** output includes per-source `refreshed_at` so mixed-vintage data is visible:
```
Data sources:
  policy_sentry   — last refreshed 2026-04-20T04:00:00Z (2 days ago)
  aws-docs        — last refreshed 2026-04-19T02:15:00Z (3 days ago)
  managed-policies — never refreshed
```

**Order-of-operations fix for Task 4 / Task 5 (per Agent 2 catch):** WAL mode via `PRAGMA journal_mode=WAL` MUST be active before any `BEGIN IMMEDIATE` refresh transaction runs. Phase 2 task ordering: Task 5 (migrations.py + WAL activation) **before** Task 4 (populate tables). Otherwise a rollback-journal-mode transaction blocks all readers during populate.

**Where `check_and_upgrade_db()` is called from:** `cli.main()`, after argparse `parse_args()` but before subcommand dispatch. It is **skipped for `sentinel --version`, `sentinel --help`, `sentinel config path`** to keep those responsive.

**Library users (D1 resolution — HARD-FAIL / RAISE):** `Database.__init__` **raises `DatabaseError`** (not just warns) when it detects `alembic_version` behind head.

> **v0.8.1 (D2) update:** migration is CLI-entry-only (`cli.main`); library callers should NOT call `check_and_upgrade_db()` directly as it is a private function. If a library embedding is needed, use `Database(path)` against a DB that is already at head revision — the schema-probe path raises a `DatabaseError` with remediation guidance if the DB is stale.

**`:memory:` exemption:** `Database(Path(":memory:"))` and any in-memory SQLite URI (`sqlite:///:memory:`, `file::memory:?cache=shared`) skip the schema-version probe entirely — in-memory DBs have no `alembic_version` table by design. Used by the `refresh` command (three call sites at `cli.py:723/730/743`).

**Error message contract:** the `DatabaseError` raised must include (a) current revision, (b) head revision, (c) exact remediation command. Example:

```
DatabaseError: Schema at revision 'abc123' but head is 'xyz789'.
Call check_and_upgrade_db(db_path) before constructing Database,
or run 'sentinel' CLI which handles the upgrade automatically.
To bypass (read-only filesystems only): set SENTINEL_SKIP_MIGRATIONS=1.
```

**Rationale (per D1 investigation):** Sentinel is a security tool; stale-schema + silent-proceed = CWE-636 "Failing Open". Bulk-load analyzer may read pre-H1 shape → zero findings on risky policy → exit 0. Django's WARN pattern works for web frameworks because downstream column-missing errors surface loudly; for security scanners, the failure is silence. Breakage cost is bounded by Task 0's `make_test_db()` fixture helper and same-PR update of `demo.py`.

**Lock file artifacts:** `.gitignore` ships a `*.db.migrate.lock` pattern. Documentation covers stale-lock recovery (manually delete the lockfile).

---

## 7. CLI surface

### 7.1 Existing commands preserved unchanged

- `sentinel validate <policy>`
- `sentinel analyze <policy>`
- `sentinel rewrite <policy>`
- `sentinel run <policy>`
- `sentinel refresh --source <src>`
- `sentinel info`

### 7.2 New subcommands / subcommand groups

```
sentinel fetch                                     # shorthand: sentinel run --url
sentinel fetch --url <url>
sentinel fetch --github <owner/repo/path>
sentinel fetch --aws-sample <name>
sentinel fetch --aws-managed <name>               # alias of `sentinel managed analyze <name>`
sentinel fetch --cloudsplaining <name>
sentinel fetch --from-clipboard
sentinel fetch --alert-on-new                     # for continuous-monitor mode

sentinel search "<query>" --on-github             # GitHub search → list of candidate policies
sentinel compare <policy-a> <policy-b>            # diff risk profiles
sentinel wizard                                    # interactive intent-to-policy builder
sentinel watch <dir>                               # re-validate on file change

sentinel cache stats
sentinel cache ls
sentinel cache purge
sentinel cache rotate-key                          # § 8.5 HMAC key rotation (wipes cache, regenerates key)

sentinel managed list
sentinel managed show <name>
sentinel managed analyze <name>

sentinel refresh --source aws-docs --live          # new: fetch live
sentinel refresh --source policy-sentry --live
sentinel refresh --source managed-policies --live
sentinel refresh --all --live                      # refresh everything

sentinel config show                               # dump resolved config (L7: redacted)
sentinel config path                               # print path to config being used
sentinel config init                               # scaffold a starter config file
```

### 7.3 New flags on existing commands

The "Persistable" column indicates whether a flag can also be set via config file or env var. Flags marked **No** are CLI-only (see § 5.2 ephemeral flags):

| Flag | Effect | Applies to | Persistable |
|---|---|---|---|
| `--profile <name>` | Activate profile | Root | Yes |
| `--config <path>` | Override config file path | Root | Yes |
| `--log-format human\|json` | Output format | Root | Yes |
| `--log-level DEBUG\|INFO\|WARNING\|ERROR` | Verbosity | Root | Yes |
| `--insecure` | Disable TLS verify (unsuppressable `[WARN]` emitted when active) | Root | **No (ephemeral)** |
| `--allow-domain <domain>` | Extend allow-list per-run | Root | **No (ephemeral)** |
| `--skip-migrations` | Bypass Alembic auto-upgrade on startup | Root | **No (ephemeral)** |
| `--cache-dir <path>` | Override cache directory for this run (§ 8.5) | Root | Yes |
| `--max-retries N` | Override retry budget | `run`, `fetch`, `refresh` | Yes |
| `--batch <dir>` | Batch mode | `run` | Yes |
| `--fail-fast` | Batch: stop on first failure | `run --batch` | Yes |
| `-o <path>` | Detailed report output file | All | Yes |
| `--output-format json\|markdown\|text` | Artifact format | All | Yes |

### 7.4 Exit code scheme (§ J2)

Existing codes 0/1/2/3 keep their current meanings — POSIX shell convention for code 2 (invalid args) is preserved. The new severity-escalation signal lands at code **4**:

| Code | Meaning | Unchanged from today? |
|---|---|---|
| 0 | No findings | Yes |
| 1 | Findings, all WARNING or below | Partially — today 1 also includes critical severity; see note below |
| 2 | Invalid arguments (POSIX convention) | Yes |
| 3 | Sentinel crashed (bad input, DB missing, network failure beyond retries, IO error) | Yes — formerly `EXIT_IO_ERROR`, semantics widened |
| 4 | At least one CRITICAL or HIGH finding | **New** |

**Backwards-compat note:** Today `EXIT_ISSUES_FOUND = 1` fires for findings of any severity. After amendment, code `1` narrows to WARNING-only. Shell scripts using `[[ $? -eq 1 ]]` to catch critical findings will stop firing; they should update to `[[ $? -eq 1 || $? -eq 4 ]]` or `[[ $? -ne 0 && $? -ne 2 && $? -ne 3 ]]`. Document this narrowing loudly in README and any forthcoming CHANGELOG.

**Implementation:** `cmd_analyze` and `cmd_run` share a helper `_verdict_to_exit_code(findings) -> int` to guarantee both commands return the same code for the same policy.

### 7.5 `cmd_config_show` redaction contract (L7 resolution)

`sentinel config show` dumps the resolved config state via `print(tomli_w.dumps(...))` — this code path bypasses the structlog `redact_sensitive` processor (§ 11.1 M10) entirely. To prevent token emission in stdout (e.g., support bundles, screenshots), a parallel SecretStr-based contract applies:

**Rule: all credential-shaped fields in `config.py` MUST be declared `pydantic.SecretStr`.** This covers `github_token`, any future webhook URLs embedded with tokens, API keys, etc. — not just `github_token` specifically. The contract phrasing is deliberately generic to future-proof against new credential fields.

**Render path:**

```python
# config.py
github_token: SecretStr | None = None   # SENTINEL_GITHUB_TOKEN

# cmd_config_show in cli.py
rendered = settings.model_dump()        # SecretStr -> '**********' by default
print(tomli_w.dumps(_coerce(rendered)))

# _coerce helper — stringifies SecretStr via str() so tomli_w accepts it.
# NEVER calls .get_secret_value() — that would defeat the contract.
def _coerce(obj):
    if isinstance(obj, SecretStr):
        return str(obj)                 # "**********" (SecretStr.__str__)
    if isinstance(obj, dict):
        return {k: _coerce(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_coerce(v) for v in obj]
    return obj
```

**Phase 6 regression test:**

```bash
SENTINEL_GITHUB_TOKEN=ghp_fake_0123456789abcdef0123456789abcdef sentinel config show > out.txt
grep -v ghp_fake_0123456789abcdef0123456789abcdef out.txt   # must exit 0
```

**Sharp edge:** `SecretStr` silently reveals its value if any caller does `model_dump_json(context={"serialize_as_any": True})` or `.get_secret_value()`. Keep `cmd_config_show` code and its helpers away from both. Add inline comment at call site.

**Together with M10 (Amendment 4) this forms the complete redaction contract:** structlog output (M10) + config-show stdout (L7). Neither alone is sufficient — they cover different code paths.

---

## 8. Network and security model

### 8.1 URL allow-list

- Domains from `[network.allow_list].domains` and `[network.allow_list].github_orgs`
- User can extend with `--allow-domain foo.com` per-run (CLI-only — ephemeral flag per § 5.2)
- URLs not matching are refused with exit code 3 and a clear error message

**M11 resolution — matching rule (dot-prefix with IDNA normalization):**

```python
def matches_allow_list(host: str, allow_list: Iterable[str]) -> bool:
    # Normalize: lowercase, strip trailing dot, IDNA-encode for Unicode homoglyph defense
    try:
        host_norm = host.lower().rstrip(".").encode("idna").decode("ascii")
    except UnicodeError:
        return False
    for entry in allow_list:
        entry_norm = entry.lower().lstrip("*.").rstrip(".")
        # Exact match OR strict subdomain match (dot boundary, not suffix)
        if host_norm == entry_norm or host_norm.endswith("." + entry_norm):
            return True
    return False
```

**Why not naïve `endswith`:** `evilraw.githubusercontent.com` ends with `raw.githubusercontent.com` as a suffix but is a different domain. Dot-prefix match (`host.endswith("." + parent)`) requires a dot boundary. IDNA normalization defeats Unicode homograph attacks (`раw.githubusercontent.com` with Cyrillic `а`).

### 8.2 Private IP blocking (SSRF)

Implemented via `httpx-secure` (transport-layer) with `ipaddress` stdlib checks:

- **Blocked IPv4 ranges:** `10/8`, `172.16/12`, `192.168/16`, `169.254/16`, `127/8`, `0.0.0.0`.
- **Blocked IPv6 ranges:** `::1/128`, `fc00::/7`, `fe80::/10`, IPv4-mapped IPv6 (`::ffff:0:0/96`), plus tunneling-protocol prefixes (**H13**):
  - `64:ff9b::/96` (NAT64 well-known)
  - `64:ff9b:1::/48` (NAT64 local-use)
  - `2001::/32` (Teredo)
  - `2002::/16` (6to4)
  - For NAT64 and Teredo addresses, the embedded IPv4 is extracted via `ipaddress.IPv6Address.ipv4_mapped` / `.teredo` and run through the IPv4 blocked-range check transitively. IPv6 zone-ID suffixes (`fe80::1%eth0`) are stripped before `ipaddress.ip_address()` parsing.
- **DNS rebinding defense:** resolve hostname once via `socket.getaddrinfo`, validate every resolved IP, pass the literal IP to the HTTP client while preserving `Host:` header for TLS SNI.
- **Redirect validation (H9):** every redirect target URL is re-validated before following. If the `Location` header's hostname is a literal IP (not a hostname), `ipaddress.ip_address()` is run directly against the blocked ranges — the resolve-once DNS flow does not fire on literal IPs, so the literal-IP branch exists to close the redirect-oscillation gap (e.g., `docs.aws.amazon.com → attacker.com (302) → http://169.254.169.254/`). Relative-redirect `Location` values are resolved via `urljoin(original_url, location)` before validation.
- **Scheme guard (H10):** enforced centrally in `net/client.py::fetch()` via `frozenset({"http", "https"})` — runs before DNS/SSRF checks, applies to every fetcher universally, re-fires on every redirect hop.

### 8.3 Input size and parse limits (applied to ALL policies — local, stdin, URL, GitHub, etc.)

- Max download / max file size: **10 MB**
- Max JSON nesting depth: **32**
- Max statements per policy: **100**
- Max document size: **10,000 chars** after JSON parse

**M14 resolution — condition-value character cap.** Before any regex pattern in `RiskAnalyzer` runs against a condition value, the value length is checked against `[parser.limits].max_condition_value_chars` (default 4096) and the operator-specific entry in `[parser.limits.condition]` (see § 5.5). Values exceeding the cap raise `PolicyParserError` with the specific operator name, OR (for non-critical conditions) are truncated and a `[WARN]` is emitted. The `re2` engine (O(n) guaranteed complexity) is deferred — tracked as **D6 open decision**.

**Enforcement order (H12 — pre-parse validation):** the size cap AND the nesting depth cap are enforced **before** `json.loads()` is called. CPython's default recursion limit (~1000) would allow a 9.9 MB payload with 900-level nesting (within the byte cap) to stack-overflow the parser before any depth check fires. The pre-parse guard lives in `parser.py::parse_policy()` at the top of the function:

1. Byte-size check against `[parser.limits].max_document_size` in `defaults.toml`.
2. Balanced-bracket depth counter walks the raw string up to first 20 KB, tracking `[{` / `]}` outside of quoted strings, respecting backslash escapes. If depth > 32 → raise `PolicyParserError` before `json.loads`.
3. Only after those two checks pass does `json.loads` run.
4. Post-parse: statement-count and document-char caps apply against the parsed structure.

`PolicyParser` receives `[parser.limits]` values via config injection at construction time (`PolicyParser(limits: ParserLimits)`), not via module-level constants — allows test fixtures and strict-mode callers to tune independently.

Violation → exit code 3, clear message, no partial processing.

### 8.4 Origin badge

Every report includes:
```
Origin: fetched from https://raw.githubusercontent.com/aws-samples/.../policy.json
        at 2026-04-21T14:33:22Z (cache: MISS)
        SHA-256: abc123...
```

Local files get `Origin: local file at /path/to/policy.json`.

**I1 note (badge semantics):** The SHA-256 attests "what bytes this tool acted on" — it is an *integrity* / *forensic* receipt, not a *provenance* claim. Authenticity is enforced upstream by TLS verification (default-on, § 8.2) + `httpx-secure` + the M15 `SSL_CERT_FILE` audit WARN. A hash match between two Sentinel runs proves identical content was analyzed; it does NOT prove the content came from a particular origin — that claim is TLS's job.

### 8.5 Cache layer

- **Location:** XDG cache dir by default (`$XDG_CACHE_HOME/sentinel/` or `%LOCALAPPDATA%\sentinel\cache\`); overridable via `--cache-dir` or `SENTINEL_CACHE_DIR`
- **Keys:** SHA-256 of canonical URL
- **Storage:** one JSON per entry with `{body, headers, fetched_at, etag, ttl_seconds, hmac_sha256}`
- **Integrity signing (HMAC-SHA256):** every cache entry is HMAC-signed with a per-install secret key. Root key lives at `$SENTINEL_DATA_DIR/cache.key` (defaults to `$XDG_DATA_HOME/sentinel/cache.key`), mode `0o600`, 32 random bytes generated on first run via `secrets.token_bytes(32)`. HMAC input binds the URL hash (cache key) to the body + headers — prevents an attacker from swapping entries. Verification uses `hmac.compare_digest` (constant-time). Signature mismatch invalidates the entry and triggers refetch; a structured-log WARN event is emitted.
- **Domain separation (Amendment 6, Theme D resolution):** the root key is NEVER used directly. Two derived sub-keys are computed via domain-prefixed HMAC per NIST SP 800-108 KDF guidance:
    - `K_cache = HMAC-SHA256(root_key, b"sentinel-v1/cache")` — used for cache entry signatures.
    - `K_db = HMAC-SHA256(root_key, b"sentinel-v1/db-row")` — used for DB row signatures (see Task 6a).
  Rationale: without domain separation, a compromised `K_cache` (low trust — cache-poisoning surface) would also unlock DB-row forgery (high trust — ReDoS injection surface). Derivation happens once per process in `net/cache.py::_derive_keys()`; both sub-keys cached in-memory. Root key file permissions unchanged.
- **HMAC scope — signed DB tables (Theme G1 clarification):** HMAC row signing applies ONLY to the tables whose rows are executed as regex or treated as classification authority: `dangerous_actions`, `companion_rules`, `dangerous_combinations`, and `managed_policies.policy_document` (column `policy_document_hmac`). Reference tables whose values are simple membership lookups (`verb_prefixes`, `arn_templates`, `action_resource_map`) are NOT signed — their attack surface is negligible vs. the O(n_rows × n_startups) verify cost. Total signed-row count is few hundred to ~1k — NOT 15k. The 15k figure elsewhere refers to the `CompanionPermissionDetector.for_action()` cache key space (not HMAC-signed).
- **Graceful degradation:** if `$SENTINEL_DATA_DIR` is unwritable (read-only container, locked-down CI), cache falls back to in-memory only for that process, with a single `[WARN]` on first fetch.
- **Key rotation:** `sentinel cache rotate-key` command wipes the cache and regenerates the key. Documented in README.
- **TTL per source:** 7 days AWS docs, 3 days policy_sentry, 1 day GitHub, 1 hour user URLs
- **Conditional requests:** `If-None-Match: <etag>` on every request; 304 responses extend TTL without counting against rate limits
- **Eviction:** time-bound primary (remove entries past TTL on next cache access), size-bound failsafe at 500 MB (LRU)
- **Commands:** `sentinel cache stats`, `sentinel cache ls`, `sentinel cache purge`, `sentinel cache rotate-key`
- **Known limit:** HMAC defends against local-user file substitution. It does NOT defend against upstream MITM (covered by TLS verify). If `--insecure` is on, a MITM-injected response gets HMAC-signed with our key — appearing "trusted" locally despite being poisoned upstream.

### 8.6 Rate limiting and retries

- **Tenacity** policies with `stop_any(stop_after_attempt(N), stop_after_delay(300))`
- Per-source budgets: GitHub 5, AWS docs 3, user URLs 2
- Retry-After header honored (seconds or HTTP-date)
- Non-retryable 4xx wrapped in `NonRetryableHTTPError` so tenacity passes them through
- `reraise=True` on every decorator so callers see the real exception
- GitHub: require `SENTINEL_GITHUB_TOKEN` for bulk operations (search, batch fetch); allow single fetches without token with a WARNING

### 8.7 JSON output schema for `sentinel run` / `sentinel fetch` / `sentinel managed analyze`

The JSON formatter emits a top-level document with these fields (names stable across v0.8.x):

- `final_verdict`: `"PASS"` / `"WARNING"` / `"FAIL"`.
- `iterations`: self-check loop-back iteration count.
- `pipeline_summary`: human-readable one-line summary.
- `validation`, `tier2_actions_for_review`, `risk_findings`, `rewrite_changes`, `self_check`, `rewritten_policy`: detail blocks (see formatter source).
- **`"semantic"`** (v0.8.0, Amendment 10): `"additions_only"` when the rewrite contains only companion-addition changes (operator should MERGE with original); `"complete_policy"` otherwise (operator can wholesale-replace). Only present when `rewrite_suppressed` is false.
- `rewrite_suppressed`, `rewrite_suppression_reason`: present when self-check FAILed and `--force-emit-rewrite` was NOT passed. `rewritten_policy` is `null` in this case.
- **`"force_emit_rewrite_bypass"`** (v0.8.1, M2): `true` when `--force-emit-rewrite` overrode a FAIL verdict. Accompanied by `"bypass_reason": "self-check FAIL verdict overridden by --force-emit-rewrite"`. Absent when no bypass occurred. Closes OWASP A09 (Security Logging & Monitoring) by giving SIEMs a structural signal for bypass audits.
- `origin`: present for fetched policies; nested `{source_type, source_spec, sha256, fetched_at, cache_status}` block per § 8.4.

---

## 9. Continuous monitoring

### 9.1 Shipped cron script (`scripts/sentinel-cron.sh`)

**Target platform: Linux only (Amendment 6, Theme H resolution).** Uses Linux-specific utilities (`flock` from util-linux, `/tmp` + `/var/log` FHS paths, trap-based exit hooks). macOS users need Homebrew `flock`; Windows users have no equivalent. For cross-platform continuous monitoring, use the GitHub Action template in § 9.2 instead — it's the only supported path on Windows (the primary target per § 14). A future `scripts/sentinel-cron.ps1` (Task Scheduler) may be added post-v0.4.0 based on user demand; no commitment in this spec.

Hardened against concurrent overlap, trap-based exit logging, and log redirection (H20):

```bash
#!/usr/bin/env bash
# Run on a schedule via cron / launchd / Task Scheduler
set -euo pipefail

LOCKFILE=/tmp/sentinel-cron.lock
LOGFILE="${SENTINEL_LOG:-/var/log/sentinel-cron.log}"

# flock concurrency guard: if already running, skip silently rather than stomp
exec 200>"$LOCKFILE"
if ! flock -n 200; then
    echo "[$(date -u +%FT%TZ)] already running; skipping" >&2
    exit 0
fi

# trap captures exit context even on errors
trap 'rc=$?; echo "[$(date -u +%FT%TZ)] exit $rc" >>"$LOGFILE"' EXIT

{
    cd "$(dirname "$0")/.."
    uv run sentinel refresh --all --live
    uv run sentinel run --batch ./policies/ -o reports/$(date +%Y%m%d).json
    uv run sentinel fetch --alert-on-new --managed-policies
} >>"$LOGFILE" 2>&1
```

Users add to crontab: `0 6 * * * /path/to/scripts/sentinel-cron.sh`.

### 9.2 GitHub Action template (`.github/workflows/sentinel-monitor.yml`)

```yaml
name: Sentinel IAM Monitor
on:
  schedule: [{ cron: "0 6 * * *" }]
  workflow_dispatch:
jobs:
  monitor:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: astral-sh/setup-uv@v3
      - run: uv sync --frozen          # L4: fail fast if uv.lock out of sync
      - run: uv run sentinel refresh --all --live
        env: { SENTINEL_GITHUB_TOKEN: "${{ secrets.GITHUB_TOKEN }}" }
      - run: uv run sentinel run --batch ./policies/ --log-format json -o report.json
      - uses: actions/upload-artifact@v4
        with: { name: sentinel-report, path: report.json }

      # H19: failure alerting — create or update a tracking issue on workflow failure
      - name: Notify on failure
        if: failure()
        uses: peter-evans/create-issue-from-file@v5
        with:
          title: "Sentinel monitor failed (run ${{ github.run_id }})"
          content-filepath: report.json
          labels: automation, incident
          # de-dup: same title + label is updated rather than duplicated
```

**Permissions note:** the job needs `permissions: { contents: read, issues: write }` at the workflow level for issue creation via `GITHUB_TOKEN`.

---

## 10. Testing strategy

### 10.1 Three test tiers

| Tier | Marker | When runs | Hits real network? |
|---|---|---|---|
| Unit | none (default) | every PR | No — cassettes or pure Python |
| Corner case | none | every PR | No — `pytest-httpserver` on localhost |
| Live | `@pytest.mark.live` | nightly (GitHub Action) | Yes |

### 10.2 Default `pyproject.toml` config

```toml
[tool.pytest.ini_options]
testpaths = ["tests"]
pythonpath = ["src"]
markers = [
  "live: hits real network; excluded by default",
  "vcr: uses recorded HTTP cassettes",
]
addopts = "-ra --strict-markers -m 'not live' --block-network --record-mode=none"
```

### 10.3 Cassette policy

- Commit cassettes to git under `tests/cassettes/`
- Request-header filtering (applied globally in `conftest.py`): `filter_headers=['authorization', 'x-github-token', 'cookie', 'set-cookie', 'x-api-key']`
- **Response-body scrubbing (H11):** VCR.py `before_record_response` callback runs regex-based redaction on every response body before write. Pattern set (extend as new token formats appear):
  ```python
  SECRET_PATTERNS = [
      r'(AKIA|ASIA)[A-Z0-9]{16}',              # AWS access key / session key
      r'gh[pousr]_[A-Za-z0-9]{36,}',           # GitHub classic / server / user / refresh / OAuth
      r'github_pat_[A-Za-z0-9_]{82}',          # GitHub fine-grained PAT
      r'"aws_secret_access_key"\s*:\s*"[^"]+"',
      r'"session_token"\s*:\s*"[^"]+"',
  ]
  ```
- **Entropy-based backstop:** `detect-secrets` added to `[dependency-groups].dev`; pre-commit hook runs `detect-secrets scan tests/cassettes/` for any miss from the regex list.
- **Extended pre-commit grep patterns:** `AKIA*`, `ASIA*`, `ghp_*`, `gho_*`, `ghs_*`, `ghu_*`, `ghr_*`, `github_pat_*`, `Bearer *`, `aws_secret_access_key`.
- Refresh via `uv run pytest <test> --record-mode=once --no-block-network`.

### 10.4 Performance benchmarks (`tests/test_performance.py`)

- Add new benchmarks for: live fetch latency, cache hit rate, parsing throughput (selectolax vs html.parser comparison)
- **Pipeline latency gates (tiered per H24):**
  - **Phase 2 exit:** full pipeline on a 100-action policy completes in **< 200ms** offline (tight — catches N+1 regression)
  - **Phase 6 steady state:** full pipeline on a 100-action policy completes in **< 300ms** offline
  - **Cache-hit path:** fetch + pipeline completes in **< 2 seconds**
  - **Legacy `MAX_ALLOWED_SECONDS = 60` cap** in `tests/test_performance.py:27` is obsolete — change to `1.0` in the same commit as H1's bulk-load refactor, then to `0.3` in Phase 6 hardening. Never change before H1's bulk-load lands or all 11 perf tests fail immediately.
  - **Measurement discipline:** warm up imports and instantiate Pipeline before timing; run N=5 and take median to reduce cold-CI flakiness.
- **Startup-time target (H25):** `sentinel --version` and `sentinel info` complete in **< 200ms** wall-clock. Measured with `time uv run sentinel --version`. Phase 1 exit criterion enforces this.
- **Lazy-import discipline:** expensive imports (`pydantic_settings`, `structlog`, `alembic`, `opentelemetry`) live inside function bodies or `__init__` methods, never at module level. `sentinel/__init__.py` must be audited for re-exports that pull the entire module graph.
- **Parser comparison benchmark (H26):** `tests/test_performance.py` includes a micro-benchmark pitting `selectolax.LexborHTMLParser` against stdlib `html.parser` on one real AWS docs page (`tests/fixtures/aws_docs_s3.html`). If the gap is < 2×, reconsider whether the native-wheel dep is justified. Benchmark is optional (`pytest-benchmark` in `[dependency-groups].dev`).

---

## 11. Logging and observability

### 11.1 Logging

- **Default:** `structlog.dev.ConsoleRenderer(colors=not NO_COLOR)`
- **`--log-format json`:** `structlog.processors.JSONRenderer()` to stderr
- Processors (in order): `merge_contextvars`, `add_log_level`, `TimeStamper(fmt="iso", utc=True)`, **`redact_sensitive` (M10)**, chosen renderer
- No emojis. Brackets like `[WARN]`, `[ERROR]` are fine in human mode.

**M10 resolution — `redact_sensitive` processor.** Runs BEFORE the renderer so both human and JSON output are scrubbed. Matches key-name deny-list + regex patterns from the shared module (see below). Uses `pydantic.SecretStr` for token-carrying config fields. Must run AFTER `merge_contextvars` so contextvar-bound headers are caught.

```python
# src/sentinel/secrets_patterns.py — NEW shared module
# Single source of truth for M10 log redaction, M22 pre-commit grep, H11 cassette scrubber.
# Amendment 6, Theme A: public API defined below. All three consumers import from here;
# no consumer reimplements scrubbing logic.
from __future__ import annotations
import re
from typing import Any

REDACT_PLACEHOLDER = "**********"

# Case-insensitive deny-list of dict-key / header names whose values are always scrubbed.
REDACT_KEYS: frozenset[str] = frozenset({
    "token", "authorization", "api_key", "api-key", "github_token", "github-token",
    "x-github-token", "secret", "password", "x-api-key", "bearer",
})

# Consolidated regex list — covers every secret format any of the three consumers
# has ever matched. Single list; no per-consumer subset.
SECRET_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r"gh[pousr]_[A-Za-z0-9]{36,}"),                   # GitHub PAT (classic + fine-grained prefix)
    re.compile(r"github_pat_[A-Za-z0-9_]{82}"),                  # GitHub fine-grained PAT (exact length)
    re.compile(r"(AKIA|ASIA|AGPA|AIDA)[A-Z0-9]{16}"),            # AWS access key ID families
    re.compile(r"aws_secret_access_key\s*[:=]\s*[\"']?[A-Za-z0-9/+=]{40}[\"']?", re.IGNORECASE),
    re.compile(r"Bearer\s+[A-Za-z0-9\-._~+/]+=*"),               # RFC 6750 bearer tokens
    re.compile(r"eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]+"),  # JWT triplet
]

# Public API — every consumer MUST call one of these three; no consumer reimplements scrubbing.

def scrub_bytes(body: bytes) -> bytes:
    """Scrub all SECRET_PATTERNS from a response body. Used by H11 VCR cassette scrubber."""
    text = body.decode("utf-8", errors="replace")
    for pattern in SECRET_PATTERNS:
        text = pattern.sub(REDACT_PLACEHOLDER, text)
    return text.encode("utf-8")

def redact_event_dict(_, __, event_dict: dict[str, Any]) -> dict[str, Any]:
    """structlog processor (M10). Signature matches structlog processor protocol.
    Scrubs by dict-key match (REDACT_KEYS) AND by regex on stringified values."""
    for key in list(event_dict.keys()):
        if key.lower() in REDACT_KEYS:
            event_dict[key] = REDACT_PLACEHOLDER
            continue
        val = event_dict[key]
        if isinstance(val, str):
            for pattern in SECRET_PATTERNS:
                val = pattern.sub(REDACT_PLACEHOLDER, val)
            event_dict[key] = val
    return event_dict

def grep_sources(paths: list[str]) -> list[tuple[str, int, str]]:
    """M22 pre-commit hook entry point. Returns [(path, line_no, matched_text), ...]
    for any pattern match across the given file paths. Exits non-zero if list non-empty."""
    # ... implementation walks paths, applies SECRET_PATTERNS line-by-line.
    ...
```

This module is imported by `logging_setup.py` (M10 — calls `redact_event_dict`), the pre-commit hook (M22 — calls `grep_sources`), and VCR cassette scrubbers (H11 — call `scrub_bytes`). **Contract test (Phase 6):** `tests/test_secrets_patterns.py::test_single_source_of_truth` asserts all three call sites import `SECRET_PATTERNS` from this module and no other symbol shadows it.

**M15 resolution — SSL_CERT_FILE audit.** At `cli.main()` startup (BEFORE any network call), if `SSL_CERT_FILE` or `REQUESTS_CA_BUNDLE` is set, emit a structured `[WARN]` logging the SHA-256 of the referenced file. Lets operators audit corporate MITM bundle swaps via SIEM pipelines. Fires AFTER `logging_setup.configure()` so the `redact_sensitive` processor is active.

### 11.2 OpenTelemetry stub

```python
# src/sentinel/telemetry.py
from opentelemetry import trace

# I2: Module-level binding is intentional. `ProxyTracer` (returned by get_tracer
# before the SDK is installed) re-resolves the real tracer provider lazily on
# each span creation. When a user later installs opentelemetry-sdk + an
# exporter, existing module-level `tracer` references automatically pick up
# the real SDK-configured provider — no code changes needed here.
tracer = trace.get_tracer("sentinel")
```

Used in `self_check.py` Pipeline and each fetcher:

```python
with tracer.start_as_current_span("pipeline.validate"):
    validation_results = parser.validate_policy(policy)
with tracer.start_as_current_span("pipeline.analyze"):
    risk_findings = analyzer.analyze_actions(...)
with tracer.start_as_current_span("pipeline.rewrite"):
    ...
with tracer.start_as_current_span("pipeline.self_check"):
    ...
```

`opentelemetry-api` is a runtime dep. SDK and exporter are NOT installed. If a user later installs the SDK + exporter and sets `OTEL_EXPORTER_OTLP_ENDPOINT`, spans activate without code changes.

---

## 12. Phase-by-phase breakdown

Six phases over seven days. Work on `main` directly, commit every ~25 lines.

### Phase 0 — Research sprint (COMPLETE)

All six research agents have reported. Library stack is locked. This plan document is the deliverable.

### Phase 1 — Foundations: packaging + config + logging (Day 1)

**Goal:** the tool runs identically to today, but now has `pyproject.toml`, config loading, and structured logging wired in.

Tasks:
1. Create `pyproject.toml` with hatchling + **complete PEP 621 `[project]` metadata (H17):** `name`, `dynamic = ["version"]` backed by `[tool.hatch.version] path = "src/sentinel/__init__.py"`, `description`, `readme = "README.md"`, `requires-python = ">=3.11"`, `license = "Apache-2.0"`, `authors`, `classifiers`, `[project.urls]` (Repository, Issues), `[project.scripts] sentinel = "sentinel.cli:main"`. **Packages (H3):** `[tool.hatch.build.targets.wheel] packages = ["src/sentinel", "src/refresh", "src/fetchers"]` — all three listed at creation even though `src/fetchers/` is empty until Phase 4. Dev deps via PEP 735 `[dependency-groups].dev`; **also dual-declare in `[project.optional-dependencies].dev` (H18)** for `pip < 23.1` users. Add CI drift-check comparing the two dev-dep lists.
2. Create `uv.lock` via `uv sync` and commit it
3. Delete `requirements.txt`, `advanced_examples.py`, `persistent_agent.py`, `quickstart.py`, `agent_config.py`, `verify_*.py`, stale phase markdowns. **Add to `.gitignore`:** `*.db.bak`, `*.db-wal`, `*.db-shm`, `*.db.migrate.lock`.
4. Create `src/sentinel/config.py` with `pydantic-settings` Settings class, profile support, and source precedence
5. Create `src/sentinel/logging_setup.py` with structlog configuration. **Import-order discipline (H23):** `cache_logger_on_first_use=False` during Phase 1 to allow reconfigure. No module has a top-level `structlog.get_logger()` call — all `get_logger()` calls live inside functions or class `__init__`. Phase 1 exit criterion: `grep -rn 'get_logger()' src/` finds zero module-level (import-time) calls.
6. Create `src/sentinel/telemetry.py` with OTel stub
7. Create `src/sentinel/exit_codes.py` with the 5-level scheme (0/1/2/3/4 — preserves existing `EXIT_INVALID_ARGS=2` and `EXIT_IO_ERROR=3`; adds `EXIT_CRITICAL_FINDING=4`)
8. Create shipped `defaults.toml`
9. Wire `cli.py` to load config via `--profile`, `--config`, `--log-format`, `--log-level` flags — root-level argparse arguments parsed before dispatch, passed to subcommand handlers via the argparse `Namespace` (no `click.Context`; pure argparse). Implement the `_verdict_to_exit_code()` helper shared by `cmd_analyze` and `cmd_run`.
10. Split `constants.py` into `constants.py` (type definitions only — enums, dataclass definitions, exit codes) and move all values into `defaults.toml`. **L6 resolution:** replace the former module-level `KNOWN_SERVICES = load_known_services()` at `constants.py:140` with a lazy-cached helper in `parser.py`:
    ```python
    # parser.py
    from functools import cache

    @cache
    def _known_services() -> frozenset[str]:
        # Deferred Settings construction — import is lazy so that
        # `import sentinel.parser` does not trigger TOML load at import time.
        from .config import get_settings
        return frozenset(get_settings().intent.known_services)
    ```
    All callers in `parser.py` use `_known_services()` instead of the old `_KNOWN_SERVICES` module constant. **Must land in the same commit as the Phase 1.5 `cache_clear()` autouse fixture** — otherwise test isolation silently rots (cached value survives across tests with different Settings monkeypatches). Exit gate: `grep -nE '^[A-Z_]+ *= *load_' src/sentinel/*.py` returns zero matches.
11. **Add README section on pip fallback (H18):** document `pip install -e .` workflow; mention `requirements-frozen.txt` (generated via `uv export --format requirements-txt`) for reproducible pip installs.
12. **Audit `sentinel/__init__.py` (H25):** no re-exports from `analyzer`, `rewriter`, `self_check` at import time — defeats lazy loading. Re-exports move to lazy `__getattr__` or get removed.
13. **M20 Python runtime version check.** Add 8-line guard at TOP of `src/sentinel/__main__.py` AND `src/sentinel/__init__.py` BEFORE any third-party import:
    ```python
    import sys
    if sys.version_info < (3, 11):
        sys.stderr.write(f"Sentinel requires Python 3.11+; found "
                         f"{sys.version_info.major}.{sys.version_info.minor}.\n"
                         f"Recreate venv: 'uv venv --python 3.11 && uv sync'\n")
        sys.exit(3)
    ```
    Catches pip-fallback users (H18) on pip < 23.1 who bypass `requires-python` metadata. `sentinel info` output surfaces `python_version`.
14. **M10 shared `secrets_patterns.py` module** — new `src/sentinel/secrets_patterns.py` (imported by M10 structlog processor, M22 pre-commit hook, H11 cassette scrubber). Single source of truth for redaction patterns.
15. **M15 SSL_CERT_FILE audit WARN** in `cli.main()` — emits structured log with SHA-256 of bundle file if env var set. Runs AFTER logging configured, BEFORE subcommand dispatch.
16. **[NEW — Amendment 6, Theme J: type-hint + import-discipline style rule]** Every new `.py` file in `src/` added from Phase 1 onwards follows these rules:
    - **PEP 604 unions:** use `X | None`, `int | str`, etc. Never `Optional[X]` or `Union[X, Y]` in new code. (`requires-python = ">=3.11"` makes this safe at runtime everywhere.)
    - **`from __future__ import annotations`:** mandatory at the top of every file EXCEPT `config.py` and any other pydantic v2 model file — pydantic's `Field(...)` validators rely on runtime annotation evaluation, and PEP 563 deferred-eval interacts badly with pydantic's `model_rebuild()` flow. Add explicit inline comment `# NOTE: no 'from __future__ import annotations' — pydantic v2 model file` at the top of such files.
    - **Ruff enforcement:** `pyproject.toml` `[tool.ruff.lint]` adds `select = ["UP007", "UP045", "FA102"]` (PEP 604 rewrite rules + future-annotations presence). `per-file-ignores` excludes pydantic model files from `FA102`.
    - **Legacy files:** existing Phase-0 modules (`analyzer.py`, `rewriter.py`, `parser.py`, etc.) are converted file-by-file in the same PR that otherwise touches them — not wholesale. No separate "style migration" PR.

Exit criteria:
- `uv sync && uv run sentinel info` works
- `uv run sentinel --log-format json run policy.json` emits JSON to stderr
- `time uv run sentinel --version` completes in **< 200ms** (H25)
- `grep -rn 'get_logger()' src/` finds zero import-time calls (H23)
- All existing 519 tests still pass
- `pytest -m "not live"` runs clean

### Phase 1.5 — Test infrastructure prep (Day 1 evening / Day 2 morning)

**Goal (from D-investigation Agent 3 ripple analysis):** make the test suite safe for `pytest-xdist` parallel execution before Phase 2 introduces `.migrate.lock`, `cache.key`, and `*-wal` sidecar files that create per-worker shared-state contention.

Tasks:
1. **Per-worker `SENTINEL_DATA_DIR`:** conftest fixture sets `os.environ["SENTINEL_DATA_DIR"]` to `tmp_path_factory.mktemp(f"sentinel-{worker_id}")` so each xdist worker has its own `cache.key` file. Prevents D4 HMAC key races.
2. **Session-scoped migration fixture:** `@pytest.fixture(scope="session") def migrated_db_template(...)` creates one stamped-at-head DB per worker session, cached on disk. Individual tests get a fresh copy via `shutil.copy2(template, tmp_path / "test.db")` — avoids 519 tests × N workers × per-test migration cost.
3. **Filelock timeout handling in fixtures:** if `check_and_upgrade_db()` hits a `FileLockTimeout` during test setup, fail the individual test with a clear message rather than the worker crashing.
4. **Shared fixture helpers** in a new `tests/conftest.py` export: `make_test_db()` (D3 Task 0 dependency), `signed_db_row()` (D4 Task 6a dependency — returns a correctly-HMAC-signed row for test fixtures).
5. **L6 cache-isolation fixture (autouse, session-scoped):** clears the `@functools.cache` on `parser._known_services()` between tests that mutate Settings, preventing cross-test pollution:
    ```python
    # tests/conftest.py
    import pytest
    @pytest.fixture(autouse=True)
    def _clear_known_services_cache():
        yield
        from sentinel.parser import _known_services
        _known_services.cache_clear()
    ```
    **Atomic sequencing constraint:** this fixture and the L6 lazy loader in Phase 1 Task 10 must land in the same commit — not separately. If the loader ships without the fixture, tests pass locally but fail under xdist with stale cached frozensets.

Exit criteria:
- `uv run pytest -n 4 tests/` (four xdist workers) runs clean with zero lock-timeout flakes across five consecutive runs.
- `tests/conftest.py` exports `make_test_db` and `signed_db_row` helpers.
- CI workflow uses `pytest-xdist` via `-n auto` to validate across varied worker counts.

### Phase 2 — Alembic + DB schema refactor (Day 2)

**Goal:** schema is versioned, values previously hardcoded in Python now live in DB tables. **No `.py` file contains a list/dict of AWS action names or policy data** after this phase completes.

**Ordering constraint — read carefully.** Task 0 (preparatory test fixtures) must land in its own commit BEFORE tasks 4–7 touch production code; otherwise CI goes red for an extended period as ~30 tests in `test_analyzer.py` and `test_self_check.py` assume class-level constants exist.

**Execution order vs. task numbering (Amendment 6, Theme B clarification).** Task numerals below are NOT in execution order — they preserve reviewer-traceability back to amendment logs (§ 17). The actual execution order is:

```
Task 0  →  1  →  2  →  3  →  3a  →  5  →  4  →  6 + 6a (atomic)  →  7  →  8  →  8a  →  8b  →  9
(prep)    (alembic)      (NEW)  (migrations,   (populate,    (analyzer+HMAC)  (rewriter) (constants) (char-cap) (D3 hardfail) (perf gate)
                                 WAL active)    post-WAL)
```

Task 5 (migrations + WAL activation) runs BEFORE Task 4 (populate tables) — M16 fix, see § 6.4. Task 3a (Amendment 6, Theme E) is a new inventory-DB baseline insertion required for dual-DB Alembic. Tasks 8a + 8b are a split introduced by Amendment 6 (Theme B2): 8a is the char-cap enforcement alone (independent), 8b is the D3 HARD-FAIL cutover (depends on Task 8's `constants.py` reshape being complete).

Tasks (ordered):

0. **[Preparatory — re-scoped per D-investigation Agent 2 crash-window catch]** Add DB fixtures to **every test site** that calls `RiskAnalyzer(None)`, `Pipeline(None)`, `CompanionPermissionDetector(None)`, or `Database(tmp_path / "x.db")`. Agent 3 grep found **99 call sites across 6 files** (original estimate of ~30 was low). Introduce a shared `make_test_db(tmp_path)` helper (via Phase 1.5 conftest) that creates a fresh DB + stamps it at head. Update all 99 cases. Also update `demo.py:260` to call `check_and_upgrade_db(DB_PATH)` before `Database(DB_PATH)` (pairs with D1 RAISE resolution). **Do NOT delete `COMPANION_RULES` class-body dict comprehension in Task 0** — deferred to Task 6 below. (Original plan deleted `COMPANION_RULES` in Task 0; Agent 2 caught that `detect_missing_companions()` at `analyzer.py:843` would crash with `AttributeError` between Task 0 and Task 6 commits. Deferring deletion to Task 6 aligns the class-to-instance conversion atomically.) No production code changes — this PR lands first and remains CI-green.
1. Add `alembic.ini`, `migrations/env.py` with `target_metadata = None`, `render_as_batch=True` (see § 6.2).
2. Create `0001_initial_schema.py` matching the current `database.py::create_schema()` output byte-for-byte. Include a Phase 6 drift-test that asserts `sqlite_master` is identical between a fresh-schema DB and a migrated DB.
3. Create `0002_add_verb_prefixes.py`, `0003_add_dangerous_actions.py`, `0004_add_companion_rules.py`, `0005_add_dangerous_combinations.py`, `0006_add_action_resource_map.py`, `0007_add_arn_templates.py`, `0008_add_managed_policies.py`. All migrations use `INSERT OR IGNORE` for idempotency. **CHECK constraints (H15):** every `source`/`category`/`severity`/`access_category` column declares `CHECK(... IN (...))` — see § 6.1 for exact constraint values. **Covering indexes (H14, H16):** `idx_dangerous_category(category, action_name)` in `0003_*`; `idx_dc_action_b(action_b, action_a)` in `0005_*`. **Downgrade mandate (Amendment 6, Theme E1):** every migration file — including `0001_initial_schema.py`, `0003b_sign_existing_rows.py`, and every file in this task list — MUST include a working `downgrade()` function that reverses its `upgrade()` (reverse-DDL; for `INSERT OR IGNORE` data migrations, record primary keys added in a helper table or emit no-op downgrade with comment). Phase 6 regression test `tests/test_alembic_roundtrip.py::test_upgrade_downgrade_upgrade` runs the full chain `upgrade head → downgrade base → upgrade head` against both `iam_actions.db` and `resource_inventory.db` and asserts byte-identical `sqlite_master` dumps between the two `upgrade head` endpoints. Without this, the § 14 dual-DB saga mitigation ("iam first; on inventory failure, downgrade iam to prior revision") is unexecutable.

3a. **[NEW — Amendment 6, Theme E2]** Create `migrations/inventory/versions/0001_initial_inventory.py` baselining the current `resources` table from `src/sentinel/inventory.py::create_schema()` output byte-for-byte. This is the inventory-DB Alembic baseline — without it, `alembic -c alembic.ini -n inventory stamp head` fails with "can't locate revision" when `check_and_upgrade_all_dbs()` probes an existing inventory DB (M18 dual-DB path). Include a `downgrade()` that drops all tables created by `upgrade()`. Phase 6 drift-test also covers this migration (sqlite_master identity against a fresh `ResourceInventory()` schema).
5. **[Reordered per M16 fix — must precede Task 4.]** Create `src/sentinel/migrations.py` with `check_and_upgrade_all_dbs(iam_db, inventory_db=None, skip=False)` — the staged check/safe-stamp/upgrade flow from § 6.3, now supporting dual-DB (M18). Wire it into `cli.main()` after argparse, before subcommand dispatch. Skip for `--version`, `--help`, `sentinel config path`. **Pre-migration backup (H5):** `shutil.copy2()` before `upgrade` with `PRAGMA wal_checkpoint(FULL)` first (H5/H27 interaction); delete on success; keep on failure with stderr restore instructions. **WAL mode (H27):** execute `PRAGMA journal_mode=WAL; PRAGMA synchronous=NORMAL;` once in the read-write branch (persistent; no-op on subsequent runs). **M18 dual-DB:** process `resource_inventory.db` with identical safe-stamp/upgrade flow if its path exists on disk; idempotent no-op if absent.
4. **[Now runs AFTER Task 5 per M16/Agent 2 fix.]** Populate new tables from current Python constants as "baseline" data via dedicated data-migration scripts. Uses the M16 source-partitioned truncate-and-reload pattern (§ 6.4) inside `BEGIN IMMEDIATE` transactions — safe because WAL is active by Task 5. All refresh writers use the exact constrained `source` string literals (per CHECK constraint in § 6.1).
6. Refactor `analyzer.py` to bulk-load classification tables at `RiskAnalyzer.__init__` and `CompanionPermissionDetector.__init__`. Class-level constants become instance-level frozensets/dicts. Regex patterns pre-compiled at load. **No per-action SQL** — the hot path remains O(1) dict/set membership (bulk-load pattern). Consider `functools.cache` on `CompanionPermissionDetector.for_action()` for the companion-lookup key space (>15k possible actions). **Migration-script regex validation:** the data-migration script that populates `dangerous_actions` / exfiltration pattern rows must `re.compile()` each regex at migration time to fail-fast on bad patterns (H1 ReDoS injection surface mitigation). **Delete `COMPANION_RULES` class-body dict comprehension** at `analyzer.py:807-816` in this same commit — deferred from Task 0 to avoid crash window (see D-investigation Agent 2 finding). Mark surviving class-level constants (`PRIVILEGE_ESCALATION_ACTIONS`, `DATA_EXFILTRATION_PATTERNS`, `DESTRUCTION_PATTERNS`, `PERMISSIONS_MGMT_PATTERNS` at `analyzer.py:378-436`) with inline comment `# [PHASE2-TRANSITIONAL] delete in Task 8` — these fall out naturally when Task 8 strips `constants.py`.
6a. **[D4 resolution — MUST land in the SAME COMMIT as Task 6]** Implement HMAC-SHA256 signing for DB rows that contain regex patterns, policy documents, or classifications. Adds `row_hmac TEXT NOT NULL` column to `0003_add_dangerous_actions.py`, `0004_add_companion_rules.py`, `0005_add_dangerous_combinations.py`, **and `0008_add_managed_policies.py` (M12 resolution — column name `policy_document_hmac`)**. Signing uses the per-install key at `$SENTINEL_DATA_DIR/cache.key` (same key introduced in C6 for cache HMAC — shared key file, separate usage context). Verification runs at bulk-load time in `RiskAnalyzer.__init__` (Task 6); mismatch raises `DatabaseError` with the specific row's primary key for forensic replay. Paired migration `0003b_sign_existing_rows.py` signs any pre-existing unsigned rows on first upgrade. **Commit-coupling rule (overrides the "commit every ~25 lines" default for this pair):** Task 6 + Task 6a are one atomic commit. Pre-commit hook guard: if any `migrations/versions/0003_*.py` changed, the diff must contain `row_hmac` column and HMAC signing logic or the commit is rejected. Without this, there's an exploitable window where regex-in-DB is live but unsigned — attacker with disk write access injects ReDoS patterns.

7. Refactor `rewriter.py` to bulk-load `ACTION_RESOURCE_MAP` and `ARN_TEMPLATES` from DB at `PolicyRewriter.__init__`.
8. Refactor `constants.py` — remove `COMPANION_PERMISSION_RULES`, `SERVICE_NAME_MAPPINGS`, `SECURITY_CRITICAL_SERVICES`, `REGION_LESS_GLOBAL_SERVICES`, `READ_INTENT_KEYWORDS`, `WRITE_INTENT_KEYWORDS`, verb prefixes. Non-value content (enum definitions, exit codes, type aliases) stays. **Also remove `IntentMapper.INTENT_KEYWORDS` class-level dict** at `analyzer.py:124-174` (M1) — `IntentMapper.__init__` now loads the 8-bucket schema from `defaults.toml` `[intent.keywords.*]` via config injection. Regression test: golden-output snapshots for `wildcard_overuse.json` and `missing_companions.json` fixtures lock intent-to-rewriter mapping across the reshape.

8a. **[M14 char-cap enforcement — Amendment 6, Theme B2: independent; no ordering dep on Task 8]** In `analyzer.py::RiskAnalyzer._check_conditions()`, insert the per-operator length check BEFORE any regex call:
    ```python
    op_cap = config.parser.limits.condition.get(operator, config.parser.limits.max_condition_value_chars)
    if len(condition_value) > op_cap:
        raise PolicyParserError(f"Condition value for '{operator}' exceeds {op_cap} chars (ReDoS defense). See § 8.3.")
    ```
    Placement is critical: AFTER statement-count/document-char caps from § 8.3 (those caps belong to `parser.py`), BEFORE regex execution in analyzer hot path. Also remove the transitional class-level constants in `analyzer.py:378-436` that were marked `# [PHASE2-TRANSITIONAL]` by Task 6. This task may land in its own commit before Task 8 completes — it does not depend on the `constants.py` reshape.

8b. **[D3 HARD-FAIL cutover — Amendment 6, Theme B2: blocked by Task 8]** After Task 8 lands (i.e., all class-level fallbacks in `analyzer.py` are file-deleted), `RiskAnalyzer(None)` raises `DatabaseError("RiskAnalyzer requires a non-None Database; construct via Database(path).")` — construction with a `None` database is now a programming error because there are no class-level fallbacks left to read from. Before Task 8 lands, the transitional CLASS-LEVEL FALLBACK state (c) exists automatically — the class constants are still present. The D3 transition is therefore enforced structurally by file-level deletion, not by a separate guard. Also update `cmd_analyze` / `cmd_run` in `cli.py` to catch `DatabaseError` from `RiskAnalyzer(db)` when `resolve_database()` returned None, and map to `EXIT_IO_ERROR` (code 3) with a clear stderr message. **Ordering:** Task 8b cannot land before Task 8; pre-commit hook rejects a diff that adds the `DatabaseError` raise if `analyzer.py` still contains any `PRIVILEGE_ESCALATION_ACTIONS` / `DATA_EXFILTRATION_PATTERNS` / `DESTRUCTION_PATTERNS` / `PERMISSIONS_MGMT_PATTERNS` class-level constants.
9. **Performance gate change (H24):** in the same commit as task 6 (bulk-load refactor), change `tests/test_performance.py:27`'s `MAX_ALLOWED_SECONDS` from `60` to `1.0`. Do NOT change this constant before task 6 — all 11 perf tests fail immediately if the gate tightens before the bulk-load lands.

Exit criteria:
- Preparatory task 0 has landed and CI is green on the main branch.
- No `.py` file contains a list/dict of AWS action names, service prefixes, or policy data (spot-check via `grep`).
- `sentinel info` shows the Alembic revision.
- `pytest -m "not live"` passes; coverage not reduced.
- Pipeline on a 100-action policy completes in < 200ms offline (tighter than the `< 1s` § 10.4 ceiling — validates the bulk-load pattern actually prevents N+1).
- WAL mode confirmed active: `sqlite3 data/iam_actions.db "PRAGMA journal_mode"` returns `wal`.

### Phase 3 — Network core (Day 3)

**Goal:** a hardened HTTP client we can point at anything.

Tasks:
1. `src/sentinel/net/allow_list.py` — config-driven domain allow-list
2. `src/sentinel/net/guards.py` — `ipaddress` SSRF checks. **SSRF quartet (H9/H10/H13/M11) lands as one coordinated commit:** scheme allow-list (`frozenset({"http", "https"})`), DNS resolve-once + validate-all-IPs, literal-IP redirect validation, NAT64/Teredo/6to4 blocked ranges, IPv6 zone-ID stripping, relative-redirect `urljoin`, **dot-prefix allow-list matching with IDNA normalization (M11)**. See § 8.1 and § 8.2 for full spec.
3. `src/sentinel/net/retry.py` — tenacity policies with per-source budgets
4. `src/sentinel/net/cache.py` — disk cache with per-source TTL, ETag support, size cap, eviction
5. `src/sentinel/net/client.py` — unified wrapper around `httpx-secure.httpx_ssrf_protection` + cache + retries + streaming size cap. **Scheme guard runs before any I/O (H10).** Return type is `FetchResponse(body: bytes, headers: dict, cache_status: Literal["HIT", "MISS", "REVALIDATED"], origin_sha256: str)` — the shape contract Phase 4 fetchers depend on.
6. Tests: unit via pytest-recording, corner cases via pytest-httpserver (429, Retry-After, truncated, redirect chain overflow, SSRF hit on `169.254.169.254`, literal-IP redirect hop, NAT64-prefix IPv6, `file://` scheme rejection, relative-redirect resolution)
7. `sentinel cache stats|ls|purge` subcommands
8. **Pipeline DI slot (H2):** `Pipeline.__init__(database=None, inventory=None, config: Optional[PipelineConfig] = None)` accepts an optional injected config; `run()` prefers `self.config` over a fresh local default. Library users get a clean injection point without monkeypatching. OTel tracer remains module-level in `telemetry.py`.

Exit criteria:
- **Phase 3 smoke test (H4 rescoped — no CLI dependency):** `pytest -m live tests/test_net_client.py::test_phase3_smoke_s3_docs` passes — first call returns `cache_status == "MISS"`, second call returns `cache_status == "HIT"` within 2 seconds, `sentinel cache stats` shows 1 entry on-disk.
- SSRF test: fetching `http://169.254.169.254` fails fast with exit 3.
- SSRF triad integration test: `docs.aws.amazon.com → attacker.com (302) → http://169.254.169.254/` chain is rejected at the redirect hop — H9 literal-IP branch fires.
- NAT64 test: hostname resolving to `64:ff9b::169.254.169.254` is rejected — H13 embedded-IPv4 extraction fires.
- Rate-limit test: two 429 responses followed by success, total wait 3 seconds, succeeds.
- Scheme test: `sentinel fetch --url file:///etc/passwd` rejected at parse-time by `net/client.py` (H10).

### Phase 4 — Source-specific fetchers (Day 4)

**Goal:** the nine input modes from § 4.1 all work.

Tasks:
1. `src/fetchers/base.py` — `Fetcher` protocol: `fetch(spec) -> (policy_text, origin_metadata)`
2. `src/fetchers/url.py` — generic URL fetcher
3. `src/fetchers/github.py` — `owner/repo/path@ref` resolver → `raw.githubusercontent.com`
4. `src/fetchers/aws_sample.py` — names mapped to aws-samples repo paths
5. `src/fetchers/aws_managed.py` — scrape managed policy doc pages using selectolax
6. `src/fetchers/cloudsplaining.py` — bridgecrewio/cloudsplaining example policies
7. `src/fetchers/clipboard.py` — **M7 resolution: `pyperclip>=1.9`** as runtime dep (added to § 3). Detects headless env (no `DISPLAY`/`WAYLAND_DISPLAY`) → raises `ClipboardUnavailable` with actionable message. WSL-native `clip.exe` path auto-detected via `/proc/version` containing `microsoft`. Tests use `pytest.importorskip("pyperclip")` + mock paste for headless CI.
8. `src/fetchers/batch.py` — directory walker, continue-on-error, summary
9. Rewrite `src/refresh/aws_docs_scraper.py` to use selectolax and fetch live
10. Update `src/refresh/aws_examples.py` to use httpx (drop `gh` CLI dep)
11. New `src/refresh/aws_managed_policies.py` and `src/refresh/cloudsplaining.py`
12. Wire `sentinel fetch`, `sentinel managed`, `sentinel refresh --live` commands. **Also back-fill `sentinel run --url <url>` (H7) as a deprecated alias** that delegates to `cmd_fetch` with a `[WARN] 'sentinel run --url' is deprecated; use 'sentinel fetch --url'` message to stderr. Preserves § 4.1 table "Arbitrary URL" workflow under both names during the deprecation window. **M3 resolution:** `sentinel refresh --source X` argparse uses `add_mutually_exclusive_group(required=True)` pairing `--data-path` and `--live`. New source choices: `managed-policies`, `cloudsplaining`.

13. **[Models cluster — M4 + M5]** Create `src/sentinel/models.py` with two frozen dataclasses:
    ```python
    @dataclass(frozen=True)
    class PolicyOrigin:
        kind: Literal["local", "stdin", "url", "github", "managed", "cloudsplaining", "clipboard", "batch"]
        location: str
        fetched_at: datetime | None = None
        cache_status: Literal["HIT", "MISS", "REVALIDATED", "N/A"] = "N/A"
        sha256: str | None = None

    @dataclass(frozen=True)
    class PolicyInput:
        text: str
        origin: PolicyOrigin
    ```
    `Fetcher.fetch(spec) -> PolicyInput` (typed, replacing the untyped tuple). `Pipeline.run(policy_input: PolicyInput, config: PipelineConfig | None = None)` — signature change from `policy_json: str`. Add thin `Pipeline.run_text(policy_json: str)` wrapper for backwards-compat (wraps into `PolicyInput(text=..., origin=PolicyOrigin(kind="local", ...))`). `formatters.py` renders origin badge from `PolicyOrigin` across json/markdown/text output modes (§ 8.4 badge format fixed). **Same PR regenerates `DEMO.md`** to match new badge schema (M8 byte-identical regression check will fail otherwise).

14. **[M17 managed_policies query discipline]** Implement `Database.list_managed_policies() -> list[ManagedPolicySummary]` with explicit column list `SELECT policy_name, policy_arn, description, version, fetched_at` (excludes `policy_document` to avoid ~6MB memory load). `sentinel managed show <name>` uses the separate full-document query. Add `ruff` custom rule (or CI grep) against `SELECT * FROM managed_policies`.

Exit criteria:
- `sentinel fetch --url https://...` runs full pipeline on fetched content with origin badge
- `sentinel managed analyze AdministratorAccess` works end-to-end
- `sentinel run --batch ./tests/fixtures/test_policies/` processes all 8 fixtures, produces one combined report
- `sentinel refresh --all --live` refreshes every table from live sources

### Phase 5 — CLI polish + monitoring + reporting (Day 5)

**Goal:** the tool is pleasant to use in production workflows.

Tasks:
1. `sentinel search "query" --on-github` implementation
2. `sentinel compare <a> <b>` — diff two pipeline results
3. `sentinel wizard` — argparse subcommand with an internal interactive loop (plain `input()` / `print()`) → intent → rewriter. No `click` dependency.
4. `sentinel watch <dir>` — **M6 resolution: `watchfiles`** (Rust-backed via `notify`; added to § 3). Previously plan erroneously said "stdlib watchdog" — watchdog is not stdlib, and watchfiles is faster + maintainer-aligned with pydantic (Samuel Colvin). Sync `watchfiles.watch(directory, stop_event=stop_event)` generator → re-run pipeline on each change batch.
5. `sentinel config show|path|init`
6. Terminal summary formatter — top 5 findings + verdict + exit code (terse)
7. Detailed report artifact via `-o` with origin badge
8. `scripts/sentinel-cron.sh` and `.github/workflows/sentinel-monitor.yml` templates
9. README update with new flags, new commands, monitoring setup

Exit criteria:
- All commands in § 7.2 functional
- `sentinel run --batch` produces both terse terminal + `report.json` artifact
- GitHub Action template is green on a fresh repo import

### Phase 6 — Tests + hardening + release (Day 6)

**Additional Phase 6 deliverables from HIGH investigation:**
- **H12 pre-parse validation** in `parser.py::parse_policy()` — balanced-bracket depth counter BEFORE `json.loads`. See § 8.3 enforcement order.
- **H21 `CHANGELOG.md`** — Keep-a-Changelog format + SemVer via git tags. `sentinel info` output includes `git describe --tags` line.
- **H26 selectolax benchmark** — `tests/test_performance.py` includes a `pytest-benchmark` parametrized test comparing `selectolax.LexborHTMLParser` vs stdlib `html.parser` on one captured AWS docs page. If gap < 2×, file a follow-up to reconsider selectolax.
- **H24 Phase 6 gate tightening** — change `tests/test_performance.py:27`'s `MAX_ALLOWED_SECONDS` from `1.0` (set in Phase 2) to `0.3` as steady-state budget.

**Amendment 6 Phase 6 additions (C-F1 + Themes G, I):**

- **C-F1 PR-gate CI workflow** (CRITICAL — was missing from v6). Create `.github/workflows/ci.yml` triggered on `pull_request` and `push` to `main`. Matrix: ubuntu-latest + windows-latest, Python 3.11 + 3.12. Steps: checkout → `astral-sh/setup-uv@v3` → `uv sync --frozen --all-extras` → `uv run ruff check .` → `uv run ruff format --check .` → `uv run mypy src/` → `uv run pytest -m "not live" -n auto --cov=src --cov-fail-under=80` → `uv run pre-commit run --all-files` → `python scripts/check_dev_deps_match.py` (H18 drift check). Permissions: `contents: read`. Cache `~/.cache/uv` keyed on `uv.lock` hash. Without this workflow, `--frozen` hardening, pre-commit hooks, and mypy/ruff gates exist but enforce nothing — Phase 6 "ruff + mypy clean" exit criterion becomes a manual local check.
- **Theme G2 cold-start performance gate.** `tests/test_performance.py` adds `test_cold_start_budget`: fresh DB, empty cache, first invocation of `sentinel run <tiny-policy>`. Assert wall-clock < 500ms (covers pydantic + TOML parse + alembic check-and-upgrade + WAL activation + HMAC key derivation + bulk-load). Distinct from the < 300ms steady-state pipeline gate (H24) which runs on an already-warm process. Cold-start budget is intentionally looser because first-run initialization cost is unamortizable.
- **Theme G3 regex pre-compilation rule.** All regex patterns surviving in class bodies between Task 6 (bulk-load refactor) and Task 8 (constants reshape) MUST be compiled at class-instance `__init__` time via a single `self._compiled_patterns: tuple[re.Pattern, ...] = tuple(re.compile(p) for p in raw_patterns)` assignment — never inline-compiled per call. Ruff custom rule or a Phase 6 grep check (`grep -rn 're.compile' src/sentinel/analyzer.py`) asserts the count is bounded (≤ 8 compile sites — one per class-level pattern group).
- **Theme I v0.4.0 first release tag.** At end of Phase 6, cut git tag `v0.4.0` (annotated: `git tag -a v0.4.0 -m "Production migration: offline → live-fetch tool"`) — this is the baseline enabling `git describe --tags` in `sentinel info` output (H21). Rationale for `v0.4.0` (not `v1.0.0`): current offline tool is Phase-3 internal v0.3.0; production migration is a significant-but-not-stability-committing step; v1.0.0 reserved for the first user-facing stable release after real-world shakedown. Acceptance criterion gate: `git describe --tags` on CI succeeds (fails on untagged repos — so the tag must land before any post-release CI run).

**M19 + M21 + M22 hardening cluster (land as one atomic Phase 6 PR):**

- **M19 Renovate config** — new `.github/renovate.json5`:
  ```json5
  {
    extends: ["config:recommended"],
    lockFileMaintenance: { enabled: true, schedule: ["before 6am on saturday"] },
    vulnerabilityAlerts: { enabled: true, labels: ["security"] },
  }
  ```
  Weekly `uv.lock` drift + immediate security bypass. Updates both `[dependency-groups].dev` AND `[project.optional-dependencies].dev` (H18 dual-declaration).

- **M21 live-tests workflow** — new `.github/workflows/live-tests.yml`. Nightly cron `0 2 * * *`; uses **`uv sync --frozen`** (L4) to install dependencies; runs `uv run pytest -m live`; on failure creates/updates tracking issue via `peter-evans/create-issue-from-file@v5` (mirrors H19 pattern). Requires `SENTINEL_GITHUB_TOKEN` repo secret. Permissions: `contents: read, issues: write`.

- **L4 Renovate coordination** — `.github/renovate.json5` gains `postUpdateOptions: ["uvLockFileMaintenance"]` so `lockFileMaintenance` PRs regenerate `uv.lock` in-PR (otherwise `--frozen` rejects every maintenance PR). Add one-line note in § 9.2 / M19 scope.

- **L7 regression test** — Phase 6 test suite adds an integration test asserting `cmd_config_show` never emits raw token values to stdout:
  ```bash
  SENTINEL_GITHUB_TOKEN=ghp_fake_0123456789abcdef0123456789abcdef \
      uv run sentinel config show > out.txt
  grep -F ghp_fake_0123456789abcdef0123456789abcdef out.txt && exit 1 || exit 0
  ```
  Also asserts `out.txt` contains `github_token = "**********"` (SecretStr default repr, verifies SecretStr is actually in use for the field).

- **M22 pre-commit config** — new `.pre-commit-config.yaml` with `ruff-check`, `ruff-format`, `mypy`, `detect-secrets`, and a custom `grep` hook importing `secrets_patterns.py` from M10. New `.secrets.baseline` committed; pre-commit `detect-secrets` hook excludes `tests/cassettes/` (already scrubbed by H11).

**Goal:** the tool is robust, benchmarked, documented, and ready to hand off.

Tasks:
1. Fill test gaps — every new module has ≥80% coverage
2. Performance benchmarks in `tests/test_performance.py` — full pipeline < 1s offline, < 2s cache hit
3. Live tests for: AWS docs scraping, GitHub fetch, managed policies fetch, CloudSplaining fetch
4. Security pass: fuzz `parser.py` with pathological inputs (deeply nested JSON, huge strings, malformed Unicode)
5. `ruff check` and `mypy` clean
6. Update README.md for installation, config, all new commands
7. CLAUDE.md update to reflect new architecture
8. Final smoke test: fresh clone → `uv sync` → `uv run sentinel info` → `uv run sentinel run tests/fixtures/test_policies/wildcard_overuse.json` → clean exit 1 (wildcards flagged), report artifact produced, terminal summary concise

Exit criteria:
- 100% of existing tests still pass (backwards compat proven)
- New test count ≥ 200 additional (covering config, network, fetchers, monitor)
- `ruff check` and `mypy` green
- README + CLAUDE.md updated
- `demo.py` still produces clean `DEMO.md` (regression check)
- **`.github/workflows/ci.yml` (C-F1) green on a throwaway PR** — enforces the above on every subsequent change.
- **Cold-start gate green** — `test_cold_start_budget < 500ms` on CI runner (Amendment 6, Theme G2).
- **Git tag `v0.4.0` created** (annotated) — enables `git describe --tags` for `sentinel info` (Amendment 6, Theme I).
- **Alembic roundtrip test green** — `test_upgrade_downgrade_upgrade` passes for both DBs (Amendment 6, Theme E1).

### Day 7 — Buffer for overflow

Any phase that runs over uses Day 7. No new work introduced on Day 7.

---

## 13. Acceptance criteria (sign-off checklist)

Before any code is written, you confirm:

- [ ] The six-phase plan above is acceptable
- [ ] The library stack (§ 3) is acceptable
- [ ] The config schema in `defaults.toml` (§ 5.5) covers your needs
- [ ] The new CLI surface (§ 7) is correct
- [ ] The database schema changes (§ 6.1) are correct
- [ ] The exit code scheme (§ 7.4) is correct
- [ ] The deleted files list (§ 4.3) is acceptable
- [ ] The security model (§ 8) is acceptable

After code is written, definition of "done":

- [ ] Fresh clone → `uv sync` installs successfully on your Windows VS Code
- [ ] `uv run sentinel run tests/fixtures/test_policies/wildcard_overuse.json` behaves identically to today
- [ ] `uv run sentinel fetch --url <public-url>` works end-to-end
- [ ] `uv run sentinel managed list` returns ~1000 managed policies from scraped data
- [ ] `uv run sentinel --profile prod run policy.json` picks up the prod profile
- [ ] All 519 existing tests pass
- [ ] `pytest -m "not live"` passes for new tests
- [ ] `pytest -m live` passes when run with network
- [ ] `ruff check` clean, `mypy` clean
- [ ] `python demo.py` still generates a clean `DEMO.md` (regression safety net)
- [ ] No `.py` file contains a hardcoded list or dict of AWS action names, service prefixes, or policy data
- [ ] README and CLAUDE.md updated
- [ ] PR-gate CI (`.github/workflows/ci.yml`) is green on main (Amendment 6, C-F1)
- [ ] Git tag `v0.4.0` (annotated) exists on the release commit (Amendment 6, Theme I)
- [ ] `test_alembic_roundtrip.py` green for both `iam_actions.db` and `resource_inventory.db` (Amendment 6, Theme E)

---

## 14. Risks and mitigations

| Risk | Likelihood | Impact | Mitigation |
|---|---|---|---|
| AWS docs HTML layout changes during migration week | Medium | High (breaks scraper) | Prefer policy_sentry upstream as primary source; AWS docs is fallback only |
| `httpx-secure` library unmaintained / thin | Low | Medium | Have a hand-rolled ipaddress fallback ready; it's ~30 lines |
| `uv sync` on Windows has surprising behavior | Low | Medium | Test on the target Windows VS Code as Phase 1 first task; document `pip install -e .` fallback |
| Alembic migration on existing `iam_actions.db` damages it | Medium | Critical | Staged `check_and_upgrade_db()` (§ 6.3) with safe-stamp branch for pre-Alembic DBs; filelock prevents concurrent upgrades; migrations add tables only, never drop |
| Stale lock file from crashed migration process blocks future startups | Medium | Medium | `filelock` 60s timeout + clear stderr recovery message + `SENTINEL_SKIP_MIGRATIONS` escape hatch; documented in README |
| Schema drift between `database.py::create_schema()` and `0001_initial_schema.py` | High | High | Phase 6 drift-test asserts `sqlite_master` match; both files updated in the same PR when schema changes |
| GitHub rate limit hit during live tests | Medium | Low | Require `SENTINEL_GITHUB_TOKEN` for live tests; cache aggressively |
| Performance regression from DB-backed lookups (was in-memory dict) | Medium | Medium | Bulk-load pattern at `RiskAnalyzer.__init__` and `PolicyRewriter.__init__` (not per-action SQL); Phase 2 exit criterion gates < 200ms offline |
| Test suite red-period during Phase 2 refactor (~30 tests in `test_analyzer.py` break when `RiskAnalyzer(None)` returns empty classifications) | High | High | **Preparatory task 0** (§ 12 Phase 2) adds DB fixtures in its own CI-green commit before production refactor lands |
| Library API users bypass `check_and_upgrade_db()` and construct `Database` against stale schema | Medium | Medium | **D1 RAISE resolution:** `Database.__init__` raises `DatabaseError` with exact remediation (was WARN). `:memory:` paths exempt. Library callers must call `check_and_upgrade_db()` explicitly. |
| pytest-xdist worker contention on `.migrate.lock` and `cache.key` causes flaky CI | Medium | Medium | **Phase 1.5 prep phase** lands xdist-safe harness: per-worker `SENTINEL_DATA_DIR`, session-scoped migration fixture, filelock-timeout handling in fixtures. |
| Task 0 `COMPANION_RULES` deletion creates AttributeError window at `analyzer.py:843` between Task 0 and Task 6 | High (pre-fix) | High | **D3/Agent 2 fix:** `COMPANION_RULES` deletion deferred from Task 0 to Task 6 — class-to-instance conversion is atomic in the bulk-load commit. |
| Task 6 regex-in-DB ships without HMAC row signing if Task 6a lands in a separate commit | Medium | High (exploitable ReDoS window) | **D4 commit-coupling rule:** Task 6 + Task 6a are one atomic commit. Pre-commit hook rejects `0003_*` diffs that lack `row_hmac` column. |
| `ConfigError` or `DatabaseError` messages too generic for users to diagnose source | High | Medium (support-burden spike) | Error messages must name file:line for TOML errors, current+head revisions for schema errors, and exact remediation command. Pinned via error-message test fixtures. |
| Alembic pulls SQLAlchemy transitively (~3 MB) — scope-creep on "offline-lean" principle | Certain | Low | Acknowledged in § 3; no-ORM mode means we never use it; accepted cost |
| HMAC cache key unwritable in read-only containers / CI | Medium | Medium | Fall back to in-memory cache + `[WARN]`; documented behavior |
| Test-suite red period during Phase 2 (analyzer bulk-load refactor touches 99 test sites — H1) | High | High | Preparatory Task 0 lands DB fixtures + `make_test_db()` helper in its own CI-green commit BEFORE production refactor. Scope updated from 30 to 99 sites. |
| Latency gate tightening before H1 bulk-load fails 11 perf tests (H24) | Medium | Medium | Explicit sequencing: `MAX_ALLOWED_SECONDS = 60 → 1.0` happens in the same commit as task 6 bulk-load, never before. Tightening to 0.3 waits for Phase 6. |
| structlog `get_logger()` called at module import time pollutes log format (H23) | Medium | Medium | Phase 1 exit criterion: `grep -rn 'get_logger()' src/` finds zero module-level calls. Enforced via CI grep gate. |
| Dev-dep list drift between `[dependency-groups].dev` and `[project.optional-dependencies].dev` (H18) | Medium | Low | CI script diffs the two lists; fails if divergent. Documented as a release-step reminder. |
| DB-stored regex patterns (H1) create ReDoS injection surface for tampered DBs | Low | High | Migration-time `re.compile()` validation; strengthens case for M12 (HMAC-signed DB rows) promotion in follow-up amendment. |
| WAL sidecar files (`*-wal`, `*-shm`) excluded from pre-migration backup (H5/H27 interaction) | Medium | Medium | `PRAGMA wal_checkpoint(FULL)` fires before `shutil.copy2()` so all data flushes into the main DB file first. |
| Stale `*.db.bak` accumulation on repeated migration failures | Low | Low | `check_and_upgrade_db()` detects + warns about pre-existing backup files older than 7 days; user decides to delete. |
| `PolicyInput`/`PolicyOrigin` signature change breaks ~60 test call sites (M4/M5) | Medium | Medium | Land as one atomic PR with `Pipeline.run_text()` backwards-compat wrapper; DEMO.md regenerated same PR. |
| User-input ReDoS via condition values (M14) bypasses H1 author-side defense | Medium | High (DoS) | Per-operator `[parser.limits.condition]` caps enforced in RiskAnalyzer before regex. `re2` adoption deferred as D6. |
| `google-re2` deferred — Python `re` remains primary engine | Low | Low | D6 tracks promotion criteria (e.g., ≥3 CVEs in `re` module within 12 months). Char-cap is sufficient defense for common cases. |
| Dual-DB Alembic partial-failure (M18) leaves iam and inventory at mismatched revisions | Medium | High | Saga-style upgrade: iam first; on inventory failure, downgrade iam to prior revision; document "delete inventory.db and refresh" recovery. |
| `.refresh.lock` stale from crashed refresh process (M16) blocks next refresh | Medium | Low | `filelock.FileLock(timeout=60)`; documented manual `rm <db>.refresh.lock` recovery. |
| Shared `secrets_patterns.py` drift among M10/M22/H11 | Medium | Medium | Single-module source-of-truth; import — not copy — patterns. Unit test asserts all three callers reference the same frozenset. |
| `@functools.cache` on `_known_services()` leaks state across tests (L6) | High (pre-fix) | Medium (flaky CI) | Phase 1.5 autouse fixture calls `cache_clear()` between tests — must land atomically with the lazy loader, not separately. |
| `cmd_config_show` emits raw `SENTINEL_GITHUB_TOKEN` in support bundles (L7) | Medium | High (credential leak) | § 7.5 SecretStr contract + `_coerce()` helper; Phase 6 regression test `grep -F ghp_fake ... out.txt` fails on leak. |
| Renovate `lockFileMaintenance` PR fails `uv sync --frozen` (L4) | High (without fix) | Low | `.github/renovate.json5` gains `postUpdateOptions: ["uvLockFileMaintenance"]` so lockfile regenerates in-PR. |
| Commit-every-25-lines means many WIP commits that don't individually pass tests | High | Low | Accept. History is messy but granular. We can squash before tagging a release. |
| Scope creep from "what if we also..." | High | High | This plan is the contract. Additions require a new plan amendment. |

---

## 15. Glossary

| Term | Definition |
|---|---|
| Hardcoded | A *value* written directly in a `.py` source file (bad). Type definitions, enums, SQL in migration files are NOT hardcoded in this sense. |
| Allow-list | List of domains/orgs we permit outbound HTTP to. Default is in `defaults.toml`; user extends. |
| Cassette | A recorded HTTP interaction (VCR.py concept) stored as YAML in `tests/cassettes/`. |
| Companion permission | An action you must also grant to make another action useful (e.g., `lambda:InvokeFunction` needs `logs:*` to write logs). |
| Origin badge | A metadata block in every report stating where the policy came from. |
| Profile | Named config block (`[profiles.prod]`) selected via `--profile` at runtime. |
| Self-check loop-back | Pipeline re-runs rewriter + self-check up to N times when self-check fails. |
| SSRF | Server-Side Request Forgery — attacker tricks a tool into fetching internal URLs (e.g., `169.254.169.254`). |
| Tier 1/2/3 | Validation classification: Tier 1 = valid AWS action, Tier 2 = unknown but plausible, Tier 3 = invalid. |

---

## 16. Appendix — Agent research summaries (condensed)

### A1 — HTTP client (httpx)

Primary. Only library giving unified sync + async, clean exception hierarchy (`ConnectTimeout`/`ReadTimeout`/`HTTPStatusError`), HTTP/2 optional. Runner-up: `requests`. Minimum Python 3.9; pin `httpx>=0.27`. Transitive deps: `httpcore`, `h11`, `anyio`, `certifi` (4 small).

### A2 — HTML parsing (selectolax)

Primary, specifically `LexborHTMLParser`. 5–25× faster than `bs4+lxml` for CSS-selector-heavy workloads; zero transitive deps; wheel coverage including Windows/WSL. No XPath (fine for AWS tables). Runner-up: `parsel` if XPath needed.

### A3 — Config / CLI / Logging

- Config: **pydantic-settings** with `TomlConfigSettingsSource`, `settings_customise_sources` for exact precedence, nested `dict[str, ProfileConfig]` for profiles, `Field(json_schema_extra={"ephemeral": True})` for CLI-only flags.
- CLI: **Pure `argparse`** with nested subparsers (`set_defaults(func=...)` dispatch). `click` was initially proposed but the 3-agent investigation found `cli.py` already uses this pattern; adding click would violate § 1.2 additivity and break Phase 1 exit criteria. Decision: drop click entirely.
- Logging: **structlog** with `ConsoleRenderer` (default) / `JSONRenderer` (via `--log-format json`); native `NO_COLOR` support. `structlog.configure()` must be called before any module-level `structlog.get_logger()`; the ephemeral-flag warn uses `print(..., file=sys.stderr)` to fire pre-configure.

### A4 — Testing

Primary stack: `pytest-recording` (VCR.py wrapper) for unit tests + `pytest-httpserver` for corner cases + `@pytest.mark.live` for nightly integration. HTTP-client-agnostic so the `httpx` choice doesn't lock us in. `filter_headers` for secret scrubbing; pre-commit hook greps cassettes for secret patterns.

### A5 — Packaging

`hatchling` backend + PEP 735 `[dependency-groups]` + `[project.scripts]`. `uv sync` is the install command; `uv.lock` is committed.

**Src-layout (H3):** all three top-level packages listed from day one, even though `src/fetchers/` is populated only in Phase 4:

```toml
[tool.hatch.build.targets.wheel]
packages = ["src/sentinel", "src/refresh", "src/fetchers"]
```

**Complete `[project]` metadata (H17):**

```toml
[project]
name = "sentinel"
dynamic = ["version"]
description = "Offline AWS IAM policy validation and least-privilege enforcement"
readme = "README.md"
requires-python = ">=3.11"
license = "Apache-2.0"
authors = [{ name = "IAM Policy Sentinel" }]
classifiers = [
  "Development Status :: 4 - Beta",
  "Environment :: Console",
  "Intended Audience :: System Administrators",
  "Topic :: Security",
  "Programming Language :: Python :: 3.11",
  "Programming Language :: Python :: 3.12",
]

[project.urls]
Repository = "https://github.com/<owner>/klarna"
Issues = "https://github.com/<owner>/klarna/issues"

[project.scripts]
sentinel = "sentinel.cli:main"

[tool.hatch.version]
path = "src/sentinel/__init__.py"
```

**Dev-dep dual declaration (H18):** both PEP 735 `[dependency-groups].dev` (uv-native) AND `[project.optional-dependencies].dev` (pip < 23.1 fallback) are populated. A CI job runs `scripts/check_dev_deps_match.py` to fail on drift between the two.

### A6 — Security / observability

- Retry: **tenacity** with `Retrying(...)` iterator form for per-source budgets; compose `stop_any(stop_after_attempt(N), stop_after_delay(300))`; parse `Retry-After` via callable `wait=`.
- OTel: install **only** `opentelemetry-api` (50 KB). `ProxyTracerProvider` is a genuine no-op. Module-level `tracer = trace.get_tracer(__name__)` + context-manager spans. Auto-lights-up if user later installs SDK + exporter.
- SSRF: **httpx-secure** transport-layer shim + stdlib `ipaddress` for custom checks. **Resolve-once-and-connect-by-IP** is the DNS rebinding defense. Redirects re-trigger validation via `validate_redirect(url)` in `net/guards.py` — handles both DNS-name and literal-IP redirect targets (H9). IPv4-mapped IPv6, NAT64 (`64:ff9b::/96`), Teredo (`2001::/32`), and 6to4 (`2002::/16`) prefixes all blocked with embedded-IPv4 extraction (H13). Non-HTTP schemes (`file://`, `gopher://`, `data:`) blocked in `net/client.py::fetch()` — applies to every fetcher universally, not only the URL fetcher (H10).

---

## 17. Amendment log

### Amendment 1 — 2026-04-22: CRITICAL findings from 3-agent investigation

Applied from `prod_imp_review_investigation_critical.md`. Addresses all 9 CRITICAL findings (C1–C9) flagged by the 7-reviewer audit. Every change is traceable back to the investigation report.

| ID | Finding | Sections amended |
|---|---|---|
| **C1** | Alembic requires SQLAlchemy metadata that doesn't exist | § 6.2 rewritten for no-ORM mode; § 3 library stack note on transitive SQLAlchemy; § 14 risk on schema drift |
| **C2** | CLI argparse/click hybrid unimplementable | § 1.2 non-goals clarified; § 3 library stack row updated; § 12 Phase 1 task 9 replaced; § 12 Phase 5 task 3 replaced; § 16 A3 updated; `click` removed from runtime deps |
| **C3** | Exit code `2` conflicts with `EXIT_INVALID_ARGS` | § 7.4 rewritten as 5-code scheme (new `EXIT_CRITICAL_FINDING = 4`); § 12 Phase 1 task 7 updated; `_verdict_to_exit_code()` helper mandated |
| **C4** | Read-only DB open blocks Alembic auto-upgrade | § 6.3 fully rewritten — upgrade moves from `Database.__init__` to `check_and_upgrade_db()` at CLI entry; `SENTINEL_SKIP_MIGRATIONS` env var added to § 5.4; library-caller contract documented |
| **C5** | Race on concurrent first-run upgrades | `filelock>=3.20.3` added to § 3 library stack and deps line; § 6.3 specifies double-check pattern inside the lock; § 14 risk on stale locks |
| **C6** | Cache poisoning via unsigned disk entries | § 8.5 expanded with HMAC-SHA256 signing, per-install key at `$SENTINEL_DATA_DIR/cache.key`, `sentinel cache rotate-key` command, graceful in-memory fallback; `SENTINEL_DATA_DIR` env var added to § 5.4 |
| **C7** | `--insecure` persistable in profile config | § 5.2 extended with ephemeral-flag specification; § 7.3 new "Persistable" column marks insecure/allow-domain/skip-migrations as CLI-only; `--skip-migrations` flag added |
| **C8** | N+1 DB query explosion in analyzer | § 12 Phase 2 reordered — preparatory task 0 added, task ordering constraint documented, bulk-load pattern mandated, tighter performance gate (< 200ms) |
| **C9** | No in-process cache layer (merged with C8) | Same as C8 — `functools.cache` hint added for larger key spaces |

### Amendment diff summary

- Total sections amended: **10** (§ 1.2, § 3, § 5.2, § 5.4, § 6.2, § 6.3, § 7.3, § 7.4, § 8.5, § 12, § 14, § 16)
- New runtime deps added: **`filelock`**
- Runtime deps removed: **`click`**
- New environment variables: **`SENTINEL_SKIP_MIGRATIONS`**, **`SENTINEL_DATA_DIR`**
- New CLI flags: **`--skip-migrations`**
- New modules: **`src/sentinel/migrations.py`**
- New Phase 2 tasks: **1** (preparatory task 0 for DB fixtures)
- New risks entered in § 14: **5**
- Exit code scheme: **4 codes → 5 codes**

### Open decisions from the investigation still unresolved (carried forward)

These items from `prod_imp_review_investigation.md` § 5 are **not yet decided**. They do not block Phase 1 but must be resolved before Phase 2 ships:

1. **C4 library-vs-CLI strictness.** Should `Database.__init__` emit a warning on behind-head (current choice), raise an error (strict), or remain silent?
2. **C7 ephemeral enforcement strength.** Loud-warn (current choice) vs hard-fail at Settings instantiation if `insecure = true` appears in config.
3. **C8 fallback for `RiskAnalyzer(None)`.** Hard-fail / empty findings silently / keep class-level fallbacks.
4. **M12 DB-row tamper defense.** Promote to CRITICAL and add to Phase 2? (HMAC-signed rows; bigger scope.)

### Not in this amendment (deliberate)

- The 27 **HIGH** findings from `prod_imp_review.md` — scope for a follow-up amendment. **→ now addressed by Amendment 2 below.**
- The 22 **MEDIUM** findings — scope for a later pass.
- The 7 **LOW** + 2 **INFO** findings — addressed opportunistically.

---

### Amendment 2 — 2026-04-22: HIGH findings from 3-agent investigation

Applied from `prod_imp_review_investigation_high.md`. Addresses 25 of 27 HIGH findings (H6 and H22 were already RESOLVED_BY_AMENDMENT from Amendment 1; no further action). Every change traceable back to the investigation report.

| ID | Finding | Sections amended |
|---|---|---|
| **H1** | `analyzer.py` refactor is more invasive than plan implies (99 test sites, not 30) | § 12 Phase 2 task 0 scope updated; task 6 mandates deletion of class-body `COMPANION_RULES`; migration-time regex `re.compile()` validation added |
| **H2** | `Pipeline` has no DI slot for config/telemetry | § 12 Phase 3 task 8 adds `config: Optional[PipelineConfig]` parameter to `Pipeline.__init__`; `run()` prefers `self.config` |
| **H3** | `src/fetchers/` package missing from hatchling packages list | § 16 A5 + § 12 Phase 1 task 1 — `packages = ["src/sentinel", "src/refresh", "src/fetchers"]` all three listed from day one |
| **H4** | Phase 3 smoke test depends on Phase 4 code | § 12 Phase 3 exit criteria rescoped — pytest live-marker test against `net/client.py` only; `FetchResponse` return-type contract defined in task 5 |
| **H5** | Auto-upgrade has no partial-failure recovery | § 6.3 adds `shutil.copy2` pre-migration backup; § 14 risk row updated; backup recovery instructions documented |
| **H6** | `alembic stamp head` split-brain on existing DBs | **RESOLVED by Amendment 1 (C4 safe-stamp branch)** — no further action |
| **H7** | `sentinel run --url` vs `sentinel fetch --url` routing contradictory | § 4.1 table moves "Arbitrary URL" from Phase 3 to Phase 4; § 12 Phase 4 task 12 wires `sentinel run --url` as deprecated alias delegating to `cmd_fetch` |
| **H8** | `registry.terraform.io` contradicts "no HCL" non-goal | § 5.5 `defaults.toml` excerpt removes domain; comment explains extension via `--allow-domain` |
| **H9** | Redirect oscillation SSRF bypass | § 8.2 adds literal-IP redirect validation branch; relative-`Location` `urljoin` documented; § 12 Phase 3 task 2 mandates SSRF triad as one commit |
| **H10** | Non-HTTP scheme enforcement only on URL fetcher | § 8.2 + § 16 A6 + § 12 Phase 3 task 5 — scheme guard centralized in `net/client.py::fetch()` |
| **H11** | Cassette response bodies not scanned for secrets | § 10.3 extended — `before_record_response` body scrubber, extended regex patterns including `gho_`/`ghs_`/`github_pat_`/`ASIA`, `detect-secrets` added as dev dep |
| **H12** | Input size/nesting caps applied after JSON parse | § 8.3 enforcement order documented — balanced-bracket counter runs before `json.loads`; `PolicyParser` gains `ParserLimits` injection |
| **H13** | IPv6 NAT64/Teredo bypass | § 8.2 adds `64:ff9b::/96`, `2001::/32`, `2002::/16` to blocked ranges; embedded-IPv4 extraction documented; § 16 A6 updated |
| **H14** | `dangerous_actions.category` lookups full-scan | § 6.1 adds `CREATE INDEX idx_dangerous_category(category, action_name)` |
| **H15** | `source` column has no CHECK constraint | § 6.1 all 7 new tables declare `CHECK(... IN (...))` for `source`, `category`, `severity`, `access_category` |
| **H16** | `dangerous_combinations.action_b` missing index | § 6.1 adds `CREATE INDEX idx_dc_action_b(action_b, action_a)` |
| **H17** | Missing `[project]` metadata in pyproject.toml | § 16 A5 expanded — complete PEP 621 block with license, authors, urls, classifiers, `dynamic = ["version"]` |
| **H18** | No pip-only fallback documented | § 12 Phase 1 task 11 + § 16 A5 — README section + dual-declare dev deps + CI drift check |
| **H19** | GitHub Action has no failure alerting | § 9.2 adds `if: failure()` step with `peter-evans/create-issue-from-file@v5`; permissions note |
| **H20** | Cron script has no concurrency guard | § 9.1 replaced with hardened version (`flock`, `trap`, log redirect); `SENTINEL_LOG` added to § 5.4 |
| **H21** | No release/versioning/changelog discipline | § 12 Phase 6 adds `CHANGELOG.md` + Keep-a-Changelog + git tags; `sentinel info` shows `git describe` |
| **H22** | Profile two-phase Settings load | **RESOLVED by Amendment 1 (C2 pure argparse)** — no further action |
| **H23** | structlog initialization order unspecified | § 12 Phase 1 task 5 + exit criterion: `cache_logger_on_first_use=False`, `grep -rn 'get_logger()' src/` finds zero module-level calls |
| **H24** | Pipeline latency budget is 10× regression | § 10.4 tiered gates (200ms Phase 2, 300ms Phase 6); § 12 Phase 2 task 9 sequencing — gate change in same commit as bulk-load |
| **H25** | No startup-time target specified | § 10.4 adds `< 200ms` for `sentinel --version`/`info`; § 12 Phase 1 task 12 + exit criterion audits `__init__.py` for lazy-import violations |
| **H26** | selectolax speedup claim unvalidated | § 10.4 + § 12 Phase 6 — `pytest-benchmark` micro-benchmark against `html.parser` on one real AWS docs page |
| **H27** | SQLite journal_mode not WAL | § 6.3 + § 12 Phase 2 task 5 — `PRAGMA journal_mode=WAL; synchronous=NORMAL;` in `check_and_upgrade_db()`; H5 backup flow uses `PRAGMA wal_checkpoint(FULL)` first |

### Amendment 2 diff summary

- Sections amended: **14** (§ 4.1, § 5.4, § 5.5, § 6.1, § 6.3, § 8.2, § 8.3, § 9.1, § 9.2, § 10.3, § 10.4, § 12 Phases 1/2/3/4/6, § 14 risks, § 16 A5/A6)
- New env vars: **`SENTINEL_LOG`** (cron script log path)
- New deps (dev only): **`detect-secrets`**, **`pytest-benchmark`** (optional)
- New Phase 1 exit criteria: startup time `< 200ms`, zero module-level `get_logger()` calls
- New Phase 2 task: performance gate sequencing (task 9 — change `MAX_ALLOWED_SECONDS` in same commit as bulk-load)
- New Phase 3 tasks: `Pipeline` DI slot, `FetchResponse` contract
- Scope change: Preparatory Task 0 extended from ~30 test sites to **99** (per Agent 3 grep count)
- New risks added to § 14: **7** (test-suite red period, latency gate sequencing, structlog discipline, dev-dep drift, DB-regex ReDoS, WAL sidecar backup, stale `.bak` accumulation)

### Open decisions from HIGH investigation — NOW ALL RESOLVED (see Amendment 3 below)

1. **D1** (C4 library-vs-CLI strictness) — **RESOLVED in Amendment 3: RAISE.** See § 6.3.
2. **D2** (C7 ephemeral enforcement) — **RESOLVED in Amendment 3: HARD-FAIL.** See § 5.2.
3. **D3** (C8 `RiskAnalyzer(None)` fallback) — **RESOLVED in Amendment 3: HARD-FAIL (post-Task-8); transitional class-level fallback during Phase 2.** See § 12 Phase 2 Task 8.
4. **D4** (M12 promote to CRITICAL?) — **RESOLVED in Amendment 3: δ (no severity change) + new Phase 2 Task 6a (HMAC DB rows, commit-coupled with Task 6).** See § 12 Phase 2.
5. **D5** (new — H18 dev-dep strategy) — resolved in Amendment 2: dual-declare + CI drift check.

### Not in this amendment (deliberate)

- The 22 **MEDIUM** findings — scope for Amendment 4 (next investigation pass).
- The 7 **LOW** + 2 **INFO** findings — addressed opportunistically after MEDIUM pass.

---

### Amendment 3 — 2026-04-22: Open-decisions resolution from 3-agent investigation

Applied from `prod_imp_review_investigation_decisions.md`. Resolves all 4 carried-forward open decisions (D1–D4) plus 2 new issues surfaced by the investigation agents. Every change traceable back to the investigation report.

| ID | Decision | Resolution | Sections amended |
|---|---|---|---|
| **D1** | Library-vs-CLI strictness on behind-head DB | **RAISE** (not WARN) | § 6.3 library-caller contract rewritten with error message template + `:memory:` exemption; § 14 risk row updated |
| **D2** | Ephemeral flag enforcement strength | **HARD-FAIL** (not silent-drop + WARN) | § 5.2 ephemeral spec rewritten with `ConfigError` + example error message; rationale documented |
| **D3** | `RiskAnalyzer(None)` fallback | **HARD-FAIL (post-Task-8); transitional class-level fallback during Phase 2** | § 12 Phase 2 Task 6 expanded (COMPANION_RULES deletion moved here); Task 8 clarified as D3 enforcement point |
| **D4** | M12 severity / HMAC DB rows | **δ VALIDATED — no severity change, add Task 6a for HMAC commit-coupled with Task 6** | § 12 Phase 2 new Task 6a inserted with commit-coupling rule; § 14 risk row updated |

### Task 0 crash-window fix (new — Agent 2 catch)

Original Task 0 scope included deleting `COMPANION_RULES` class-body dict at `analyzer.py:807-816`. Agent 2 caught that `detect_missing_companions()` at line 843 references `self.COMPANION_RULES` — between Task 0 and Task 6 commits, that method would crash. **Fix:** deferred `COMPANION_RULES` deletion from Task 0 to Task 6. Task 0 now contains only fixture preparation and `demo.py` update. Task 6 deletes `COMPANION_RULES` atomically with the bulk-load refactor.

### New Phase 1.5 — xdist-safe test harness (from Agent 3 ripple finding)

Agent 3 identified filesystem-level shared state introduced by D1 (`.migrate.lock`) and D4 (`cache.key`) would cause pytest-xdist worker contention → intermittent CI flakes across the 519-test suite. New prep phase inserted between Phase 1 and Phase 2:

- Per-worker `SENTINEL_DATA_DIR` via conftest fixture
- Session-scoped `migrated_db_template` fixture (one stamped DB per worker, test-copies from template)
- Filelock-timeout handling in fixtures
- Shared helpers (`make_test_db`, `signed_db_row`) in `tests/conftest.py`

### Amendment 3 diff summary

- Sections amended: **5** (§ 5.2, § 6.3, § 12 Phase 1.5 / Phase 2 Tasks 0/6/6a/8, § 14 risks, § 17)
- New Phase: **Phase 1.5** (xdist-safe test harness prep)
- New Phase 2 task: **Task 6a** (HMAC DB rows, commit-coupled with Task 6)
- Task 0 scope: re-scoped (defers `COMPANION_RULES` deletion + adds `demo.py` update)
- New risks added to § 14: **5** (WARN→RAISE update, xdist flakiness, Task 0 crash window, Task 6/6a commit-coupling, generic error messages)
- Open decisions: **all 5 now resolved** (D1–D4 resolved here; D5 resolved in Amendment 2)

### Cross-decision constraints codified

- D1 RAISE + D3 HARD-FAIL = fail-fast pair (both raise `DatabaseError` → onboarding docs front-load `uv run alembic upgrade head`)
- D2 HARD-FAIL + D4 HMAC = security posture coherence (no `insecure=true` in config can coexist with HMAC-trusted rows)
- Task 6 + Task 6a atomic commit (overrides "every ~25 lines" default)
- Task 8 = D3 HARD-FAIL enforcement point (structurally enforced by `constants.py` + class-constant deletion)

### Not in this amendment (deliberate)

- The 22 **MEDIUM** findings — now addressed in Amendment 4 below.
- The 7 **LOW** + 2 **INFO** findings — addressed opportunistically after MEDIUM pass.

---

### Amendment 4 — 2026-04-22: MEDIUM findings from 3-agent investigation

Applied from `prod_imp_review_investigation_medium.md`. Addresses 17 GENUINE + 3 RESIDUAL_TRIVIAL MEDIUMs; confirms 2 already-resolved (M9, M13). One first-ever DOESN'T_FIT verdict on M14 triggered the loop-back protocol — Agent 2's alternative (char-cap only) adopted; `re2` deferred as new open decision **D6**.

| ID | Finding | Resolution | Sections amended |
|---|---|---|---|
| **M1** | Intent keywords schema too narrow (2 vs 8 buckets) | Expand `[intent.keywords]` in `defaults.toml` to 8 buckets with `values` + `levels` arrays | § 5.5; § 12 Phase 2 Task 8 |
| **M2** | `ACTION_RESOURCE_MAP` location mislabeled | Trivial doc edit: Task 7 citations `inventory.py:52` + `:83` | § 12 Phase 2 Task 7 |
| **M3** | `refresh --data-path` / `--live` argparse conflict | Mutually exclusive group + 2 new source choices (`managed-policies`, `cloudsplaining`) | § 12 Phase 4 Task 12 |
| **M4** | No `PolicyInput` dataclass | New `src/sentinel/models.py`; `Pipeline.run(PolicyInput)` + `run_text(str)` wrapper | § 12 Phase 4 Task 13 |
| **M5** | Origin badge schema incomplete | `PolicyOrigin` dataclass + fixed rendering recipe per format | § 12 Phase 4 Task 13 (co-land with M4) |
| **M6** | "stdlib watchdog" false label | Use `watchfiles` (Rust-backed) | § 12 Phase 5 Task 4 |
| **M7** | `pyperclip` status "evaluate" | Committed `pyperclip>=1.9` + `ClipboardUnavailable` + WSL `clip.exe` auto-detect | § 12 Phase 4 Task 7 |
| **M8** | `demo.py` migration status unclear | Trivial; handled in Phase 2 Task 0 + Phase 6 byte-identical regression | § 12 Phase 2 Task 0 (Amendment 3) |
| **M9** | `REGION_LESS_GLOBAL_SERVICES` in Python | **Already RESOLVED** by Amendment 2 Task 8 explicit enumeration | — |
| **M10** | Token leak via structlog contextvars | `redact_sensitive` processor + shared `secrets_patterns.py` module | § 11.1; § 12 Phase 1 Task 14 |
| **M11** | Subdomain wildcard bypass | Dot-prefix matching + IDNA normalization in `net/allow_list.py` | § 8.1; § 12 Phase 3 Task 2 (SSRF quartet) |
| **M12** | `managed_policies` no content hash | Extend Task 6a HMAC scope: add `policy_document_hmac` column to `0008_*` migration | § 6.1; § 12 Phase 2 Task 6a |
| **M13** | `--allow-domain` persistence | **Already RESOLVED** by Amendments 1+3 (§ 5.2 HARD-FAIL + § 7.3 ephemeral) | — |
| **M14** | No ReDoS protection | **DOESN'T_FIT loop-back:** adopted Agent 2's char-cap-only alternative. `re2` deferred as **D6**. | § 5.5 `[parser.limits.condition]`; § 8.3; § 12 Phase 2 Task 8a |
| **M15** | `SSL_CERT_FILE` silent override | Startup `[WARN]` with SHA-256 of bundle file | § 11.1; § 12 Phase 1 Task 15 |
| **M16** | `refreshed_at` update strategy undefined | Source-partitioned truncate-and-reload in `BEGIN IMMEDIATE`; new `.refresh.lock`; `sentinel info` surfaces vintage | § 6.4 (NEW); § 12 Phase 2 Tasks 4/5 reordered |
| **M17** | `managed_policies` memory via `SELECT *` | Explicit column list + `ruff` custom rule | § 6.1; § 12 Phase 4 Task 14 |
| **M18** | Inventory DB not under Alembic | Dual-DB `[alembic:inventory]`; `check_and_upgrade_all_dbs()` | § 6.2; § 6.3; § 12 Phase 2 Task 5 |
| **M19** | `uv.lock` regeneration policy | Renovate config with weekly lockFileMaintenance + security bypass | § 12 Phase 6 |
| **M20** | Python runtime version not validated | 8-line guard at top of `__main__.py` AND `__init__.py` | § 12 Phase 1 Task 13 |
| **M21** | Live-test workflow missing | New `.github/workflows/live-tests.yml` — nightly `pytest -m live` | § 12 Phase 6 |
| **M22** | No pre-commit config | New `.pre-commit-config.yaml` + `.secrets.baseline` | § 12 Phase 6 |

### Task 4/Task 5 reorder (Agent 2 catch in D-pass, amplified by M16)

Phase 2 Task 5 (migrations + WAL activation) now runs **BEFORE** Task 4 (populate tables). Reason: M16's `BEGIN IMMEDIATE` truncate-and-reload semantics behave correctly under WAL but deadlock readers under default rollback-journal mode. WAL must activate first.

### New shared infrastructure from Amendment 4

- **`src/sentinel/secrets_patterns.py`** — single source for M10 redaction, M22 pre-commit grep, H11 cassette scrubber.
- **`src/sentinel/models.py`** — `PolicyInput` + `PolicyOrigin` dataclasses (M4/M5).
- **`.refresh.lock`** filelock alongside existing `.migrate.lock` (M16).
- **`migrations/inventory/`** tree for dual-DB Alembic (M18).
- **`.github/renovate.json5`**, **`.github/workflows/live-tests.yml`**, **`.pre-commit-config.yaml`**, **`.secrets.baseline`** (M19/M21/M22).

### Amendment 4 diff summary

- Sections amended: **8+** (§ 5.5, § 6.1, § 6.2, § 6.3, § 6.4 NEW, § 8.1, § 8.3, § 11.1, § 12 Phases 1/2/3/4/5/6, § 14, § 17)
- New module files referenced: **2** (`secrets_patterns.py`, `models.py`)
- New configuration files: **4** (renovate.json5, live-tests.yml, .pre-commit-config.yaml, .secrets.baseline)
- New runtime deps: **`pyperclip>=1.9`**, **`watchfiles>=0.22`**
- New dev deps: `pytest-benchmark` (optional), `pre-commit`
- Task reordering: **Task 5 (WAL) now runs before Task 4 (populate)** in Phase 2
- Open decisions: **1 new (D6: `re2` adoption)**; D1–D5 remain resolved.

### Open decision D6 — `google-re2` adoption for ReDoS hardening

**Context:** M14 char-cap (Amendment 4) defends against common user-input ReDoS by bounding condition-value length. But a tampered DB row signed with a stolen cache.key could still inject a pathological regex pattern (Python `re` supports catastrophic backtracking). `google-re2` would eliminate backtracking with O(n) guaranteed complexity.

**Options:**
- (a) Reject permanently — char-cap is sufficient; `re2` native dep violates offline-first
- (b) Adopt with optional-dep-with-fallback (`try: import re2 as re except ImportError: import re`)
- (c) Track as deferred; reconsider if Python `re` gets ≥3 CVEs within 12 months OR if attack is observed in production

**Current state:** tracked as D6. Default: (c) defer with explicit promotion criteria.

### Not in this amendment (deliberate)

- The 7 **LOW** + 2 **INFO** findings — now addressed in Amendment 5 below.

---

### Amendment 5 — 2026-04-22: LOW + INFO findings from 3-agent investigation (FINAL INVESTIGATION-CHAIN AMENDMENT; superseded as terminal amendment by Amendment 6 below)

Applied from `prod_imp_review_investigation_low_info.md`. Addresses 3 actionable findings (L4, L6, L7); confirms 4 as already-resolved by prior amendments (L1, L2, L3, L5); promotes 2 INFO observations (I1, I2) to inline plan comments.

| ID | Finding | Resolution | Sections amended |
|---|---|---|---|
| **L1** | tomli backport for Py 3.9/3.10 | **Already RESOLVED** — `requires-python = ">=3.11"` + M20 runtime guard | — |
| **L2** | No pre-migration DB backup | **Already RESOLVED** by Amendment 2 (H5 `shutil.copy2`) | — |
| **L3** | Baseline migration not idempotent | **Already RESOLVED** by Amendment 2 (Phase 2 Task 3 `INSERT OR IGNORE`) | — |
| **L4** | `uv sync --frozen` missing in CI | `--frozen` added to § 9.2 + M21 live-tests workflow + Renovate `postUpdateOptions` | § 9.2; Phase 6 M19/M21 |
| **L5** | `--version` flag collision | **Already RESOLVED** by Amendment 3 (click dropped) | — |
| **L6** | `KNOWN_SERVICES` import-time side effect | Lazy-cached `_known_services()` helper in `parser.py` + **atomic** Phase 1.5 conftest `cache_clear()` fixture + grep exit gate | § 12 Phase 1 Task 10; § 12 Phase 1.5 Task 5 |
| **L7** | `cmd_config_show` token emission | New § 7.5 SecretStr contract + `_coerce()` helper + Phase 6 regression test | § 7.5 (NEW); Phase 6 |
| **I1** | Origin badge SHA semantics | One-line editorial clarification in § 8.4 | § 8.4 |
| **I2** | OTel module-level tracer pattern | Docstring in `telemetry.py` stub explaining ProxyTracer lazy resolution | § 11.2 |

### Amendment 5 diff summary

- Sections amended: **7** (§ 7.2 heading annotation, § 7.5 NEW, § 8.4, § 9.2, § 11.2, § 12 Phase 1 Task 10, § 12 Phase 1.5 Task 5, § 12 Phase 6, § 14 risks, § 17)
- New sections: **1** (§ 7.5 cmd_config_show redaction contract)
- New deps: **0**
- New files: **0**
- Sequencing constraints: L6 lazy loader + Phase 1.5 conftest fixture must land in **same commit** (non-negotiable — otherwise test isolation rots).

### Investigation chain — COMPLETE

After Amendment 5, all 67 original review findings have been addressed:

| Severity | Count | Amendment | Status |
|---|---|---|---|
| CRITICAL | 9 | Amendment 1 | All applied |
| HIGH | 27 | Amendment 2 | 25 applied + 2 auto-resolved by A1 |
| Open decisions | 5 (D1–D5) | Amendment 3 | All resolved |
| MEDIUM | 22 | Amendment 4 | 17 applied + 2 auto-resolved + 3 residual trivial |
| LOW | 7 | Amendment 5 | 3 applied + 4 auto-resolved |
| INFO | 2 | Amendment 5 | 2 inline editorial comments |
| **TOTAL** | **67** | 5 amendments | **100% addressed** |

Plus **1 formally deferred** (D6: `google-re2` adoption for stronger ReDoS hardening) with explicit promotion criteria.

### Amendment 6 — 2026-04-22: Final implementation-readiness patches (from 7-agent review)

Applied from `prod_imp_final_review.md`. Synthesized from 7 parallel specialist reviews (code-architect, code-reviewer, security-auditor, database-admin, deployment-engineer, python-pro, performance-engineer) — all 7 returned `READY_WITH_MINOR_PATCHES` unanimously. Addresses 1 CRITICAL + 12 HIGH findings across 10 themes. No investigation-cycle overhead; all findings are spec-gap patches, not design changes.

| ID | Theme | Resolution | Sections amended |
|---|---|---|---|
| **C-F1** | Missing PR-gate CI workflow (CRITICAL) | New Phase 6 task: `.github/workflows/ci.yml` matrix (ubuntu+windows × 3.11+3.12) running ruff/mypy/pytest/pre-commit/dev-dep drift check | § 12 Phase 6; § 13 |
| **Theme A** | `secrets_patterns.py` API under-specified | Public API defined: `scrub_bytes()`, `redact_event_dict()`, `grep_sources()`, consolidated `SECRET_PATTERNS` list; contract test asserts single source of truth | § 11.1 |
| **Theme B** | Phase 2 task ordering ambiguity | Preamble gains explicit execution-order flow; Task 8a split into 8a (char-cap, independent) + 8b (D3 HARD-FAIL, depends on Task 8); task numerals retained for § 17 traceability | § 12 Phase 2 preamble + Task 8a/8b |
| **Theme C** | `exit_codes.py` stale label | "4-level" → "5-level" in directory layout comment | § 4.2 |
| **Theme D** | Shared HMAC key trust-domain collapse | Domain separation via NIST SP 800-108 KDF: `K_cache = HMAC(root, b"sentinel-v1/cache")`, `K_db = HMAC(root, b"sentinel-v1/db-row")` — compromise of one sub-key does not unlock the other | § 8.5 |
| **Theme E** | Dual-DB migration saga incomplete | Mandate `downgrade()` in every migration file + new Task 3a (`0001_initial_inventory.py` baseline) + Phase 6 `test_upgrade_downgrade_upgrade` roundtrip test for both DBs | § 12 Phase 2 Task 3 + new Task 3a; § 12 Phase 6 |
| **Theme F** | Subcommand / flag / env-var contract gaps | `sentinel cache rotate-key` added to § 7.2; `--cache-dir` added to § 7.3; `SENTINEL_SKIP_MIGRATIONS` carve-out documented (TOML HARD-FAIL, env LOUD-WARN-ACCEPT) | § 7.2; § 7.3; § 5.2 |
| **Theme G** | Performance claim / HMAC scope mismatches | Cold-start < 500ms gate separate from steady-state < 300ms; HMAC scope explicitly limited to `dangerous_actions`/`companion_rules`/`dangerous_combinations`/`managed_policies.policy_document`; regex pre-compilation rule at `__init__` | § 8.5; § 12 Phase 6 |
| **Theme H** | Cron script portability | Scoped to Linux only; Windows users directed to GitHub Action template (§ 9.2) | § 9.1 |
| **Theme I** | First-release versioning undefined | `v0.4.0` specified as first release tag — cut at end of Phase 6; enables `git describe --tags` for `sentinel info` | § 12 Phase 6; § 13 |
| **Theme J** | Type-hint / import-discipline ambiguity | Style rule codified: PEP 604 unions (`X | None`); `from __future__ import annotations` mandatory except on pydantic model files; ruff `UP007`/`UP045`/`FA102` enforcement | § 12 Phase 1 Task 16 (NEW) |

### Amendment 6 diff summary

- Sections amended: **11** (§ 4.2, § 5.2, § 7.2, § 7.3, § 8.5, § 9.1, § 11.1, § 12 Phase 1, § 12 Phase 2, § 12 Phase 6, § 13, § 17)
- New sections / tasks: **1 new Phase 1 task (Task 16 — style rule), 1 new Phase 2 task (Task 3a — inventory baseline), 1 new Phase 6 task cluster (C-F1 + G2 + G3 + I)**
- Task splits: **1** (Phase 2 Task 8a → 8a + 8b)
- New files referenced: **2** (`.github/workflows/ci.yml`, `migrations/inventory/versions/0001_initial_inventory.py`)
- New deps: **0**
- Sequencing constraints: Task 8b blocked-by Task 8; `v0.4.0` tag must land before any post-release CI run that depends on `git describe`.

### Final review convergence themes (for future-implementer awareness)

Five themes showed up independently across 3+ reviewers — these are the design areas that are working correctly but where prose had drifted:

1. `secrets_patterns.py` API under-specification (Architect + Spec + Python Pro)
2. Latency-gate number inconsistency — 200/300ms/1s contradictions (Spec + Performance)
3. HMAC scope ambiguity (Database + Spec + Performance)
4. Phase 2 task numbering/ordering (Architect + Spec + Database)
5. Ephemeral-flag env-var loophole (Architect + Security)

All five are now closed by the Amendment 6 text above.

### Amendment 6 NOT in scope (deliberate)

- ~20 MEDIUM findings from `prod_imp_final_review.md` § 4 — treated as "fix-as-encountered during implementation"; not pre-patched. Risk accepted: these are implementation-detail smells, not architectural gaps.
- ~10 LOW findings (§ 5) — editorial polish; deferred.
- 4 INFO observations (§ 6) — deferred.
- D6 `google-re2` adoption — still deferred pending production ReDoS evidence.

### Plan status → implementation-ready (v7, FINAL)

`prod_imp.md` v7 is the definitive implementation specification. Changes relative to v6:
- 1 CRITICAL (C-F1) + 12 HIGH (Themes A–J) findings applied as Amendment 6.
- `.github/workflows/ci.yml` is now a Phase 6 deliverable — without it, nothing enforces the plan's linting/type/test/coverage gates.
- HMAC trust domain is split (cache vs. DB-row sub-keys) — compromise of one does not cascade.
- Phase 2 execution order is explicit and no longer contradicts task numerals.
- `v0.4.0` is the first release tag; `sentinel info` has a tag to describe.
- PEP 604 unions + `from __future__ import annotations` are the codebase style rule.

An implementer reading v7 from scratch has:
- Full phase-by-phase breakdown (Phase 0–6, including Phase 1.5 prep)
- Complete task lists with ordering constraints and explicit execution order
- Every referenced module, config key, migration file, and CI workflow specified (including PR gate)
- All cross-cutting concerns (test harness, HMAC infrastructure, observability, sequencing) documented
- 6 amendment logs providing full traceability from reviewer finding → plan text

**Next step is Phase 1 implementation** — create `pyproject.toml`, set up `uv`, write `config.py` / `logging_setup.py` / `telemetry.py`, ship `defaults.toml`. No further planning passes expected.

---

### Amendment 6.1 — 2026-04-22: Version string correction

Amendment 6 Theme I specified `v0.4.0` as the first release tag with rationale "current offline tool is Phase-3 internal v0.3.0." This premise was factually incorrect — the offline tool's `src/sentinel/__init__.py::__version__` was already at `0.5.0` when the plan was written (bumped 0.3.0 → 0.5.0 in pre-session commit `e601818` which added self-check + CLI + formatters).

Correction: the first production release is `v0.5.0`. Monotonic version increase (0.3.0 → 0.5.0 → v0.5.0 release) preserves SemVer ordering. 0.4.0 is skipped entirely; was never released.

This is a plan-premise correction, not a design change. No implementation impact.

---

### Amendment 7 — 2026-04-22: fetchers/refresh relocation (departure from § 4.2)

**Decision:** move `src/fetchers/` and `src/refresh/` under `src/sentinel/` as subpackages (`src/sentinel/fetchers/`, `src/sentinel/refresh/`), departing from the peer-layout specified in § 4.2.

**Rationale:** The implemented codebase contains 30 cross-package absolute imports between `fetchers`/`refresh` and `sentinel`, creating brittle coupling that surfaced as a latent runtime bug — `from ..refresh.*` imports in `src/sentinel/cli.py` crash with `ImportError: attempted relative import beyond top-level package` when `cmd_refresh` executes. The § 4.2 peer-layout was specified before the coupling was visible. Nesting both under `sentinel/` is now the canonical arrangement: single logical package, clean relative imports, one entry in pyproject.toml wheel packages.

**Scope:** 30+ cross-package import rewrites (absolute + relative forms), 17+ test mock string literals, `pyproject.toml` package list.

**Backwards-compat:** project is pre-PyPI; no external consumers depend on `fetchers.X` or `refresh.X` import paths.

**Verification:** `rg '(from|import) (fetchers|refresh)\b'` returns zero; full test suite passes; `sentinel refresh --source policy-sentry --dry-run --data-path /tmp/x` no longer crashes with ImportError.

---

### Amendment 8 — 2026-04-23: Contract tightening to match § 2 fail-closed principle (v0.6.2)

**Decision:** Tighten 5 silent-failure patterns to loud raises, bringing implementation into alignment with § 2 principle 4 (fail-closed).

**Changes:**
- `parser.py` (6 sites): DB-error silent demotion of validation tier now raises.
- `config.py`: missing shipped `defaults.toml` now aborts instead of silently empty config.
- `analyzer.py`: unguarded `re.compile` on DB-sourced patterns now converts `re.error` to `DatabaseError`.
- `migrations.py`: `_current_revision` broad except narrowed; debug-logs the swallowed exception.
- `net/cache.py`: `HMACError` no longer silently falls through to in-memory cache.

**Rationale:** These are contract tightenings, not feature changes. The § 2 fail-closed principle was always the design intent; these 5 sites were implementation gaps from earlier phases. No documented behavior is being reversed — only previously-unintended silent fallbacks are being removed.

**Version impact:** v0.6.2 (patch bump justified because no external contract is changed; only internal failure-mode cleanup).

---

### Amendment 9 — 2026-04-23: Retirement of v0.6.1 Deviation 2 (test harness restructure, v0.7.0)

**Decision:** Retire the shared-session `SENTINEL_DATA_DIR` workaround introduced in v0.6.1 (Deviation 2). Restore per-worker data-dir isolation as originally designed in § 12 Phase 1.5 Task 1.

**Rationale:** The shared-session workaround was introduced because pre-v0.6.2 tests relied on a shared `data/iam_actions.db` which polluted across xdist workers (HMAC mismatch when different workers derived different K_db from different data dirs). With `migrated_db_template` fast-copy now adopted in all CLI-path tests, each test gets its own DB + key — no sharing required. The workaround is strictly less safe than the original per-worker design and created a new class of serial-mode test failures (11 tests failing in v0.6.2 serial-mode runs because shared-state pollution could not be prevented even with the `_reset_hmac_cache_after_test` autouse).

**Changes:**
- `tests/conftest.py` `_sentinel_data_dir_per_worker`: per-worker `tmp_path_factory.mktemp(f"sentinel-{worker_id}")` per the original § 12 Phase 1.5 Task 1 design. Removes the session-scope `check_and_upgrade_all_dbs(data/iam_actions.db, None) + seed_all_baseline(...)` pair that rebuilt the shared repo-root DB.
- `tests/conftest.py` `make_test_db`: docstring now documents the callsite inventory (19 callsites across 10 files) and the adoption sweep target.
- 10 test files migrated to pass `template=migrated_db_template` at `make_test_db()` callsites, covering all CLI-path test fixtures.
- `tests/test_cli.py` gains a `cli_db_path` fixture that provides a per-test template-backed DB path for `cmd_run` / `cmd_analyze` / `cmd_rewrite` invocations; 9 previously-`database=None` tests now explicitly pass this path.
- `src/sentinel/migrations.py` `_phase2_missing_tables`: raises `DatabaseError` on `sqlite3.Error` instead of silently returning `[]` (P0-2 γ regression fix; NEW-A from phase7_2_postship_review_silent_failures.md).

**Net effect:** 11 serial-mode test failures in v0.6.2 resolved. Closes Architect Concern C4 from the v0.6.2 post-ship review. Full test suite wall time drops ~50% (146s → 79s serial; 75s → 47s parallel) because the template fast-copy path eliminates per-test migration cost.

**No plan-design changes** — this finishes what Phase 1.5 Task 2 started.

**Version impact:** v0.7.0 (minor bump signals the scope of internal test-infrastructure restructuring; no external contract changes).

---

### Amendment 10 — 2026-04-24: Tier-2 action preservation semantics (v0.8.0)

**Decision:** Tier-2 (unknown) actions are now PRESERVED in the rewritten policy rather than silently removed. TIER2_IN_POLICY findings downgrade from ERROR to WARNING severity. The formatter renames the output heading to "Suggested additions" when the rewrite contains only companion permissions without original-action narrowing.

**Before (v0.7.0):**
- `_check_tier2_exclusion` emitted findings at `CheckSeverity.ERROR`.
- `_apply_self_check_fixes` removed Tier-2 actions from the rewrite via `actions_to_remove.add(finding.action)`.
- On an empty-corpus DB, ALL actions became Tier-2 → all stripped → rewrite contained only companions.
- User pipes `sentinel run policy.json > out.json`, deploys — loses all their original actions silently.

**After (v0.8.0):**
- `_check_tier2_exclusion` emits findings at `CheckSeverity.WARNING` — verdict becomes WARNING (not FAIL) when Tier-2 is the only issue.
- `_apply_self_check_fixes` only removes INVALID (Tier-3 / `ACTION_VALIDATION`) actions; TIER2_IN_POLICY findings are no-ops for the fixer.
- Tier-2 actions preserved in `rewritten_policy.statements`.
- Formatter output includes a `"semantic": "additions_only" | "complete_policy"` field (JSON) or heading rename (text/markdown) when the rewrite is companion-only.
- `--strict` mode preserves pre-v0.8.0 safety: WARNING escalates to FAIL, and under Issue 5 the rewrite emission is then suppressed.

**Rationale:** "Fail-closed" principle (§ 2 principle 4) means refusing to silently drop user-provided actions, not "drop everything we can't verify." The user's original intent is preserved; the WARNING tells them to run `sentinel refresh` for full verification. Combined with Issue 3 (empty-corpus banner) and Issue 5 (refuse-on-FAIL suppression), the v0.8.0 flow guides the operator through the degraded-mode situation without destroying their work.

**Breaking changes for callers:**
- `SelfCheckResult.tier2_excluded: bool` renamed → `tier2_preserved_actions: list[str]`. A backward-compat `@property tier2_excluded` returning `not tier2_preserved_actions` is retained for one release cycle; slated for removal in v1.0.
- Policies that previously produced FAIL verdict due to Tier-2 action presence now produce WARNING (unless wildcard-action or other ERROR-severity findings independently drive FAIL).
- JSON formatter adds a top-level `"semantic"` key under the non-suppressed path.
- Formatter APIs gain keyword-only `force_emit: bool = False` parameter on all three `format_pipeline_result` implementations (Issue 5 sibling change shipped in the same release).

**Snapshot regeneration:** `tests/fixtures/snapshots/missing_companions.snapshot` and `tests/fixtures/snapshots/wildcard_overuse.snapshot` regenerated. Hand-audited diffs confirm the new `rewritten_actions` lists reflect preserved originals + companion additions (not just companions alone, as v0.7.0 snapshots showed).

**No plan-contract violations** — § 2 principle 4 (fail-closed) is BETTER satisfied by preservation-with-WARNING than by silent-removal. Silent drops were a fail-open in practice: the operator got a "PASS" verdict alongside a policy that had lost its intent.

**Version impact:** v0.8.0 (minor bump signals external schema evolution: new `"semantic"` JSON field + renamed dataclass field).

---

### Amendment 11 — 2026-04-24: v0.8.1 maintenance release

**Decision:** maintenance release addressing 8 post-v0.8.0 review findings + 4 pre-existing items + docs realignment.

**Contract changes (non-breaking):**
- `SelfCheckResult.tier2_excluded` shim now emits `DeprecationWarning`; removal scheduled for v0.9.0.
- JSON output gains optional `"force_emit_rewrite_bypass": true` field (v0.8.1) documenting `--force-emit-rewrite` bypass events.
- `--force-emit-rewrite` flag moved from shared parent parser to 3 subcommand parsers only (`run`, `fetch`, `managed analyze`); other subcommands no longer display it in help.

**Policy-level changes:** `cmd_info` and `sentinel refresh` now return `EXIT_IO_ERROR` on alembic-query / refresh-errors paths (previously returned `EXIT_SUCCESS`, hiding failures).

**Rationale:** fail-closed principle (§ 2 Principle 4) applied uniformly across CLI exit-code behaviors.

**No schema or breaking API changes.** Safe drop-in for existing users.

---

## End of plan

Next step: you review this document. If approved, Phase 1 begins. If anything needs changing, we amend this file before any code is written.

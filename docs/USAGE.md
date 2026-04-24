# IAM Policy Sentinel -- Usage guide

End-user how-to guide for v0.8.1. Task-oriented. For the feature
catalogue, see [`FEATURES.md`](FEATURES.md); for the landing page, see
[`../README.md`](../README.md); for design rationale, see
[`../prod_imp.md`](../prod_imp.md).

## Table of contents

1. [Getting started](#getting-started)
2. [Analyzing a policy file](#analyzing-a-policy-file)
3. [Fetching from the web](#fetching-from-the-web)
4. [Interactive workflows](#interactive-workflows)
5. [Batch analysis](#batch-analysis)
6. [CI integration](#ci-integration)
7. [Troubleshooting](#troubleshooting)
8. [Advanced](#advanced)

---

## Getting started

### Install

```bash
git clone <repo-url>
cd klarna
uv sync --all-extras       # creates .venv/, installs runtime + dev deps
```

Python 3.11+ is required. `uv sync` respects `requires-python` from
`pyproject.toml`; no separate `.python-version` file is needed.

### First run

```bash
uv run sentinel info
```

Output includes DB stats (service / action counts) and the alembic
revision. On a fresh install the corpus is empty, and sentinel prints:

```
[WARN] IAM action corpus is empty. Run:
        sentinel refresh --source policy-sentry --data-path <policy_sentry.json>
       to populate. Validation will operate with limited coverage until then.
```

This banner is expected and non-fatal. The `iam_actions.db` shipped
with the repo contains the security-critical baselines (dangerous
actions, companion rules, ARN templates) HMAC-signed with
`source='shipped'`; the bulk services/actions corpus is not shipped.

### Populate the corpus

Sentinel imports policy_sentry's raw data directly from a local JSON
file. You can either clone [policy_sentry](https://github.com/salesforce/policy_sentry)
and point at `policy_sentry/shared/data/iam-definition.json`, or use
`sentinel refresh --source policy-sentry --live` to fetch the upstream
file through the hardened HTTP client.

```bash
# Offline (preferred for reproducibility)
uv run sentinel refresh --source policy-sentry \
    --data-path /path/to/policy_sentry/shared/data/iam-definition.json

# Live fetch (network-allowed; cached per § 8.5)
uv run sentinel refresh --source policy-sentry --live
```

`sentinel info` should now show ~350 services and ~16,000 actions.

### Run your first analysis

```bash
uv run sentinel run tests/fixtures/test_policies/wildcard_overuse.json
```

Expected output: a PASS / WARNING / FAIL verdict, a findings table
(wildcards on `s3:*` actions), and a rewritten policy narrowing
wildcards to specific actions with placeholder ARNs.

---

## Analyzing a policy file

### Local file

```bash
uv run sentinel run my-policy.json
uv run sentinel run my-policy.yaml          # YAML auto-detected by suffix
```

Use stage-specific subcommands when you want only part of the pipeline:

```bash
uv run sentinel validate my-policy.json    # parse + classify only
uv run sentinel analyze  my-policy.json    # + risk findings
uv run sentinel rewrite  my-policy.json    # + least-privilege rewrite
uv run sentinel run      my-policy.json    # full pipeline (default for CI)
```

### Stdin

```bash
cat my-policy.json | uv run sentinel run -
```

### Clipboard

```bash
uv run sentinel fetch --from-clipboard
```

On WSL2 this falls back to `powershell.exe Get-Clipboard` when
`pyperclip`'s native path fails.

### Output format

```bash
uv run sentinel run my-policy.json --output-format json -o report.json
uv run sentinel run my-policy.json --output-format markdown -o report.md
```

JSON output is the canonical machine-readable format; see
[`FEATURES.md#json-output-schema`](FEATURES.md#json-output-schema-sentinel-run--fetch--managed-analyze)
for the field list.

---

## Fetching from the web

Every `sentinel fetch` pass routes through a hardened HTTP client
(allow-list + SSRF + redirect chaser + HMAC-signed cache).

### From a URL

```bash
uv run sentinel fetch --url https://example.com/policy.json
```

Only HTTPS is allowed by default. Private-IP destinations (RFC 1918,
loopback, link-local, metadata addresses) are blocked. Redirects are
followed but every hop is re-validated (H9).

### From GitHub

```bash
# Set a token for private repos and rate-limit relief
export SENTINEL_GITHUB_TOKEN=ghp_...

uv run sentinel fetch --github owner/repo/path/to/policy.json
```

The token is stored as a `pydantic.SecretStr` and redacted in
`sentinel config show` and all log events.

### From an AWS documentation sample page

```bash
uv run sentinel fetch --aws-sample ExampleMinimalPolicy
```

Selectolax parses the HTML; sources limited to the AWS docs allow-list.

### From an AWS managed policy (local DB)

```bash
uv run sentinel fetch --aws-managed AdministratorAccess
```

No network; reads the managed-policy table loaded via
`sentinel refresh --source managed-policies`.

### From a CloudSplaining example

```bash
uv run sentinel fetch --cloudsplaining infrastructure_administrator.json
```

---

## Interactive workflows

### Wizard

```bash
uv run sentinel wizard
```

Prompts for an intent ("read-only s3", "lambda deploy", ...), maps it
to access levels via `IntentMapper`, and emits a minimal starter
policy. Unknown intents are rejected with the list of recognized
buckets (P1-4 α); the wizard refuses `service:*` fallback.

### Watch mode

```bash
uv run sentinel watch tests/fixtures/test_policies/
```

Uses `watchfiles` to re-validate on every change. Convenient for
editor-driven iteration on a policy file.

### HITL Tier-2 approval

```bash
uv run sentinel run my-policy.json --interactive
```

When `--interactive` is set, the pipeline pauses on every Tier-2
(unknown) action and prompts approve / reject before the rewriter
runs. Without the flag, Tier-2 actions are preserved with a WARNING
verdict (Amendment 10) and flagged in the "Actions Kept For Review"
block.

---

## Batch analysis

```bash
uv run sentinel run --batch ./policies/
uv run sentinel run --batch ./policies/ --fail-fast
uv run sentinel run --batch ./policies/ --output-format json -o batch.json
```

`--fail-fast` stops on the first non-clean verdict. Without it, every
policy is analyzed; the batch exit code is the worst of all individual
exit codes.

Typical batch-report consumption:

```bash
uv run sentinel run --batch ./policies/ --output-format json \
    | jq '.[] | select(.final_verdict == "FAIL") | .origin.source_spec'
```

---

## CI integration

### Exit codes

| Code | CI behavior suggestion |
|------|------------------------|
| 0 (`EXIT_SUCCESS`) | green |
| 1 (`EXIT_ISSUES_FOUND`) | warn-but-pass (soft) or fail (strict) |
| 2 (`EXIT_INVALID_ARGS`) | fail (operator error) |
| 3 (`EXIT_IO_ERROR`) | fail + alert (infrastructure problem) |
| 4 (`EXIT_CRITICAL_FINDING`) | fail (blocks deploy) |

```bash
# Soft gate: block only on FAIL verdict + IO errors
uv run sentinel run policy.json || [ $? -le 1 ] || exit 1

# Strict gate: any non-zero fails the build
uv run sentinel run --strict policy.json
```

### GitHub Actions example

```yaml
name: iam-policy-review

on:
  pull_request:
    paths: ['policies/**']

jobs:
  sentinel:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: astral-sh/setup-uv@v5
      - name: Install
        run: uv sync --all-extras
      - name: Refresh corpus (offline mode; data pinned in repo)
        run: uv run sentinel refresh --source policy-sentry --data-path data/iam-definition.json
      - name: Analyze changed policies
        run: uv run sentinel run --batch policies/ --fail-fast --output-format markdown -o sentinel.md
      - name: Post report
        if: always()
        uses: mshick/add-pr-comment@v2
        with:
          message-path: sentinel.md
```

### `--force-emit-rewrite` in CI

When you need to emit a rewritten policy even on FAIL verdict (e.g.
for engineer review of what the tool would have done), pass
`--force-emit-rewrite`. This is audited: a `WARNING`-level structlog
event (`force_emit_rewrite_bypass`) fires with `bypass_of_failure: true`
on FAIL or `bypass_of_failure: false` on PASS/WARNING (SEC-L4 gives
SIEM rules a way to distinguish). The JSON output gains a
`"force_emit_rewrite_bypass": true` field; the text formatter prints
a `[!] WARNING: --force-emit-rewrite bypassed FAIL verdict` banner;
the markdown formatter adds a `> [!] FORCE-EMIT BYPASS` blockquote.

```bash
uv run sentinel run policy.json --force-emit-rewrite -o out.json
```

### Continuous monitoring

```bash
uv run sentinel fetch --github owner/repo/policies/iam.json --alert-on-new
```

Hash-compares the fetched content against the prior fetch's SHA-256.
A mismatch prints a visible `[WARN]` on stderr and a `policy_changed`
structlog event (PE3). Combine with `watch` or cron.

---

## Troubleshooting

### HMAC verification errors

Symptoms: `sentinel fetch` / `sentinel run` fails with
`HMACError` or a `DatabaseError` mentioning "HMAC mismatch".

Causes:
- `data/iam_actions.db` was built under a different root key (e.g.,
  copied from another machine).
- `cache.key` was deleted or truncated after signed rows landed.
- Shared-filesystem clone where file perms became `0o644` (P2-13 β
  refuses to load).

Recovery (targeted fix first; destructive last):

```bash
# Preferred: clear cache, regenerate HMAC keys. Leaves the DB alone.
uv run sentinel cache rotate-key

# If the DB itself is the problem, delete and rebuild:
rm data/iam_actions.db
uv run sentinel info        # triggers fresh migration + baseline seed
uv run sentinel refresh --source policy-sentry --data-path <json>
```

### Empty-corpus warnings

Every `validate` / `analyze` / `rewrite` / `run` / `fetch` emits a
WARN banner when `service_count == 0 or action_count == 0`. It's
non-fatal -- the pipeline still runs, but every action becomes Tier 2
(unknown). Refresh the corpus per [Getting started](#populate-the-corpus).

### Cold-start feels slow

`sentinel --version` is gated at 0.3 s by
`tests/test_performance.py::test_cold_start_budget`. Post-v0.8.1
median is ~113 ms. If your measurement exceeds the budget:

- Run `time .venv/bin/sentinel --version` 5 times; take the median.
- Check that no new top-level import pulls pydantic-settings (see
  `CONTRIBUTING.md#cold-start-performance-gate`).
- On WSL2 with NTFS-backed `.venv/`, `rm -rf .venv && uv sync` on the
  ext4 side.

### WSL2 setup

- Use WSL2 Ubuntu (not WSL1) for accurate `filelock` + `flock`
  behavior.
- Keep the repository on the ext4 side (under `~/`), not
  `/mnt/c/...`. Windows NTFS metadata operations are 3-10x slower.
- `sentinel watch` + `watchfiles` require a kernel >= 5.10 (WSL2
  defaults to 5.15.x as of Windows 11).

### Serial vs parallel pytest

Both test-run modes must pass before release:

```bash
uv run pytest -m "not live" -n auto   # parallel, ~45s
uv run pytest -m "not live"           # serial, ~110s
```

Serial catches shared-state regressions that xdist hides. If the
parallel suite passes but serial fails, inspect `conftest.py`
fixtures for accidental session scope or global mutation. See
Amendment 9 in `prod_imp.md § 17`.

### `--force-emit-rewrite` absent

On `validate`, `analyze`, `rewrite`, `watch`, `compare`, `search`,
`wizard`, `refresh`, `config`, `cache`, `managed list/show`, `info`,
`export-services`, `fetch-examples`: argparse rejects
`--force-emit-rewrite` with `unrecognized arguments`. This is
intentional (L2 in v0.8.1) -- only `run`, `fetch`, and
`managed analyze` emit a rewrite, so the flag is scoped to those.
Previously it was on the shared parent parser and appeared in every
subcommand's help text misleadingly.

---

## Advanced

### Custom profiles

Project-local `./.sentinel.toml` (precedence 4 of 6):

```toml
[profiles.prod]
log_level = "WARNING"
log_format = "json"
max_retries = 5
allow_list.domains = ["my-corp.com", "gh-enterprise.internal"]

[profiles.dev]
log_level = "DEBUG"
```

Activate:

```bash
uv run sentinel --profile prod run policy.json
```

Profile `max_retries` fans out to `retries.budgets.{github, aws_docs,
user_url}` plus `defaults.max_retries` (P2-9 α).

### Extending the allow-list per-run

```bash
uv run sentinel --allow-domain my-corp.internal fetch \
    --url https://my-corp.internal/policy.json
```

`--allow-domain` is ephemeral; HARD-FAILs if found in TOML or env.
Repeatable for multiple domains.

### Disabling TLS verify (emergency only)

```bash
uv run sentinel --insecure fetch --url https://self-signed.example/policy.json
```

`--insecure` is ephemeral (HARD-FAIL in TOML/env), emits an
unsuppressable `[WARN]` per request, and skips cache writes so an
MITM-poisoned response cannot persist into a signed cache entry that
a later secure session would trust (SEC-M3). Prefer installing the
right CA bundle over this flag.

### Skipping migrations (read-only filesystem)

```bash
uv run sentinel --skip-migrations info

# Or via env for Docker :ro mounts (Amendment 6 Theme F3 carve-out):
SENTINEL_SKIP_MIGRATIONS=1 sentinel info
```

The CLI flag is ephemeral. The env var is the single carve-out for
read-only filesystems -- everywhere else, ephemeral flags HARD-FAIL
if persisted.

### Custom database paths

```bash
uv run sentinel --database /path/to/custom_iam.db \
                --inventory /path/to/inventory.db \
                run policy.json
```

Useful for air-gapped installs or CI where the DB is a build-cache
artifact.

### Cache inspection

```bash
uv run sentinel cache stats       # entry count + total size
uv run sentinel cache ls          # metadata only (no bodies)
uv run sentinel cache purge       # delete every entry
uv run sentinel cache rotate-key  # regen HMAC key + purge
```

Cache entries are HMAC-SHA256 signed with the derived `K_cache`
sub-key; a mismatch on read invalidates the entry and triggers
refetch. Signed rows have `(url_hash, source, body_sha256, etag,
fetched_at_ts)` bound into the signature (see
`src/sentinel/net/cache.py`).

### Custom data paths for `refresh`

```bash
uv run sentinel refresh --source policy-sentry \
    --data-path ~/data/iam-definition-2026-04-24.json

uv run sentinel refresh --source aws-docs --live --dry-run
```

`--dry-run` parses and validates without writing. Useful to preview
a refresh against an updated source.

### Export services to JSON

```bash
uv run sentinel export-services --export-output /tmp/services.json
```

Dumps the sorted service-prefix list for external tooling (e.g., a
corp-internal policy linter that wants to whitelist only known
services).

### Benchmark AWS examples

```bash
uv run sentinel fetch-examples --benchmark --report /tmp/bench.json
```

Downloads a fixed set of AWS example policies, normalizes them, and
benchmarks the pipeline. The report is machine-readable; useful as a
regression baseline when optimizing the pipeline.

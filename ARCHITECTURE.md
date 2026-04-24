# Architecture

IAM Policy Sentinel is an offline AWS IAM policy validator.  It parses
policy JSON/YAML, classifies every `Action` against a local SQLite
corpus of IAM actions, scores risk (wildcards, privilege escalation
chains, exfiltration / destruction primitives, companion-permission
gaps), emits a least-privilege rewrite, and self-checks that the
rewrite preserves the caller's intent.  The tool ships no boto3
dependency and makes no live AWS calls at validate time — the corpus
is refreshed on demand from pinned upstream sources (policy_sentry,
AWS Service Authorization Reference, cloudsplaining, AWS managed
policies) over an allow-listed, SSRF-guarded, HMAC-signed-caching
HTTP client.

## Where to read further

- `CLAUDE.md` — project conventions, design decisions, current phase,
  and historical thinking log.
- `docs/CODEBASE_MAP.md` — generated codebase map (regenerate with
  the cartographer skill as the tree evolves).
- `CHANGELOG.md` — release-by-release change history, each entry
  cross-linked to its audit label.
- `prod_imp.md` — production-migration spec (Phase 1-8) including
  the four-step pipeline (Validate → Analyze → Rewrite → Self-check),
  HMAC-signed disk cache protocol, and the SSRF guard / allow-list
  contract.
- `CONTRIBUTING.md` — local setup, test / lint / type-check commands,
  commit and release workflow.

## Four-step pipeline

```
+-----------+   +----------+   +----------+   +-------------+
| VALIDATE  |-->| ANALYZE  |-->| REWRITE  |-->| SELF-CHECK  |
|  parser.py|   |analyzer. |   |rewriter. |   |self_check.  |
|           |   |   py     |   |   py     |   |    py       |
+-----------+   +----------+   +----------+   +-------------+
     |                |              |               |
     v                v              v               v
  3-tier          risk findings  least-priv.     re-validate
 classification  (wildcards,     policy +        + functional-
 against local    escalation,    specific ARNs   completeness
 IAM corpus       exfiltration,  (or explicit    + tier-2
 (services +      destruction,   placeholders)   preservation
  actions)        companion-gap)
```

## Subsystems

| Package / Module | Responsibility |
|---|---|
| `src/sentinel/database.py` | SQLite IAM-actions DB |
| `src/sentinel/inventory.py` | SQLite resource-inventory DB |
| `src/sentinel/parser.py` | Policy JSON / YAML parser + action classification |
| `src/sentinel/analyzer.py` | Risk analysis + intent → access-level mapping |
| `src/sentinel/rewriter.py` | Least-privilege policy rewriter |
| `src/sentinel/self_check.py` | Re-validation + functional-completeness check |
| `src/sentinel/cli*.py` | argparse-based CLI; split by subcommand family |
| `src/sentinel/fetchers/` | Pluggable input fetchers (URL, local, clipboard, github, cloudsplaining, aws-managed) |
| `src/sentinel/net/` | Hardened HTTP client: allow-list, SSRF guard, HMAC-signed disk cache, retry / Retry-After, per-request context manager |
| `src/sentinel/refresh/` | Upstream corpus loaders |
| `src/sentinel/hmac_keys.py` | HMAC key derivation + row-level signing |
| `src/sentinel/migrations.py` | Alembic-based schema migrations, dual-DB (IAM + inventory) |
| `src/sentinel/config.py`, `constants.py` | Typed settings via pydantic-settings + TOML defaults |
| `src/sentinel/logging_setup.py`, `secrets_patterns.py`, `telemetry.py` | Structured logging + secret redaction + OTel spans |
| `src/sentinel/formatters.py`, `models.py`, `exit_codes.py` | Output rendering + typed cross-boundary data + CLI exit contract |
| `src/sentinel/seed_data.py` | HMAC-signed baseline row seeding at first run |

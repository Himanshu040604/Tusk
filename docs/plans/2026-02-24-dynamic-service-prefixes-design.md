# Dynamic AWS Service Prefixes -- Design Document

**Date:** 2026-02-24
**Status:** Approved
**Approach:** Hybrid (JSON file + init-time DB merge)

## Problem

`KNOWN_SERVICES` in `constants.py` is a hardcoded set of ~150 AWS service
prefixes.  AWS adds new services regularly, so this set goes stale.  The
only way to recognize a new service is to edit source code.

## Decision Summary

| Decision | Choice |
|----------|--------|
| Approach | Hybrid: JSON file at import time + DB merge at parser init |
| Auto-export during refresh | Yes |
| Standalone export command | Yes (`sentinel export-services`) |
| JSON committed to git | Yes |

## Three-Layer Resolution

```
Layer 1: data/known_services.json  (loaded at import time, committed to git)
         |
         v  fallback if JSON missing/corrupted/empty
Layer 2: _HARDCODED_SERVICES in constants.py  (safety net, never removed)
         |
         v  merged at PolicyParser.__init__()
Layer 3: DB service prefixes  (queried once, merged via set union)
```

**Result:** `parser.known_services` = union of (JSON or hardcoded) + DB services.

## Scenario Coverage

| Scenario | Layer 1 (JSON) | Layer 2 (Hardcoded) | Layer 3 (DB) | Outcome |
|----------|---------------|--------------------:|-------------|---------|
| Fresh clone, no DB | Used | Fallback if missing | Skipped | ~150 services from JSON |
| Fresh clone, no DB, no JSON | N/A | Used | Skipped | ~150 hardcoded services |
| Refreshed DB, JSON in sync | Used | Not needed | Merged | Full coverage |
| Refreshed DB, JSON deleted | N/A | Used | Merged | Hardcoded + DB union |
| Refreshed DB, JSON corrupted | N/A | Used | Merged | Hardcoded + DB union |
| DB query fails at init | Used | Fallback if needed | Skipped | JSON/hardcoded services |

## Data Flow

### `sentinel refresh` (auto-export)

```
sentinel refresh --source policy-sentry --data-path ./data/
  1. Populate SQLite services table (existing behavior)
  2. Auto-export: SELECT service_prefix FROM services ORDER BY service_prefix
  3. Write data/known_services.json
```

### `sentinel export-services` (standalone)

```
sentinel export-services [-d DB] [-o FILE]
  1. Open DB (explicit flag, or default search path)
  2. SELECT service_prefix FROM services ORDER BY service_prefix
  3. Write data/known_services.json (or custom -o path)
```

### Import time (`constants.py`)

```
  1. Try: load data/known_services.json -> KNOWN_SERVICES = set(data["services"])
  2. Fallback on FileNotFoundError/JSONDecodeError/OSError: use _HARDCODED_SERVICES
```

### Parser init (`parser.py.__init__`)

```
  1. self.known_services = set(KNOWN_SERVICES)  # copy from constants
  2. If database provided:
       db_prefixes = {s.service_prefix for s in database.get_services()}
       self.known_services |= db_prefixes
  3. If DB query fails: pass (continue with JSON/hardcoded set)
```

## Files Changed

| File | Change | Purpose |
|------|--------|---------|
| `data/known_services.json` | CREATE | Initial JSON from hardcoded set |
| `src/sentinel/constants.py` | MODIFY | `load_known_services()` loader |
| `src/sentinel/parser.py` | MODIFY | Init-time merge, 5 call-site updates |
| `src/sentinel/cli.py` | MODIFY | `export-services` subcommand + auto-export in refresh |
| `src/refresh/policy_sentry_loader.py` | MODIFY | Call export after load |
| `src/refresh/aws_docs_scraper.py` | MODIFY | Call export after load |
| `tests/test_cli.py` | MODIFY | Tests for `export-services` |
| `tests/test_dynamic_services.py` | CREATE | JSON loading, fallback, merge tests |

## JSON File Format

```json
{
  "_generated": "2026-02-24T00:00:00Z",
  "_source": "hardcoded",
  "services": ["access-analyzer", "account", "acm", ...]
}
```

Sorted alphabetically.  `_source` is either `"hardcoded"` (initial) or
the database file path (after refresh).

## Key Constraints

- `KNOWN_SERVICES` public API unchanged -- zero breaking changes for importers
- `_HARDCODED_SERVICES` is private, never removed from source
- Set union is additive only -- DB can grow the set, never shrink it
- Parser handles missing DB gracefully (no crash, no error output)
- JSON path uses `Path(__file__).resolve().parent.parent.parent / "data" / ...`
  (three `.parent` calls: `constants.py` -> `sentinel/` -> `src/` -> project root)

## Test Plan

| Test | What it verifies |
|------|-----------------|
| JSON loads successfully | Services from JSON used |
| JSON missing | Hardcoded fallback used |
| JSON corrupted | Hardcoded fallback used |
| JSON has empty services array | Hardcoded fallback used |
| Parser init without DB | `known_services` == JSON/hardcoded set |
| Parser init with DB | `known_services` == union of JSON/hardcoded + DB |
| DB query fails at init | No crash, falls back to JSON/hardcoded |
| `export_services_json()` writes correct structure | JSON has `_generated`, `_source`, sorted `services` |
| `cmd_export_services` with valid DB | Returns EXIT_SUCCESS |
| Refresh auto-exports | JSON file updated after refresh |

## Agent Coordination (3-Agent System)

| Agent | Role | Files Owned |
|-------|------|-------------|
| Agent 1 (Scraper/Research) | Verify path resolution, edge cases | Research only |
| Agent 2 (Code Writer) | All file changes | All 8 files |
| Agent 3 (Validator) | Review + test execution | Validation report |

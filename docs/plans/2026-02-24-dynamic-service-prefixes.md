# Dynamic AWS Service Prefixes -- Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Make `KNOWN_SERVICES` dynamic via a 3-layer resolution: JSON file -> hardcoded fallback -> DB merge at parser init.

**Architecture:** Hybrid approach with `data/known_services.json` loaded at import time, `_HARDCODED_SERVICES` as safety net, and DB services merged at `PolicyParser.__init__()`. Auto-export during `sentinel refresh` and standalone `sentinel export-services` command.

**Tech Stack:** Python 3.9+, SQLite3, pathlib, json, pytest

**Design Doc:** `docs/plans/2026-02-24-dynamic-service-prefixes-design.md`

---

## Task 1: Create initial `data/known_services.json`

**Files:**
- Create: `data/known_services.json`

**Step 1: Create the JSON file**

Generate from the current hardcoded `KNOWN_SERVICES` set in `constants.py:117-196`. Sorted alphabetically. Format:

```json
{
  "_generated": "2026-02-24T00:00:00Z",
  "_source": "hardcoded",
  "services": ["access-analyzer", "account", "acm", ...]
}
```

All ~150 services from the hardcoded set, sorted with `sorted()`.

**Step 2: Verify the JSON file**

Run: `python -c "import json; d=json.load(open('data/known_services.json')); print(len(d['services']), 'services'); assert len(d['services']) > 140"`
Expected: `~150 services` printed, no assertion error.

**Step 3: Commit**

```bash
git add data/known_services.json
git commit -m "feat: add initial known_services.json from hardcoded set"
```

---

## Task 2: Add `_HARDCODED_SERVICES` and `load_known_services()` to `constants.py`

**Files:**
- Modify: `src/sentinel/constants.py:8,111-196`

**Step 1: Write the failing test**

File: `tests/test_dynamic_services.py`

```python
"""Tests for dynamic service prefix resolution."""

import json
from pathlib import Path
from unittest.mock import patch

import pytest

from src.sentinel.constants import (
    KNOWN_SERVICES,
    _HARDCODED_SERVICES,
    load_known_services,
)


class TestLoadKnownServices:
    """Test the JSON loading and fallback logic."""

    def test_known_services_is_a_set(self):
        assert isinstance(KNOWN_SERVICES, set)
        assert len(KNOWN_SERVICES) > 140

    def test_hardcoded_services_exists(self):
        assert isinstance(_HARDCODED_SERVICES, set)
        assert len(_HARDCODED_SERVICES) > 140

    def test_load_from_json(self, tmp_path: Path):
        json_file = tmp_path / "known_services.json"
        json_file.write_text(json.dumps({
            "_generated": "2026-01-01T00:00:00Z",
            "_source": "test",
            "services": ["s3", "ec2", "lambda", "custom-svc"],
        }), encoding="utf-8")

        result = load_known_services(json_path=json_file)
        assert result == {"s3", "ec2", "lambda", "custom-svc"}

    def test_fallback_on_missing_json(self):
        result = load_known_services(
            json_path=Path("/nonexistent/path/known_services.json")
        )
        assert result == _HARDCODED_SERVICES

    def test_fallback_on_corrupted_json(self, tmp_path: Path):
        bad = tmp_path / "known_services.json"
        bad.write_text("not valid json {{{", encoding="utf-8")

        result = load_known_services(json_path=bad)
        assert result == _HARDCODED_SERVICES

    def test_fallback_on_empty_services_array(self, tmp_path: Path):
        empty = tmp_path / "known_services.json"
        empty.write_text(json.dumps({
            "_generated": "2026-01-01T00:00:00Z",
            "_source": "test",
            "services": [],
        }), encoding="utf-8")

        result = load_known_services(json_path=empty)
        assert result == _HARDCODED_SERVICES

    def test_fallback_on_missing_services_key(self, tmp_path: Path):
        no_key = tmp_path / "known_services.json"
        no_key.write_text(json.dumps({
            "_generated": "2026-01-01T00:00:00Z",
        }), encoding="utf-8")

        result = load_known_services(json_path=no_key)
        assert result == _HARDCODED_SERVICES
```

**Step 2: Run test to verify it fails**

Run: `python -m pytest tests/test_dynamic_services.py::TestLoadKnownServices -v`
Expected: FAIL -- `ImportError: cannot import name '_HARDCODED_SERVICES'` and `cannot import name 'load_known_services'`

**Step 3: Implement in `constants.py`**

Changes to `src/sentinel/constants.py`:

1. Add `import json` and `from pathlib import Path` to imports (line 8).
2. Rename `KNOWN_SERVICES` (lines 117-196) to `_HARDCODED_SERVICES`.
3. Add `_JSON_PATH` constant pointing to `data/known_services.json` relative to project root (3 `.parent` calls from `constants.py`).
4. Add `load_known_services(json_path=None)` function:

```python
_JSON_PATH: Path = Path(__file__).resolve().parent.parent.parent / "data" / "known_services.json"


def load_known_services(json_path: Optional[Path] = None) -> Set[str]:
    """Load known AWS service prefixes from JSON file with hardcoded fallback.

    Args:
        json_path: Override path to JSON file (for testing). Defaults to
            ``data/known_services.json`` relative to project root.

    Returns:
        Set of service prefix strings.
    """
    path = json_path or _JSON_PATH
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        services = data.get("services", [])
        if not services:
            return set(_HARDCODED_SERVICES)
        return set(services)
    except (FileNotFoundError, json.JSONDecodeError, OSError, KeyError):
        return set(_HARDCODED_SERVICES)


KNOWN_SERVICES: Set[str] = load_known_services()
```

Key points:
- `_HARDCODED_SERVICES` is private, never removed.
- `KNOWN_SERVICES` public API unchanged -- still a `Set[str]` at module level.
- `load_known_services()` is testable with `json_path` override.

**Step 4: Run tests to verify they pass**

Run: `python -m pytest tests/test_dynamic_services.py::TestLoadKnownServices -v`
Expected: All 7 tests PASS.

**Step 5: Run full test suite for regressions**

Run: `python -m pytest tests/ -v --tb=short`
Expected: All 352 existing tests PASS (no regressions from renaming).

**Step 6: Commit**

```bash
git add src/sentinel/constants.py tests/test_dynamic_services.py
git commit -m "feat: add load_known_services() with JSON loading and hardcoded fallback"
```

---

## Task 3: Add DB merge to `PolicyParser.__init__()`

**Files:**
- Modify: `src/sentinel/parser.py:16,107,115-121,329,382-384,404,561,576`

**Step 1: Write the failing test**

Append to `tests/test_dynamic_services.py`:

```python
from src.sentinel.parser import PolicyParser
from src.sentinel.database import Database, Service


class TestParserInitMerge:
    """Test DB service merge at parser init."""

    def test_init_without_db(self):
        parser = PolicyParser()
        assert isinstance(parser.known_services, set)
        assert "s3" in parser.known_services
        assert "ec2" in parser.known_services

    def test_init_with_db_merges_services(self, tmp_path: Path):
        db = Database(tmp_path / "test.db")
        db.create_schema()
        db.insert_service(Service(service_prefix="custom-new-svc", service_name="Custom"))
        db.insert_service(Service(service_prefix="s3", service_name="Amazon S3"))

        parser = PolicyParser(db)

        # Should have both hardcoded/JSON services AND db services
        assert "s3" in parser.known_services
        assert "custom-new-svc" in parser.known_services
        # DB can grow the set, never shrink it
        assert len(parser.known_services) >= len(KNOWN_SERVICES)

    def test_init_db_query_failure_no_crash(self, tmp_path: Path):
        db = Database(tmp_path / "test.db")
        # Don't create schema -- querying will fail
        parser = PolicyParser(db)
        # Should not crash, falls back to JSON/hardcoded
        assert isinstance(parser.known_services, set)
        assert "s3" in parser.known_services
```

**Step 2: Run test to verify it fails**

Run: `python -m pytest tests/test_dynamic_services.py::TestParserInitMerge -v`
Expected: FAIL -- `AttributeError: 'PolicyParser' object has no attribute 'known_services'`

**Step 3: Implement in `parser.py`**

Changes to `src/sentinel/parser.py`:

1. Remove class-level `KNOWN_SERVICES = _KNOWN_SERVICES` (line 107).
2. Update `__init__` (lines 115-121) to create `self.known_services` instance variable and merge DB services:

```python
def __init__(self, database: Optional[Database] = None):
    """Initialize parser.

    Args:
        database: Optional Database instance for Tier 1 validation.
            Also used to merge DB service prefixes into known_services.
    """
    self.database = database
    self.known_services: Set[str] = set(_KNOWN_SERVICES)

    # Layer 3: merge DB service prefixes
    if self.database:
        try:
            db_prefixes = {s.service_prefix for s in self.database.get_services()}
            self.known_services |= db_prefixes
        except Exception:
            pass  # Continue with JSON/hardcoded set
```

3. Update 5 call sites from `self.KNOWN_SERVICES` to `self.known_services`:
   - Line 329: `if service_prefix in self.KNOWN_SERVICES` -> `self.known_services`
   - Line 382-383: `service_prefix in self.KNOWN_SERVICES` -> `self.known_services`
   - Line 404: `service_prefix not in self.KNOWN_SERVICES` -> `self.known_services`
   - Line 561: `for svc in self.KNOWN_SERVICES:` -> `self.known_services`
   - Line 576: `for svc in self.KNOWN_SERVICES:` -> `self.known_services`

**Step 4: Run tests to verify they pass**

Run: `python -m pytest tests/test_dynamic_services.py::TestParserInitMerge -v`
Expected: All 3 tests PASS.

**Step 5: Run full test suite for regressions**

Run: `python -m pytest tests/ -v --tb=short`
Expected: All tests PASS. The 5 call-site changes are a simple rename from class attribute to instance attribute.

**Step 6: Commit**

```bash
git add src/sentinel/parser.py tests/test_dynamic_services.py
git commit -m "feat: merge DB service prefixes at PolicyParser init"
```

---

## Task 4: Add `export_services_json()` utility function

**Files:**
- Modify: `src/sentinel/cli.py` (add helper function)

**Step 1: Write the failing test**

Append to `tests/test_dynamic_services.py`:

```python
from src.sentinel.cli import export_services_json


class TestExportServicesJson:
    """Test the export utility function."""

    def test_export_writes_correct_structure(self, tmp_path: Path):
        db = Database(tmp_path / "test.db")
        db.create_schema()
        db.insert_service(Service(service_prefix="s3", service_name="Amazon S3"))
        db.insert_service(Service(service_prefix="ec2", service_name="Amazon EC2"))
        db.insert_service(Service(service_prefix="lambda", service_name="AWS Lambda"))

        output_file = tmp_path / "known_services.json"
        export_services_json(db, output_file)

        data = json.loads(output_file.read_text(encoding="utf-8"))
        assert "_generated" in data
        assert "_source" in data
        assert data["services"] == ["ec2", "lambda", "s3"]  # sorted

    def test_export_source_contains_db_path(self, tmp_path: Path):
        db = Database(tmp_path / "test.db")
        db.create_schema()
        db.insert_service(Service(service_prefix="s3", service_name="Amazon S3"))

        output_file = tmp_path / "known_services.json"
        export_services_json(db, output_file)

        data = json.loads(output_file.read_text(encoding="utf-8"))
        assert "test.db" in data["_source"]

    def test_export_empty_db(self, tmp_path: Path):
        db = Database(tmp_path / "test.db")
        db.create_schema()

        output_file = tmp_path / "known_services.json"
        export_services_json(db, output_file)

        data = json.loads(output_file.read_text(encoding="utf-8"))
        assert data["services"] == []
```

**Step 2: Run test to verify it fails**

Run: `python -m pytest tests/test_dynamic_services.py::TestExportServicesJson -v`
Expected: FAIL -- `ImportError: cannot import name 'export_services_json'`

**Step 3: Implement `export_services_json()` in `cli.py`**

Add to `src/sentinel/cli.py` (after the imports, before `build_parser()`):

```python
from datetime import datetime, timezone


def export_services_json(
    database: "Database",
    output_path: Optional[Path] = None,
) -> Path:
    """Export service prefixes from DB to JSON file.

    Args:
        database: Database to query services from.
        output_path: Destination path. Defaults to
            ``data/known_services.json`` relative to project root.

    Returns:
        Path to the written JSON file.
    """
    if output_path is None:
        output_path = (
            Path(__file__).resolve().parent.parent.parent
            / "data"
            / "known_services.json"
        )

    services = sorted(s.service_prefix for s in database.get_services())

    data = {
        "_generated": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "_source": str(database.db_path),
        "services": services,
    }

    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(
        json.dumps(data, indent=2) + "\n", encoding="utf-8"
    )
    return output_path
```

**Step 4: Run tests to verify they pass**

Run: `python -m pytest tests/test_dynamic_services.py::TestExportServicesJson -v`
Expected: All 3 tests PASS.

**Step 5: Commit**

```bash
git add src/sentinel/cli.py tests/test_dynamic_services.py
git commit -m "feat: add export_services_json() utility function"
```

---

## Task 5: Add `export-services` CLI subcommand

**Files:**
- Modify: `src/sentinel/cli.py` (add subcommand + handler)

**Step 1: Write the failing test**

Append to `tests/test_dynamic_services.py`:

```python
from src.sentinel.cli import build_parser, cmd_export_services
from src.sentinel.constants import EXIT_SUCCESS, EXIT_IO_ERROR


class TestCmdExportServices:
    """Test the export-services subcommand."""

    def test_export_services_with_valid_db(self, tmp_path: Path):
        db = Database(tmp_path / "test.db")
        db.create_schema()
        db.insert_service(Service(service_prefix="s3", service_name="Amazon S3"))

        output_file = tmp_path / "output.json"

        parser = build_parser()
        args = parser.parse_args([
            "export-services",
            "-d", str(tmp_path / "test.db"),
            "-o", str(output_file),
        ])
        exit_code = cmd_export_services(args)

        assert exit_code == EXIT_SUCCESS
        data = json.loads(output_file.read_text(encoding="utf-8"))
        assert "s3" in data["services"]

    def test_export_services_no_db(self, tmp_path: Path):
        parser = build_parser()
        args = parser.parse_args([
            "export-services",
            "-d", str(tmp_path / "nonexistent.db"),
        ])
        exit_code = cmd_export_services(args)
        assert exit_code == EXIT_IO_ERROR
```

**Step 2: Run test to verify it fails**

Run: `python -m pytest tests/test_dynamic_services.py::TestCmdExportServices -v`
Expected: FAIL -- `ImportError: cannot import name 'cmd_export_services'`

**Step 3: Implement in `cli.py`**

1. Add `export-services` subparser inside `build_parser()` (after the `info` block, before `return parser`):

```python
    # export-services
    p_export = subparsers.add_parser(
        "export-services",
        parents=[parent],
        help="Export service prefixes from DB to JSON file",
    )
    p_export.add_argument(
        "-o", "--output",
        default=None,
        help="Output JSON file path (default: data/known_services.json)",
    )
```

Note: The `export-services` parser inherits `-d`/`--database` from the parent.

2. Add `cmd_export_services()` handler:

```python
def cmd_export_services(args: argparse.Namespace) -> int:
    """Execute the export-services subcommand.

    Args:
        args: Parsed arguments.

    Returns:
        Exit code.
    """
    db = resolve_database(args)
    if db is None:
        print(
            "No database found. Use --database to specify path.",
            file=sys.stderr,
        )
        return EXIT_IO_ERROR

    output_path = None
    output_arg = getattr(args, "output", None)
    if output_arg:
        output_path = Path(output_arg)

    written = export_services_json(db, output_path)
    print(f"Exported services to {written}")
    return EXIT_SUCCESS
```

3. Add `"export-services": cmd_export_services` to the `handlers` dict in `main()`.

**Step 4: Run tests to verify they pass**

Run: `python -m pytest tests/test_dynamic_services.py::TestCmdExportServices -v`
Expected: All 2 tests PASS.

**Step 5: Commit**

```bash
git add src/sentinel/cli.py tests/test_dynamic_services.py
git commit -m "feat: add export-services CLI subcommand"
```

---

## Task 6: Add auto-export to `cmd_refresh()`

**Files:**
- Modify: `src/sentinel/cli.py:524-572` (inside `cmd_refresh`)

**Step 1: Write the failing test**

Append to `tests/test_dynamic_services.py`:

```python
class TestRefreshAutoExport:
    """Test that refresh auto-exports known_services.json."""

    def test_refresh_auto_exports(self, tmp_path: Path):
        # Create sample data
        sample = {
            "prefix": "s3",
            "service_name": "Amazon S3",
            "privileges": [
                {"privilege": "GetObject", "access_level": "Read"},
            ],
            "resources": [],
            "conditions": [],
        }
        data_file = tmp_path / "s3.json"
        data_file.write_text(json.dumps(sample), encoding="utf-8")

        db_path = tmp_path / "test.db"
        output_json = tmp_path / "known_services.json"

        parser = build_parser()
        args = parser.parse_args([
            "refresh",
            "--source", "policy-sentry",
            "--data-path", str(data_file),
            "-d", str(db_path),
        ])
        # Patch export path to tmp_path
        with patch(
            "src.sentinel.cli.export_services_json"
        ) as mock_export:
            exit_code = cmd_refresh(args)

        assert exit_code == EXIT_SUCCESS
        # Verify export was called with the database
        mock_export.assert_called_once()
```

**Step 2: Run test to verify it fails**

Run: `python -m pytest tests/test_dynamic_services.py::TestRefreshAutoExport -v`
Expected: FAIL -- `mock_export.assert_called_once()` fails because `cmd_refresh` doesn't call `export_services_json` yet.

**Step 3: Implement auto-export in `cmd_refresh()`**

In `src/sentinel/cli.py`, add the auto-export call at the end of `cmd_refresh()`, after the stats are printed but before `return EXIT_SUCCESS`. Only call when NOT in dry-run mode:

```python
    # Auto-export known_services.json after successful refresh
    try:
        written = export_services_json(db)
        print(f"Auto-exported services to {written}")
    except Exception as e:
        print(f"[WARN] Auto-export failed: {e}", file=sys.stderr)
```

Insert this block after the changelog writing block (after line 570) and before `return EXIT_SUCCESS` (line 572).

**Step 4: Run tests to verify they pass**

Run: `python -m pytest tests/test_dynamic_services.py::TestRefreshAutoExport -v`
Expected: PASS.

**Step 5: Run full test suite for regressions**

Run: `python -m pytest tests/ -v --tb=short`
Expected: All tests PASS.

**Step 6: Commit**

```bash
git add src/sentinel/cli.py tests/test_dynamic_services.py
git commit -m "feat: auto-export known_services.json after refresh"
```

---

## Task 7: Update `tests/test_cli.py` for `export-services`

**Files:**
- Modify: `tests/test_cli.py`

**Step 1: Add export-services test to `TestBuildParser`**

Add a test verifying the subcommand is registered:

```python
def test_export_services_subcommand(self):
    parser = build_parser()
    args = parser.parse_args(["export-services", "-d", "test.db"])
    assert args.command == "export-services"
    assert args.database == "test.db"
```

**Step 2: Run the test**

Run: `python -m pytest tests/test_cli.py::TestBuildParser::test_export_services_subcommand -v`
Expected: PASS (implementation already done in Task 5).

**Step 3: Commit**

```bash
git add tests/test_cli.py
git commit -m "test: add export-services parser test to test_cli.py"
```

---

## Task 8: Final verification

**Step 1: Run full test suite**

Run: `python -m pytest tests/ -v`
Expected: All tests PASS (~360+ tests).

**Step 2: Verify JSON file is valid**

Run: `python -c "import json; d=json.load(open('data/known_services.json')); print(f'{len(d[\"services\"])} services, source={d[\"_source\"]}')" `
Expected: `~150 services, source=hardcoded`

**Step 3: Verify imports still work**

Run: `python -c "from src.sentinel import KNOWN_SERVICES; print(f'{len(KNOWN_SERVICES)} services loaded')"`
Expected: `~150 services loaded`

Run: `python -c "from src.sentinel.constants import _HARDCODED_SERVICES, load_known_services; print('OK')"`
Expected: `OK`

**Step 4: Verify CLI export-services**

Run: `python -m sentinel export-services --help`
Expected: Help text shown.

---

## Agent Coordination (3-Agent System)

| Agent | Role | Files Owned |
|-------|------|-------------|
| Agent 1 (Research) | Verify path resolution, review edge cases | Read-only |
| Agent 2 (Code Writer) | All 8 tasks above | All modified/created files |
| Agent 3 (Validator) | Review + test execution | Validation report |

**Execution flow:**
1. Agent 2 implements Tasks 1-7 sequentially (each depends on previous)
2. Agent 3 runs Task 8 verification
3. Final commit with all changes

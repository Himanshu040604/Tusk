"""Regression tests for Phase 7 completeness gaps (v0.6.1).

Closes test-harness coverage for 4 of the 7 Phase 7 fixes identified in
the post-ship test review as having no direct regression test:

* P0-2 γ — `verify_phase2_tables` aborts on mis-stamped DB.
* P1-4 α — `cmd_wizard` refuses to emit a `service:*` fallback.
* P1-6 β — `Database.is_empty` SQL-injection hardening.
* P2-13 β — HMAC root-key file refuses to load on broad POSIX perms.

Per phase7_postship_review_tests.md § "Top 5 test improvements needed".
"""

from __future__ import annotations

import os
import sqlite3
import subprocess
import sys
from pathlib import Path

import pytest

from sentinel.database import Database, DatabaseError
from sentinel.exit_codes import EXIT_INVALID_ARGS
from sentinel.hmac_keys import HMACError
from sentinel.migrations import check_and_upgrade_all_dbs


# ---------------------------------------------------------------------------
# Test 1 — P0-2 γ: mis-stamped DB abort
# ---------------------------------------------------------------------------


def test_verify_phase2_tables_aborts_on_safe_stamp(tmp_path: Path) -> None:
    """Mis-stamped Phase-1-only DB must be caught by verify_phase2_tables.

    Creates a DB with ONLY Phase-1 tables (minimal services + metadata),
    manually stamps it at Alembic HEAD (0008_add_managed_policies) via
    `alembic command.stamp`, then calls `check_and_upgrade_all_dbs`.
    Without P0-2 γ the safe-stamp branch would let this slide silently;
    with P0-2 γ we get a `DatabaseError` naming the missing tables.
    """
    from alembic import command

    from sentinel.migrations import _make_config

    db_path = tmp_path / "phase1_only.db"

    # Create minimal Phase-1-only schema: just `services` and `metadata`
    # tables.  Any Phase-1 table presence (see `_db_has_tables`) is enough
    # to trigger the safe-stamp branch on a fresh-stamp attempt.
    conn = sqlite3.connect(db_path)
    try:
        conn.execute(
            "CREATE TABLE services (service_prefix TEXT PRIMARY KEY, "
            "service_name TEXT NOT NULL)"
        )
        conn.execute("CREATE TABLE metadata (key TEXT PRIMARY KEY, value TEXT)")
        conn.commit()
    finally:
        conn.close()

    # Now stamp it at HEAD without running migrations — this reproduces
    # the "stamped but missing tables" state the fix is designed to catch.
    cfg = _make_config(db_path, "iam")
    command.stamp(cfg, "head")

    # Without P0-2 γ, check_and_upgrade_all_dbs would silently return
    # because the DB is already at HEAD.  With the fix, verify_phase2_tables
    # aborts.
    with pytest.raises(DatabaseError, match=r"missing expected tables"):
        check_and_upgrade_all_dbs(db_path, None)


# ---------------------------------------------------------------------------
# Test 2 — P1-4 α: wizard refuses unknown intent
# ---------------------------------------------------------------------------


def test_cmd_wizard_refuses_unknown_intent() -> None:
    """`sentinel wizard` with a bogus intent must exit EXIT_INVALID_ARGS
    and print the Recognized-intents list — never silently fall back to
    `service:*` (would violate the least-privilege core guarantee).
    """
    sentinel = Path(__file__).resolve().parent.parent / ".venv" / "bin" / "sentinel"
    result = subprocess.run(
        [str(sentinel), "wizard"],
        input="badservice\nbadintent\n\n",  # service, intent, empty-resource.
        capture_output=True,
        text=True,
        timeout=30,
    )

    assert result.returncode == EXIT_INVALID_ARGS, (
        f"Expected EXIT_INVALID_ARGS ({EXIT_INVALID_ARGS}); got {result.returncode}. "
        f"stderr={result.stderr!r}"
    )
    # Combined stdout + stderr contains the expected guidance text — the
    # tool emits to stderr but some environments interleave them.
    combined = result.stdout + result.stderr
    assert "Recognized intents" in combined, (
        f"Missing 'Recognized intents:' guidance; got:\nstdout={result.stdout!r}\n"
        f"stderr={result.stderr!r}"
    )
    # Crucially: no wildcard fallback policy should be emitted.
    assert "service:*" not in result.stdout, (
        f"Wizard leaked `service:*` wildcard on an unrecognized intent — "
        f"stdout={result.stdout!r}"
    )


# ---------------------------------------------------------------------------
# Test 3 — P1-6 β: is_empty rejects injection attempt
# ---------------------------------------------------------------------------


def test_is_empty_rejects_sql_injection(tmp_path: Path) -> None:
    """Database.is_empty must reject names outside `_EXPECTED_TABLES`.

    Three paths:
    1. Real table with rows -> returns False.
    2. Unknown but benign name -> returns True (allowlist short-circuit).
    3. Classic SQL-injection payload -> returns True (allowlist reject);
       `actions` table must remain intact afterwards.
    """
    db_path = tmp_path / "test.db"
    db = Database(db_path)
    db.create_schema()

    # Seed one row so is_empty("services") can differentiate "empty" from
    # "has rows".
    with db.get_connection() as conn:
        conn.execute(
            "INSERT INTO services (service_prefix, service_name) VALUES (?, ?)",
            ("s3", "Amazon S3"),
        )
        conn.commit()

    # 1. Real whitelisted table with rows.
    assert db.is_empty("services") is False

    # 2. Unknown but benign name — allowlist returns True (safe short-circuit).
    assert db.is_empty("evil_table_does_not_exist") is True

    # 3. Classic SQL injection attempt — must not execute the DROP.
    assert db.is_empty("dangerous_actions; DROP TABLE actions;") is True

    # Verify `actions` table still exists (introspection).  The injection
    # payload must never have reached SQL.
    with db.get_connection() as conn:
        tables = {
            row[0]
            for row in conn.execute(
                "SELECT name FROM sqlite_master WHERE type='table'"
            )
        }
    assert "actions" in tables, (
        f"`actions` table missing after SQL-injection probe — "
        f"hardening failed. Tables: {sorted(tables)}"
    )


# ---------------------------------------------------------------------------
# Test 4 — P2-13 β: HMAC key refuse-to-load on broad POSIX perms
# ---------------------------------------------------------------------------


@pytest.mark.skipif(
    sys.platform == "win32", reason="POSIX perm check is platform-guarded"
)
def test_hmac_refuses_to_load_on_broad_perms(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """An existing cache.key with group/world-readable perms must raise
    HMACError BEFORE the bytes are read.  A tool regression that dropped
    the platform check or the `mode & 0o077` test would silently resume
    loading a compromised key.
    """
    import sentinel.hmac_keys as hk

    # Point the data dir at a sandbox so we don't touch the real key.
    monkeypatch.setenv("SENTINEL_DATA_DIR", str(tmp_path))

    # Write a syntactically-valid 32-byte key then chmod it to 0o644
    # (world-readable).  The check fires on the perm bits, not the
    # contents, so a correct-sized key still triggers HMACError.
    key_file = tmp_path / "cache.key"
    key_file.write_bytes(b"\x00" * 32)
    os.chmod(key_file, 0o644)

    # Reset the process-level key cache so _load_or_create_root_key
    # re-reads the on-disk file.
    hk._root_key_cached = None

    with pytest.raises(HMACError, match=r"0o600|rotate-key"):
        hk._load_or_create_root_key()

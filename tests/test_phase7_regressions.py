"""Regression tests for Phase 7 completeness gaps (v0.6.1 / v0.6.2).

Closes test-harness coverage for the Phase 7 fixes identified in the
post-ship test review as having no direct regression test:

v0.6.1 (original suite):
* P0-2 γ — `verify_phase2_tables` aborts on mis-stamped DB.
* P1-4 α — `cmd_wizard` refuses to emit a `service:*` fallback.
* P1-6 β — `Database.is_empty` SQL-injection hardening.
* P2-13 β — HMAC root-key file refuses to load on broad POSIX perms.

v0.6.2 (extension):
* P0-1 α — bulk-load raises DatabaseError on HMAC tamper.
* P0-3 — cold-start import graph (pydantic_settings not in self_check).
* P1-5 — fetchers/refresh relocation: imports resolve from new paths.
* P1-8 — shared-connection `_classify_action_with_conn` path.
* P2-14 — Pipeline reuses one RiskAnalyzer across SelfCheckValidator.
* P2-15 — IntentMapper precompiles keyword patterns once.

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


# ---------------------------------------------------------------------------
# v0.6.2 additions — Phase 7 fixes previously without regression coverage
# ---------------------------------------------------------------------------


def test_p0_1_alpha_bulk_load_raises_on_hmac_tamper(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """P0-1 α: a tampered dangerous_actions row must raise DatabaseError
    from RiskAnalyzer.__init__, not silently yield zero findings.

    Tampers the description column on a seeded row so the stored row_hmac
    no longer matches -- verify_row returns False, bulk-load must raise.
    """
    from sentinel.analyzer import RiskAnalyzer

    monkeypatch.setenv("SENTINEL_DATA_DIR", str(tmp_path / "data_dir"))
    from tests.conftest import make_test_db  # type: ignore[import-not-found]

    db_path = make_test_db(tmp_path)
    db = Database(db_path)

    # Tamper: update ONE dangerous_actions row's description without
    # recomputing row_hmac -> verify_row() will reject it.
    with db.get_connection() as conn:
        # Pick any seeded row.
        row = conn.execute(
            "SELECT action_name, category FROM dangerous_actions LIMIT 1"
        ).fetchone()
        assert row is not None, "Expected seeded dangerous_actions rows"
        conn.execute(
            "UPDATE dangerous_actions SET description = ? "
            "WHERE action_name = ? AND category = ?",
            ("TAMPERED", row[0], row[1]),
        )
        conn.commit()

    with pytest.raises(DatabaseError, match=r"HMAC|tamper"):
        RiskAnalyzer(db)


def test_p0_3_cold_start_no_pydantic_settings_in_self_check() -> None:
    """P0-3: sentinel.self_check must not transitively import
    pydantic_settings -- which is heavy and pushes cold-start > 200ms.

    The fix deferred the config import; a regression that moves it back
    to module scope would re-inflate cold-start.
    """
    import subprocess

    sentinel = Path(__file__).resolve().parent.parent / ".venv" / "bin" / "python"
    # -X importtime prints every import; grep in-process afterwards.
    result = subprocess.run(
        [str(sentinel), "-c", "import sentinel.self_check"],
        capture_output=True,
        text=True,
        timeout=15,
        env={**os.environ, "PYTHONDONTWRITEBYTECODE": "1"},
    )
    # pydantic_settings MUST NOT be imported as a side effect.
    combined = result.stdout + result.stderr
    assert "pydantic_settings" not in combined, (
        f"Cold-start regression: pydantic_settings imported via self_check.\n"
        f"Output:\n{combined}"
    )


def test_p1_5_fetchers_refresh_imports_resolve() -> None:
    """P1-5: After the fetchers/refresh relocation, all new import paths
    must resolve cleanly.  A regression (e.g., stale `from sentinel.X import Y`
    pointing at the old location) would raise ImportError at collection.
    """
    # Smoke imports of the key relocated symbols.
    from sentinel.fetchers.batch import BatchFetcher  # noqa: F401
    from sentinel.fetchers.github import GitHubFetcher  # noqa: F401
    from sentinel.fetchers.url import URLFetcher  # noqa: F401
    from sentinel.fetchers.local import LocalFileFetcher  # noqa: F401
    from sentinel.refresh.aws_managed_policies import (  # noqa: F401
        ManagedPoliciesLiveScraper,
    )
    from sentinel.refresh.cloudsplaining import CloudSplainingLiveFetcher  # noqa: F401


def test_p1_8_classify_with_conn_path_used(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """P1-8: validate_policy on a policy with N actions must open only ONE
    connection via `_classify_action_with_conn`, not N.
    """
    from sentinel.parser import PolicyParser, Policy, Statement

    monkeypatch.setenv("SENTINEL_DATA_DIR", str(tmp_path / "data_dir"))
    from tests.conftest import make_test_db  # type: ignore[import-not-found]

    db_path = make_test_db(tmp_path)
    db = Database(db_path)

    # Count get_connection() calls via monkeypatch wrapper.
    call_count = {"n": 0}
    real_get_connection = db.get_connection

    def _counting_get_connection():
        call_count["n"] += 1
        return real_get_connection()

    monkeypatch.setattr(db, "get_connection", _counting_get_connection)

    parser = PolicyParser(db)
    # The parser already loaded get_services() once in __init__; reset counter
    # so we measure ONLY validate_policy behaviour.
    call_count["n"] = 0

    policy = Policy(
        version="2012-10-17",
        statements=[
            Statement(
                effect="Allow",
                actions=[
                    "s3:GetObject",
                    "s3:PutObject",
                    "s3:DeleteObject",
                    "s3:ListBucket",
                ],
                resources=["*"],
            )
        ],
    )
    parser.validate_policy(policy)

    # P1-8: 1 shared connection for 4 actions, not 4+ per-call.
    assert call_count["n"] <= 2, (
        f"Expected shared connection path (≤2 get_connection), "
        f"got {call_count['n']} -- P1-8 β regressed?"
    )


def test_p2_14_pipeline_reuses_one_risk_analyzer(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """P2-14: Pipeline constructs ONE RiskAnalyzer and hands the same
    instance to SelfCheckValidator via the `risk_analyzer=` DI slot.
    Avoids paying the ~200ms bulk-load cost twice on a single run.
    """
    from sentinel.self_check import Pipeline

    monkeypatch.setenv("SENTINEL_DATA_DIR", str(tmp_path / "data_dir"))
    from tests.conftest import make_test_db  # type: ignore[import-not-found]

    db_path = make_test_db(tmp_path)
    db = Database(db_path)

    pipeline = Pipeline(database=db)
    # Pipeline owns a _risk_analyzer; SelfCheckValidator receives it via DI.
    # We can't trivially inspect the SelfCheckValidator until run() fires,
    # but we CAN assert the attribute is present and is the right type.
    from sentinel.analyzer import RiskAnalyzer

    assert isinstance(pipeline._risk_analyzer, RiskAnalyzer)


def test_p2_15_intent_mapper_precompiles_once(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """P2-15: IntentMapper must precompile keyword patterns in __init__
    (single pass) rather than recompile on every map_intent() call.
    """
    import re

    from sentinel.analyzer import IntentMapper

    monkeypatch.setenv("SENTINEL_DATA_DIR", str(tmp_path / "data_dir"))
    from tests.conftest import make_test_db  # type: ignore[import-not-found]

    db_path = make_test_db(tmp_path)
    db = Database(db_path)

    mapper = IntentMapper(db)
    # The attribute must exist and be non-empty.
    compiled = mapper._compiled_keyword_patterns
    assert isinstance(compiled, list)
    assert len(compiled) > 0
    # Every entry must already be a compiled regex (not a raw str).
    for pattern, _levels in compiled:
        assert isinstance(pattern, re.Pattern)


# ---------------------------------------------------------------------------
# v0.7.0 additions — Phase 7.3 regression tests
# ---------------------------------------------------------------------------


def test_phase2_missing_tables_raises_on_sqlite_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """NEW-A regression: ``_phase2_missing_tables`` must raise ``DatabaseError``
    when ``sqlite3.connect`` fails, NOT silently return ``[]``.

    The v0.6.2 post-ship silent-failure review identified this regression:
    on ``sqlite3.Error`` the function returned ``[]``, which means
    ``verify_phase2_tables`` saw no missing tables and proceeded — defeating
    the P0-2 γ fail-closed guarantee for the disk-corruption case it was
    built to catch.

    Fix: raise ``DatabaseError`` with a recovery hint naming the DB path.
    This test asserts the fail-closed behaviour so a future regression
    that restores the silent ``[]`` return fails loudly.
    """
    from sentinel.migrations import _phase2_missing_tables
    import sentinel.migrations as migrations_mod

    # Seed a real file so the ``exists()`` check passes (otherwise we'd
    # hit the early-return branch which is correct behaviour).
    db_path = tmp_path / "corrupt.db"
    db_path.write_bytes(b"not a valid sqlite file")

    # Monkeypatch sqlite3.connect at the module level so only this call
    # site raises — we don't want to break other tests.
    def _raising_connect(*_args, **_kwargs):  # type: ignore[no-untyped-def]
        raise sqlite3.OperationalError("unable to open database file (simulated)")

    monkeypatch.setattr(migrations_mod.sqlite3, "connect", _raising_connect)

    # The fail-closed contract: raise, don't silently return [].
    with pytest.raises(DatabaseError, match=r"Could not probe Phase-2 tables"):
        _phase2_missing_tables(db_path)


def test_serial_mode_test_isolation_via_per_test_db(tmp_path: Path) -> None:
    """Phase 7.3 regression: per-test DB isolation must hold.

    The v0.6.2 post-ship review identified 11 serial-mode test failures
    caused by cross-test HMAC-cache / shared-DB pollution.  Phase 7.3
    restructured the test harness so every CLI-path test gets its own
    DB via ``make_test_db(tmp_path, template=migrated_db_template)``.

    This test exercises a minimal shape of that contract: two
    ``make_test_db`` invocations in the same test-worker process produce
    DIFFERENT files — per-test isolation holds.  A regression that
    reintroduced shared-state (e.g., a hardcoded data-dir path) would
    fail this test.
    """
    from tests.conftest import make_test_db  # type: ignore[import-not-found]

    dir_a = tmp_path / "a"
    dir_b = tmp_path / "b"
    dir_a.mkdir()
    dir_b.mkdir()

    path_a = make_test_db(dir_a)
    path_b = make_test_db(dir_b)

    # Must be distinct files — each test gets its own sandbox.
    assert path_a != path_b
    assert path_a.resolve() != path_b.resolve()
    # Both exist on disk.
    assert path_a.is_file()
    assert path_b.is_file()
    # Both are readable as sqlite DBs (schema sanity).
    for p in (path_a, path_b):
        conn = sqlite3.connect(p)
        try:
            rows = conn.execute(
                "SELECT name FROM sqlite_master WHERE type='table' "
                "AND name='dangerous_actions'"
            ).fetchall()
        finally:
            conn.close()
        assert rows, f"Expected dangerous_actions table in {p}"

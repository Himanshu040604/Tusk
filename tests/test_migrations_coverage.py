"""Security-critical coverage tests for ``sentinel.migrations``.

Targets the previously-uncovered paths (v0.6.1 coverage: 72%):

* ``_phase2_missing_tables`` with non-existent DB / unreadable DB.
* ``check_and_upgrade_all_dbs`` skip-via-env-var + skip-via-flag branches.
* ``check_and_upgrade_db`` backwards-compat alias.
* ``_checkpoint_and_backup`` produces .bak file with full content.
* ``_current_revision`` narrow-except branches (Architect Concern 2).

Per phase7_postship_review_tests.md § "Dimension B — coverage analysis".
"""

from __future__ import annotations

from pathlib import Path

import pytest

from sentinel.migrations import (
    _checkpoint_and_backup,
    _current_revision,
    _phase2_missing_tables,
    check_and_upgrade_all_dbs,
    check_and_upgrade_db,
)


# ---------------------------------------------------------------------------
# _phase2_missing_tables fast paths
# ---------------------------------------------------------------------------


def test_phase2_missing_tables_nonexistent_db(tmp_path: Path) -> None:
    """Missing DB file returns empty list (no mis-stamp to verify)."""
    missing = _phase2_missing_tables(tmp_path / "does_not_exist.db")
    assert missing == []


# ---------------------------------------------------------------------------
# Skip paths — env var + flag
# ---------------------------------------------------------------------------


def test_skip_via_env_var_short_circuits(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """SENTINEL_SKIP_MIGRATIONS=1 must emit [WARN] and return without
    touching the DB.  Exercises lines 358-365.
    """
    monkeypatch.setenv("SENTINEL_SKIP_MIGRATIONS", "1")
    db_path = tmp_path / "skipped.db"
    # Must NOT crash even with a non-existent path — the skip kicks in first.
    check_and_upgrade_all_dbs(db_path, None)
    # DB was never created -- migration was truly skipped.
    assert not db_path.exists()
    captured = capsys.readouterr()
    assert "[WARN]" in captured.err
    assert "SENTINEL_SKIP_MIGRATIONS=1" in captured.err


def test_skip_via_flag_short_circuits(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """skip=True kwarg emits [WARN] (--skip-migrations wording) and returns."""
    db_path = tmp_path / "skipped.db"
    check_and_upgrade_all_dbs(db_path, None, skip=True)
    assert not db_path.exists()
    captured = capsys.readouterr()
    assert "[WARN]" in captured.err
    assert "--skip-migrations" in captured.err


# ---------------------------------------------------------------------------
# Backwards-compat alias
# ---------------------------------------------------------------------------


def test_check_and_upgrade_db_alias_delegates(tmp_path: Path) -> None:
    """check_and_upgrade_db is the single-DB alias for backwards compat.
    A fresh path must migrate to HEAD and create the canonical schema.
    """
    db_path = tmp_path / "alias.db"
    check_and_upgrade_db(db_path)
    assert db_path.exists()
    # At least one expected Phase-2 table must now exist.
    import sqlite3

    conn = sqlite3.connect(str(db_path))
    try:
        tables = {r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")}
    finally:
        conn.close()
    assert "alembic_version" in tables
    assert "dangerous_actions" in tables  # Phase-2 table present.


# ---------------------------------------------------------------------------
# _checkpoint_and_backup round-trip
# ---------------------------------------------------------------------------


def test_checkpoint_and_backup_produces_bak_file(tmp_path: Path) -> None:
    """_checkpoint_and_backup writes <db>.bak with identical content."""
    import sqlite3

    db_path = tmp_path / "snap.db"
    conn = sqlite3.connect(str(db_path))
    try:
        conn.execute("CREATE TABLE t (x INT)")
        conn.execute("INSERT INTO t VALUES (42)")
        conn.commit()
    finally:
        conn.close()

    bak = _checkpoint_and_backup(db_path)
    assert bak.exists()
    assert bak.name == "snap.db.bak"
    # Verify content round-trip.
    conn = sqlite3.connect(str(bak))
    try:
        row = conn.execute("SELECT x FROM t").fetchone()
    finally:
        conn.close()
    assert row == (42,)


# ---------------------------------------------------------------------------
# _current_revision non-existent DB
# ---------------------------------------------------------------------------


def test_current_revision_on_nonexistent_db(tmp_path: Path) -> None:
    """Non-existent DB -> _current_revision returns None (fast path)."""
    assert _current_revision(tmp_path / "ghost.db") is None


def test_current_revision_on_unstamped_db(tmp_path: Path) -> None:
    """Fresh DB without alembic_version -> returns None cleanly.

    Exercises the MigrationContext branch that falls through to None
    when no revision row exists.
    """
    import sqlite3

    db_path = tmp_path / "unstamped.db"
    conn = sqlite3.connect(str(db_path))
    try:
        conn.execute("CREATE TABLE t (x INT)")
        conn.commit()
    finally:
        conn.close()
    # MigrationContext on an Alembic-unstamped DB returns None -- not an error.
    assert _current_revision(db_path) is None

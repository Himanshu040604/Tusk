"""Alembic migration round-trip test (Amendment 6 Theme E1).

Asserts ``upgrade -> downgrade -> upgrade`` produces byte-identical
``sqlite_master`` for both the IAM actions and resource inventory DBs.
This is the Phase 6 guarantee that no migration silently leaves
orphaned objects on the downgrade path.
"""

from __future__ import annotations

import sqlite3
from pathlib import Path

import pytest
from alembic import command

from sentinel.migrations import _make_config, check_and_upgrade_all_dbs


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _normalize_sql(sql: str | None) -> str:
    """Collapse runs of whitespace so cosmetic indentation doesn't affect equality.

    Alembic's ``op.execute`` and ``Database.create_schema`` both emit the
    same DDL but with different indentation (Alembic strips the outer
    triple-quote indent; ``create_schema`` keeps it).  The resulting
    ``sqlite_master.sql`` column differs only in whitespace — which is
    semantically irrelevant for schema drift detection.
    """
    if sql is None:
        return ""
    return " ".join(sql.split())


def _sqlite_master_snapshot(db_path: Path) -> list[tuple]:
    """Return a sorted snapshot of ``sqlite_master`` as comparable tuples.

    Excludes ``alembic_version`` bookkeeping (the row itself changes on
    upgrade/downgrade) and any internal SQLite tables whose content is
    platform-dependent.  The ``sql`` column is whitespace-normalised so
    the comparison is semantic, not cosmetic.
    """
    conn = sqlite3.connect(db_path)
    try:
        cur = conn.execute(
            "SELECT type, name, tbl_name, sql "
            "FROM sqlite_master "
            "WHERE name NOT LIKE 'sqlite_%' "
            "  AND name != 'alembic_version' "
            "ORDER BY type, name"
        )
        rows = [(t, n, tn, _normalize_sql(s)) for (t, n, tn, s) in cur.fetchall()]
        return sorted(rows)
    finally:
        conn.close()


# ---------------------------------------------------------------------------
# IAM DB round-trip
# ---------------------------------------------------------------------------


class TestIamDbRoundtrip:
    def test_upgrade_downgrade_upgrade_idempotent(self, tmp_path: Path) -> None:
        db = tmp_path / "iam.db"

        # First upgrade — fresh empty DB.
        check_and_upgrade_all_dbs(db, None)
        snap_after_first_upgrade = _sqlite_master_snapshot(db)
        assert snap_after_first_upgrade, "upgrade should have created tables"

        # Downgrade to base.
        cfg = _make_config(db, "iam")
        command.downgrade(cfg, "base")
        snap_after_downgrade = _sqlite_master_snapshot(db)
        # After downgrade to base, only alembic_version should remain (which
        # we strip in the snapshot) — user tables all gone.
        assert snap_after_downgrade == [], (
            f"downgrade left residual objects: {snap_after_downgrade}"
        )

        # Upgrade again.
        command.upgrade(cfg, "head")
        snap_after_second_upgrade = _sqlite_master_snapshot(db)

        assert snap_after_first_upgrade == snap_after_second_upgrade, (
            "upgrade->downgrade->upgrade produced drifted schema"
        )


# ---------------------------------------------------------------------------
# Inventory DB round-trip
# ---------------------------------------------------------------------------


class TestInventoryDbRoundtrip:
    def test_upgrade_downgrade_upgrade_idempotent(self, tmp_path: Path) -> None:
        iam_db = tmp_path / "iam.db"
        inv_db = tmp_path / "inventory.db"
        # Touch the inventory file so check_and_upgrade_all_dbs handles it.
        inv_db.touch()
        check_and_upgrade_all_dbs(iam_db, inv_db)

        snap_first = _sqlite_master_snapshot(inv_db)
        assert snap_first, "inventory migration should have created tables"

        cfg = _make_config(inv_db, "inventory")
        command.downgrade(cfg, "base")
        snap_down = _sqlite_master_snapshot(inv_db)
        assert snap_down == [], f"inventory downgrade left residual objects: {snap_down}"

        command.upgrade(cfg, "head")
        snap_second = _sqlite_master_snapshot(inv_db)

        assert snap_first == snap_second, "inventory upgrade->downgrade->upgrade drifted"


# ---------------------------------------------------------------------------
# Schema drift — Database.create_schema() vs Alembic HEAD
# ---------------------------------------------------------------------------


class TestSchemaDrift:
    """Phase 2 Task 3 exit criterion — see also tests/test_alembic_drift.py.

    Duplicated here as a belt-and-braces check: a migration author who
    only runs the round-trip test still catches schema divergence.
    """

    def test_create_schema_matches_alembic_head_iam(self, tmp_path: Path) -> None:
        # Path A: Database(path).create_schema()
        from sentinel.database import Database

        path_a = tmp_path / "via_create_schema.db"
        Database(path_a).create_schema()
        snap_a = _sqlite_master_snapshot(path_a)

        # Path B: Alembic upgrade from empty.
        path_b = tmp_path / "via_alembic.db"
        check_and_upgrade_all_dbs(path_b, None)
        snap_b = _sqlite_master_snapshot(path_b)

        # Phase 2 establishes this equivalence — the TWO paths must match.
        # If they don't, a migration is missing or create_schema is stale.
        only_in_a = set(snap_a) - set(snap_b)
        only_in_b = set(snap_b) - set(snap_a)

        assert not (only_in_a or only_in_b), (
            f"schema drift:\n"
            f"  only in create_schema: {sorted(only_in_a)}\n"
            f"  only in alembic HEAD:  {sorted(only_in_b)}"
        )

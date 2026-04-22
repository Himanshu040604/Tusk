"""Alembic schema-drift test (Phase 2 Task 3 exit criterion).

Asserts ``sqlite_master`` from ``Database().create_schema()`` matches
``sqlite_master`` from an empty-DB Alembic upgrade for BOTH the IAM
actions and resource inventory schemas.  A mismatch indicates either:

* a missing migration, OR
* a ``create_schema()`` drift that never landed as a migration.

Either is a release-blocker — ``create_schema`` is the fallback for
library users who skip ``check_and_upgrade_all_dbs``, so the two paths
MUST stay in lock-step.
"""

from __future__ import annotations

import sqlite3
from pathlib import Path

import pytest

from sentinel.database import Database
from sentinel.inventory import ResourceInventory
from sentinel.migrations import check_and_upgrade_all_dbs


def _tables_and_indexes(db_path: Path) -> set[tuple[str, str]]:
    """Return ``{(type, name)}`` pairs for all user objects.

    Strips SQL body because formatting whitespace can differ trivially
    between ``CREATE TABLE`` issued from SQLAlchemy ORM vs hand-written
    migration DDL.  A missing / extra NAME is the only true drift signal.
    """
    conn = sqlite3.connect(db_path)
    try:
        cur = conn.execute(
            "SELECT type, name FROM sqlite_master "
            "WHERE name NOT LIKE 'sqlite_%' "
            "  AND name != 'alembic_version' "
        )
        return {tuple(row) for row in cur.fetchall()}
    finally:
        conn.close()


class TestIamSchemaDrift:
    def test_create_schema_matches_alembic(self, tmp_path: Path) -> None:
        a = tmp_path / "create_schema.db"
        b = tmp_path / "alembic.db"

        Database(a).create_schema()
        check_and_upgrade_all_dbs(b, None)

        sa = _tables_and_indexes(a)
        sb = _tables_and_indexes(b)

        only_in_create = sa - sb
        only_in_alembic = sb - sa
        assert not only_in_create, (
            f"objects present in create_schema but missing in Alembic "
            f"HEAD: {sorted(only_in_create)}"
        )
        assert not only_in_alembic, (
            f"objects present in Alembic HEAD but missing in "
            f"create_schema: {sorted(only_in_alembic)}"
        )


class TestInventorySchemaDrift:
    def test_create_schema_matches_alembic(self, tmp_path: Path) -> None:
        a = tmp_path / "create_schema.db"
        b = tmp_path / "alembic.db"
        iam_placeholder = tmp_path / "iam.db"

        ResourceInventory(a).create_schema()

        # check_and_upgrade_all_dbs requires an iam path too.
        b.touch()
        check_and_upgrade_all_dbs(iam_placeholder, b)

        sa = _tables_and_indexes(a)
        sb = _tables_and_indexes(b)

        only_in_create = sa - sb
        only_in_alembic = sb - sa
        assert not only_in_create, (
            f"inventory objects in create_schema but missing in Alembic "
            f"HEAD: {sorted(only_in_create)}"
        )
        assert not only_in_alembic, (
            f"inventory objects in Alembic HEAD but missing in "
            f"create_schema: {sorted(only_in_alembic)}"
        )

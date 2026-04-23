"""Initial resource inventory schema — baseline (Amendment 6 Theme E2).

Byte-replicates the schema produced by
``src/sentinel/inventory.py::create_schema()``.  Required for dual-DB Alembic
(M18) — without this baseline, ``alembic -n inventory stamp head`` fails
with "can't locate revision" when ``check_and_upgrade_all_dbs()`` probes an
existing inventory DB.

Revision ID: 0001_initial_inventory
Revises:
Create Date: 2026-04-22
"""

from __future__ import annotations

from typing import Sequence, Union

from alembic import op

revision: str = "0001_initial_inventory"
down_revision: str | None = None
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.execute("""
        CREATE TABLE IF NOT EXISTS resources (
            resource_id INTEGER PRIMARY KEY AUTOINCREMENT,
            service_prefix TEXT NOT NULL,
            resource_type TEXT NOT NULL,
            resource_arn TEXT UNIQUE NOT NULL,
            resource_name TEXT,
            region TEXT,
            account_id TEXT,
            metadata TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)
    op.execute("CREATE INDEX IF NOT EXISTS idx_resources_service ON resources(service_prefix)")
    op.execute("CREATE INDEX IF NOT EXISTS idx_resources_type ON resources(resource_type)")
    op.execute("CREATE INDEX IF NOT EXISTS idx_resources_arn ON resources(resource_arn)")
    op.execute("CREATE INDEX IF NOT EXISTS idx_resources_account ON resources(account_id)")
    op.execute("CREATE INDEX IF NOT EXISTS idx_resources_region ON resources(region)")
    op.execute(
        "CREATE INDEX IF NOT EXISTS idx_resources_service_type "
        "ON resources(service_prefix, resource_type)"
    )
    op.execute("""
        CREATE TABLE IF NOT EXISTS inventory_metadata (
            key TEXT PRIMARY KEY,
            value TEXT NOT NULL,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)
    op.execute(
        "INSERT OR IGNORE INTO inventory_metadata (key, value, updated_at) "
        "VALUES ('schema_version', '1.0', CURRENT_TIMESTAMP)"
    )


def downgrade() -> None:
    op.execute("DROP TABLE IF EXISTS inventory_metadata")
    op.execute("DROP TABLE IF EXISTS resources")

"""Add action_resource_map table.

Replaces ``rewriter.py``'s ``ACTION_RESOURCE_MAP`` Python dict.  Simple
membership lookups — NOT HMAC-signed (per Theme G1: HMAC scope is limited
to regex/classification-authority tables).

Revision ID: 0006_add_action_resource_map
Revises: 0005_add_dangerous_combinations
Create Date: 2026-04-22
"""

from __future__ import annotations

from typing import Sequence, Union

from alembic import op

revision: str = "0006_add_action_resource_map"
down_revision: str | None = "0005_add_dangerous_combinations"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.execute("""
        CREATE TABLE IF NOT EXISTS action_resource_map (
            action_name TEXT NOT NULL,
            resource_type TEXT NOT NULL,
            PRIMARY KEY (action_name, resource_type)
        )
    """)


def downgrade() -> None:
    op.execute("DROP TABLE IF EXISTS action_resource_map")

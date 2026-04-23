"""Add dangerous_combinations table with HMAC row signing support.

Action pairs that are safe alone but dangerous together (e.g.
``iam:PassRole`` + ``iam:CreateAccessKey``).  Rows HMAC-signed via K_db.

Includes H16 covering index ``idx_dc_action_b(action_b, action_a)`` for
reverse-direction lookups.

Revision ID: 0005_add_dangerous_combinations
Revises: 0004_add_companion_rules
Create Date: 2026-04-22
"""
from __future__ import annotations

from typing import Sequence, Union

from alembic import op

revision: str = "0005_add_dangerous_combinations"
down_revision: str | None = "0004_add_companion_rules"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.execute("""
        CREATE TABLE IF NOT EXISTS dangerous_combinations (
            action_a TEXT NOT NULL,
            action_b TEXT NOT NULL,
            severity TEXT NOT NULL
                CHECK (severity IN ('CRITICAL','HIGH','MEDIUM','LOW')),
            description TEXT NOT NULL,
            source TEXT NOT NULL
                CHECK (source IN ('policy_sentry','aws-docs','shipped','managed-policies','cloudsplaining')),
            refreshed_at TIMESTAMP NOT NULL,
            row_hmac TEXT NOT NULL,
            PRIMARY KEY (action_a, action_b)
        )
    """)
    op.execute(
        "CREATE INDEX IF NOT EXISTS idx_dc_action_b "
        "ON dangerous_combinations(action_b, action_a)"
    )


def downgrade() -> None:
    op.execute("DROP INDEX IF EXISTS idx_dc_action_b")
    op.execute("DROP TABLE IF EXISTS dangerous_combinations")

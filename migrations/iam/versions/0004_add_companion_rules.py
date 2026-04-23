"""Add companion_rules table with HMAC row signing support.

Replaces ``analyzer.py``'s ``COMPANION_RULES`` class-level dict.  Rows are
HMAC-signed per Task 6a (K_db sub-key).

Revision ID: 0004_add_companion_rules
Revises: 0003_add_dangerous_actions
Create Date: 2026-04-22
"""

from __future__ import annotations

from typing import Sequence, Union

from alembic import op

revision: str = "0004_add_companion_rules"
down_revision: str | None = "0003_add_dangerous_actions"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.execute("""
        CREATE TABLE IF NOT EXISTS companion_rules (
            primary_action TEXT NOT NULL,
            companion_action TEXT NOT NULL,
            reason TEXT NOT NULL,
            severity TEXT NOT NULL
                CHECK (severity IN ('CRITICAL','HIGH','MEDIUM','LOW')),
            source TEXT NOT NULL
                CHECK (source IN ('policy_sentry','aws-docs','shipped','managed-policies','cloudsplaining')),
            refreshed_at TIMESTAMP NOT NULL,
            row_hmac TEXT NOT NULL,
            PRIMARY KEY (primary_action, companion_action)
        )
    """)


def downgrade() -> None:
    op.execute("DROP TABLE IF EXISTS companion_rules")

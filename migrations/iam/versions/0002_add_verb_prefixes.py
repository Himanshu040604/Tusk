"""Add verb_prefixes table.

AWS action-name verb conventions (``Get``, ``List``, ``Put``, ``Delete``, etc.)
mapped to a coarse access category (``read`` / ``write`` / ``admin``).  Used
by ``analyzer.py`` heuristics when an action isn't in the policy_sentry
dataset yet (Tier 2 plausible-but-unknown).

Revision ID: 0002_add_verb_prefixes
Revises: 0001_initial_schema
Create Date: 2026-04-22
"""

from __future__ import annotations

from typing import Sequence, Union

from alembic import op

revision: str = "0002_add_verb_prefixes"
down_revision: str | None = "0001_initial_schema"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.execute("""
        CREATE TABLE IF NOT EXISTS verb_prefixes (
            prefix TEXT PRIMARY KEY,
            access_category TEXT NOT NULL
                CHECK (access_category IN ('read','write','admin')),
            source TEXT NOT NULL
                CHECK (source IN ('policy_sentry','aws-docs','shipped','managed-policies','cloudsplaining')),
            refreshed_at TIMESTAMP NOT NULL
        )
    """)


def downgrade() -> None:
    op.execute("DROP TABLE IF EXISTS verb_prefixes")

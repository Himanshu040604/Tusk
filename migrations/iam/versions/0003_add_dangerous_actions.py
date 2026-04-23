"""Add dangerous_actions table with HMAC row signing support.

Replaces the ``PRIVILEGE_ESCALATION_ACTIONS`` / ``DATA_EXFILTRATION_PATTERNS``
/ ``DESTRUCTION_PATTERNS`` / ``PERMISSIONS_MGMT_PATTERNS`` class constants
in ``analyzer.py``.  Rows are HMAC-signed per Task 6a (Amendment 6 Theme D
domain-separated K_db sub-key) — signature verified at ``RiskAnalyzer``
bulk-load time; mismatch raises ``DatabaseError``.

Includes covering index ``idx_dangerous_category(category, action_name)``
per H14 (category-first queries like "find all privilege_escalation").

Revision ID: 0003_add_dangerous_actions
Revises: 0002_add_verb_prefixes
Create Date: 2026-04-22
"""
from __future__ import annotations

from typing import Sequence, Union

from alembic import op

revision: str = "0003_add_dangerous_actions"
down_revision: str | None = "0002_add_verb_prefixes"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.execute("""
        CREATE TABLE IF NOT EXISTS dangerous_actions (
            action_name TEXT NOT NULL,
            category TEXT NOT NULL
                CHECK (category IN ('privilege_escalation','exfiltration','destruction','permissions_mgmt')),
            severity TEXT NOT NULL
                CHECK (severity IN ('CRITICAL','HIGH','MEDIUM','LOW')),
            description TEXT NOT NULL,
            source TEXT NOT NULL
                CHECK (source IN ('policy_sentry','aws-docs','shipped','managed-policies','cloudsplaining')),
            refreshed_at TIMESTAMP NOT NULL,
            row_hmac TEXT NOT NULL,
            PRIMARY KEY (action_name, category)
        )
    """)
    # H14: covering index for category-first lookups.
    op.execute(
        "CREATE INDEX IF NOT EXISTS idx_dangerous_category "
        "ON dangerous_actions(category, action_name)"
    )


def downgrade() -> None:
    op.execute("DROP INDEX IF EXISTS idx_dangerous_category")
    op.execute("DROP TABLE IF EXISTS dangerous_actions")

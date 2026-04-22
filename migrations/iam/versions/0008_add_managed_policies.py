"""Add managed_policies table with policy_document_hmac column (M12).

AWS managed policies scraped from documentation.  The full
``policy_document`` JSON is HMAC-SHA256-signed (K_db sub-key) to prevent
on-disk tampering injecting a malicious "trusted" policy.

M17 query discipline: ``SELECT * FROM managed_policies`` is banned outside
``migrations/versions/`` — ``policy_document`` is ~6 KB per row; a 1000-row
table means accidental full-load costs ~6 MB.  Use the explicit column
list in ``Database.list_managed_policies()``.

Revision ID: 0008_add_managed_policies
Revises: 0007_add_arn_templates
Create Date: 2026-04-22
"""
from __future__ import annotations

from typing import Sequence, Union

from alembic import op

revision: str = "0008_add_managed_policies"
down_revision: Union[str, None] = "0007_add_arn_templates"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.execute("""
        CREATE TABLE IF NOT EXISTS managed_policies (
            policy_name TEXT PRIMARY KEY,
            policy_arn TEXT NOT NULL,
            policy_document TEXT NOT NULL,
            description TEXT,
            version TEXT,
            fetched_at TIMESTAMP NOT NULL,
            policy_document_hmac TEXT NOT NULL
        )
    """)


def downgrade() -> None:
    op.execute("DROP TABLE IF EXISTS managed_policies")

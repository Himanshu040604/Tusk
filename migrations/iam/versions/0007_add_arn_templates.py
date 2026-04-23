"""Add arn_templates table.

Replaces ``rewriter.py``'s ``ARN_TEMPLATES`` Python dict.  NOT HMAC-signed
(Theme G1 — simple membership lookup).

Revision ID: 0007_add_arn_templates
Revises: 0006_add_action_resource_map
Create Date: 2026-04-22
"""

from __future__ import annotations

from typing import Sequence, Union

from alembic import op

revision: str = "0007_add_arn_templates"
down_revision: str | None = "0006_add_action_resource_map"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.execute("""
        CREATE TABLE IF NOT EXISTS arn_templates (
            service_prefix TEXT NOT NULL,
            resource_type TEXT NOT NULL,
            arn_template TEXT NOT NULL,
            PRIMARY KEY (service_prefix, resource_type)
        )
    """)


def downgrade() -> None:
    op.execute("DROP TABLE IF EXISTS arn_templates")

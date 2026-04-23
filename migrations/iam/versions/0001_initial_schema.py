"""Initial IAM actions schema — baseline matching database.py::create_schema().

Byte-replicates the schema produced by ``src/sentinel/database.py::create_schema()``
so existing user DBs can be stamped at this revision via ``alembic stamp head``
without re-applying DDL.  Phase 6 drift-test (``test_alembic_roundtrip.py``)
asserts ``sqlite_master`` dumps match between a fresh-schema DB and a migrated
DB.

Revision ID: 0001_initial_schema
Revises:
Create Date: 2026-04-22

Downgrade mandate (Amendment 6 Theme E1): ``downgrade()`` drops every table
and index created by ``upgrade()``.  This enables the dual-DB saga recovery
path in § 14 (iam downgrades if inventory upgrade fails).
"""

from __future__ import annotations

from typing import Sequence, Union

from alembic import op

revision: str = "0001_initial_schema"
down_revision: str | None = None
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    # Services
    op.execute("""
        CREATE TABLE IF NOT EXISTS services (
            service_prefix TEXT PRIMARY KEY,
            service_name TEXT NOT NULL,
            service_authorization_url TEXT,
            api_reference_url TEXT,
            last_updated TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            data_version TEXT
        )
    """)
    op.execute("CREATE INDEX IF NOT EXISTS idx_services_name ON services(service_name)")

    # Actions
    op.execute("""
        CREATE TABLE IF NOT EXISTS actions (
            action_id INTEGER PRIMARY KEY AUTOINCREMENT,
            service_prefix TEXT NOT NULL,
            action_name TEXT NOT NULL,
            description TEXT,
            access_level TEXT NOT NULL
                CHECK(access_level IN ('List', 'Read', 'Write', 'Permissions management', 'Tagging')),
            is_permission_only BOOLEAN DEFAULT 0,
            reference_url TEXT,
            is_list BOOLEAN DEFAULT 0,
            is_read BOOLEAN DEFAULT 0,
            is_write BOOLEAN DEFAULT 0,
            is_permissions_management BOOLEAN DEFAULT 0,
            is_tagging_only BOOLEAN DEFAULT 0,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (service_prefix) REFERENCES services(service_prefix) ON DELETE CASCADE,
            UNIQUE(service_prefix, action_name)
        )
    """)
    op.execute("CREATE INDEX IF NOT EXISTS idx_actions_service ON actions(service_prefix)")
    op.execute("CREATE INDEX IF NOT EXISTS idx_actions_access_level ON actions(access_level)")
    op.execute(
        "CREATE INDEX IF NOT EXISTS idx_actions_is_write ON actions(is_write) WHERE is_write = 1"
    )
    op.execute(
        "CREATE INDEX IF NOT EXISTS idx_actions_is_permissions_mgmt "
        "ON actions(is_permissions_management) WHERE is_permissions_management = 1"
    )

    # Resource types
    op.execute("""
        CREATE TABLE IF NOT EXISTS resource_types (
            resource_type_id INTEGER PRIMARY KEY AUTOINCREMENT,
            service_prefix TEXT NOT NULL,
            resource_name TEXT NOT NULL,
            arn_pattern TEXT NOT NULL,
            reference_url TEXT,
            FOREIGN KEY (service_prefix) REFERENCES services(service_prefix) ON DELETE CASCADE,
            UNIQUE(service_prefix, resource_name)
        )
    """)
    op.execute(
        "CREATE INDEX IF NOT EXISTS idx_resource_types_service ON resource_types(service_prefix)"
    )

    # Action-Resource join
    op.execute("""
        CREATE TABLE IF NOT EXISTS action_resource_types (
            action_id INTEGER NOT NULL,
            resource_type_id INTEGER NOT NULL,
            is_required BOOLEAN DEFAULT 1,
            PRIMARY KEY (action_id, resource_type_id),
            FOREIGN KEY (action_id) REFERENCES actions(action_id) ON DELETE CASCADE,
            FOREIGN KEY (resource_type_id) REFERENCES resource_types(resource_type_id) ON DELETE CASCADE
        )
    """)
    op.execute(
        "CREATE INDEX IF NOT EXISTS idx_action_resources_action ON action_resource_types(action_id)"
    )
    op.execute(
        "CREATE INDEX IF NOT EXISTS idx_action_resources_resource "
        "ON action_resource_types(resource_type_id)"
    )

    # Condition keys
    op.execute("""
        CREATE TABLE IF NOT EXISTS condition_keys (
            condition_key_id INTEGER PRIMARY KEY AUTOINCREMENT,
            service_prefix TEXT NOT NULL,
            condition_key_name TEXT NOT NULL,
            description TEXT,
            condition_type TEXT
                CHECK(condition_type IN (
                    'String', 'Numeric', 'Date', 'Boolean', 'Binary',
                    'IPAddress', 'ARN', 'Null',
                    'ArrayOfString', 'ArrayOfARN', 'ArrayOfBool',
                    'Long', 'Integer', 'Float'
                )),
            reference_url TEXT,
            is_global BOOLEAN DEFAULT 0,
            FOREIGN KEY (service_prefix) REFERENCES services(service_prefix) ON DELETE CASCADE,
            UNIQUE(service_prefix, condition_key_name)
        )
    """)
    op.execute(
        "CREATE INDEX IF NOT EXISTS idx_condition_keys_service ON condition_keys(service_prefix)"
    )
    op.execute(
        "CREATE INDEX IF NOT EXISTS idx_condition_keys_global "
        "ON condition_keys(is_global) WHERE is_global = 1"
    )

    # Action-Condition join
    op.execute("""
        CREATE TABLE IF NOT EXISTS action_condition_keys (
            action_id INTEGER NOT NULL,
            condition_key_id INTEGER NOT NULL,
            PRIMARY KEY (action_id, condition_key_id),
            FOREIGN KEY (action_id) REFERENCES actions(action_id) ON DELETE CASCADE,
            FOREIGN KEY (condition_key_id) REFERENCES condition_keys(condition_key_id) ON DELETE CASCADE
        )
    """)
    op.execute(
        "CREATE INDEX IF NOT EXISTS idx_action_conditions_action "
        "ON action_condition_keys(action_id)"
    )
    op.execute(
        "CREATE INDEX IF NOT EXISTS idx_action_conditions_condition "
        "ON action_condition_keys(condition_key_id)"
    )

    # Dependent actions
    op.execute("""
        CREATE TABLE IF NOT EXISTS action_dependent_actions (
            action_id INTEGER NOT NULL,
            depends_on_action_id INTEGER NOT NULL,
            PRIMARY KEY (action_id, depends_on_action_id),
            FOREIGN KEY (action_id) REFERENCES actions(action_id) ON DELETE CASCADE,
            FOREIGN KEY (depends_on_action_id) REFERENCES actions(action_id) ON DELETE CASCADE,
            CHECK (action_id != depends_on_action_id)
        )
    """)
    op.execute(
        "CREATE INDEX IF NOT EXISTS idx_dependent_actions_action "
        "ON action_dependent_actions(action_id)"
    )
    op.execute(
        "CREATE INDEX IF NOT EXISTS idx_dependent_actions_depends "
        "ON action_dependent_actions(depends_on_action_id)"
    )

    # Resource-Condition join
    op.execute("""
        CREATE TABLE IF NOT EXISTS arn_condition_keys (
            resource_type_id INTEGER NOT NULL,
            condition_key_id INTEGER NOT NULL,
            PRIMARY KEY (resource_type_id, condition_key_id),
            FOREIGN KEY (resource_type_id) REFERENCES resource_types(resource_type_id) ON DELETE CASCADE,
            FOREIGN KEY (condition_key_id) REFERENCES condition_keys(condition_key_id) ON DELETE CASCADE
        )
    """)
    op.execute(
        "CREATE INDEX IF NOT EXISTS idx_arn_conditions_resource "
        "ON arn_condition_keys(resource_type_id)"
    )
    op.execute(
        "CREATE INDEX IF NOT EXISTS idx_arn_conditions_condition "
        "ON arn_condition_keys(condition_key_id)"
    )

    # Metadata
    op.execute("""
        CREATE TABLE IF NOT EXISTS metadata (
            key TEXT PRIMARY KEY,
            value TEXT NOT NULL,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)
    op.execute(
        "INSERT OR IGNORE INTO metadata (key, value, updated_at) "
        "VALUES ('schema_version', '1.0', CURRENT_TIMESTAMP)"
    )
    op.execute("""
        INSERT OR IGNORE INTO metadata (key, value, updated_at) VALUES
            ('data_source', 'AWS Service Authorization Reference', CURRENT_TIMESTAMP),
            ('last_full_update', CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
    """)

    # Validation errors
    op.execute("""
        CREATE TABLE IF NOT EXISTS validation_errors (
            error_id INTEGER PRIMARY KEY AUTOINCREMENT,
            policy_id TEXT,
            error_type TEXT NOT NULL,
            error_message TEXT NOT NULL,
            action_name TEXT,
            severity TEXT CHECK(severity IN ('ERROR', 'WARNING', 'INFO')),
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)
    op.execute(
        "CREATE INDEX IF NOT EXISTS idx_validation_errors_policy ON validation_errors(policy_id)"
    )
    op.execute(
        "CREATE INDEX IF NOT EXISTS idx_validation_errors_severity ON validation_errors(severity)"
    )


def downgrade() -> None:
    # Drop in reverse dependency order (child tables first).
    op.execute("DROP TABLE IF EXISTS validation_errors")
    op.execute("DROP TABLE IF EXISTS metadata")
    op.execute("DROP TABLE IF EXISTS arn_condition_keys")
    op.execute("DROP TABLE IF EXISTS action_dependent_actions")
    op.execute("DROP TABLE IF EXISTS action_condition_keys")
    op.execute("DROP TABLE IF EXISTS condition_keys")
    op.execute("DROP TABLE IF EXISTS action_resource_types")
    op.execute("DROP TABLE IF EXISTS resource_types")
    op.execute("DROP TABLE IF EXISTS actions")
    op.execute("DROP TABLE IF EXISTS services")

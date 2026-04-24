"""Database interface for IAM Policy Sentinel.

This module provides SQLite database operations for storing and querying
IAM actions, services, resource types, and condition keys.
"""

import sqlite3
from dataclasses import dataclass
from pathlib import Path
from typing import List, Optional, Dict, Any, Tuple, Iterator
from contextlib import contextmanager

from .constants import SCHEMA_VERSION


@dataclass
class Service:
    """AWS Service data model.

    Attributes:
        service_prefix: AWS service prefix (e.g., 's3', 'ec2', 'iam')
        service_name: Full service name (e.g., 'Amazon S3')
        service_authorization_url: URL to AWS service authorization docs
        api_reference_url: URL to API reference documentation
        data_version: Version of the service data
    """

    service_prefix: str
    service_name: str
    service_authorization_url: str | None = None
    api_reference_url: str | None = None
    data_version: str | None = None


@dataclass
class Action:
    """IAM Action data model.

    Attributes:
        action_id: Database primary key
        service_prefix: AWS service prefix
        action_name: Action name without service prefix
        full_action: Complete action name (service:action)
        description: Human-readable action description
        access_level: Access level category
        is_list: Whether this is a List operation
        is_read: Whether this is a Read operation
        is_write: Whether this is a Write operation
        is_permissions_management: Whether this manages permissions
        is_tagging_only: Whether this only modifies tags
        reference_url: URL to action documentation
    """

    action_id: int | None
    service_prefix: str
    action_name: str
    full_action: str
    description: str | None
    access_level: str
    is_list: bool = False
    is_read: bool = False
    is_write: bool = False
    is_permissions_management: bool = False
    is_tagging_only: bool = False
    reference_url: str | None = None


@dataclass
class ResourceType:
    """Resource Type data model.

    Attributes:
        resource_type_id: Database primary key
        service_prefix: AWS service prefix
        resource_name: Resource type name (e.g., 'bucket', 'object')
        arn_pattern: ARN pattern template
        reference_url: URL to resource documentation
    """

    resource_type_id: int | None
    service_prefix: str
    resource_name: str
    arn_pattern: str
    reference_url: str | None = None


@dataclass
class ConditionKey:
    """Condition Key data model.

    Attributes:
        condition_key_id: Database primary key
        service_prefix: AWS service prefix
        condition_key_name: Condition key name
        full_condition_key: Full condition key (service:key or aws:key)
        description: Human-readable description
        condition_type: Data type (String, Numeric, etc.)
        is_global: Whether this is a global aws:* condition key
        reference_url: URL to condition key documentation
    """

    condition_key_id: int | None
    service_prefix: str
    condition_key_name: str
    full_condition_key: str
    description: str | None
    condition_type: str | None
    is_global: bool = False
    reference_url: str | None = None


class DatabaseError(Exception):
    """Base exception for database operations."""

    pass


# P1-6 β — frozenset whitelist of known table names.  ``Database.is_empty``
# checks membership before any SQL runs, so an attacker-controlled string
# can never reach the interpolated SELECT path even if the caller forgets
# the usual ``(table,)`` binding.  Keep in sync with Alembic migrations
# 0001–0008; updates land atomically with new migration commits.
_EXPECTED_TABLES: frozenset[str] = frozenset({
    # Phase 1 (initial schema + Phase-1.5 tweaks)
    "services",
    "actions",
    "resource_types",
    "condition_keys",
    "arn_condition_keys",
    "action_condition_keys",
    "action_resource_types",
    "action_dependent_actions",
    "metadata",
    "validation_errors",
    # Phase 2 (dynamic data tables + Task 6 HMAC + Task 7 lookup + Task 10 seeds)
    "verb_prefixes",
    "dangerous_actions",
    "companion_rules",
    "dangerous_combinations",
    "action_resource_map",
    "arn_templates",
    "managed_policies",
    # Phase 2 / inventory — lives in inventory.db, included here so the
    # is_empty shim on inventory Database instances (if any) short-circuits
    # cleanly rather than raising.
    "resources",
})


class Database:
    """SQLite database interface for IAM actions.

    Provides methods for schema creation, data insertion, and queries.
    Supports both read-only and read-write connections.
    """

    def __init__(self, db_path: Path, read_only: bool = False):
        """Initialize database connection.

        Args:
            db_path: Path to SQLite database file
            read_only: If True, open database in read-only mode

        Raises:
            DatabaseError: If database cannot be opened
        """
        self.db_path = Path(db_path)
        self.read_only = read_only

    @contextmanager
    def get_connection(self) -> Iterator[sqlite3.Connection]:
        """Get database connection as context manager.

        Yields:
            sqlite3.Connection: Database connection

        Raises:
            DatabaseError: If connection cannot be established
        """
        conn = None
        try:
            if self.read_only:
                uri = f"file:{self.db_path}?mode=ro"
                conn = sqlite3.connect(uri, uri=True)
            else:
                conn = sqlite3.connect(self.db_path)
            conn.row_factory = sqlite3.Row
            conn.execute("PRAGMA foreign_keys = ON")
        except sqlite3.Error as e:
            raise DatabaseError(f"Database connection failed: {e}") from e
        try:
            yield conn
            if not self.read_only:
                conn.commit()
        except sqlite3.Error as e:
            raise DatabaseError(f"Database operation failed: {e}") from e
        finally:
            if conn:
                conn.close()

    def is_empty(self, table: str) -> bool:
        """Return True if ``table`` has zero rows (or does not exist).

        P1-6 β — hardened against SQL-injection via the ``table``
        argument.  Two-layer defense:

        1. ``table`` must be in ``_EXPECTED_TABLES`` (frozenset of known
           table names from the migration catalogue).  Unknown names
           return True immediately, without touching SQL.
        2. Even for whitelisted names, the table-exists probe uses a
           parameterized ``sqlite_master`` query.  Only after
           confirmation does the row probe interpolate — and the
           interpolated value is ``probe[0]`` (the name SQLite itself
           stored), not the caller's string.  Double-quoted to satisfy
           ANSI quoting for any identifier that would otherwise be a
           reserved word.

        Args:
            table: Table name to probe.  Must be a static identifier
                from the migrations catalogue — not user input.

        Returns:
            True if the table has no rows or does not exist.
        """
        if table not in _EXPECTED_TABLES:
            return True
        with self.get_connection() as conn:
            probe = conn.execute(
                "SELECT name FROM sqlite_master WHERE type='table' AND name = ? LIMIT 1",
                (table,),
            ).fetchone()
            if not probe:
                return True
            # probe[0] is the SQLite-round-tripped identifier — safe to
            # interpolate inside ANSI quotes.
            row = conn.execute(f'SELECT 1 FROM "{probe[0]}" LIMIT 1').fetchone()
            return row is None

    def is_corpus_populated(self) -> bool:
        """Return True when both services and actions tables have >=1 row.

        Added in v0.8.0 (Issue 3).  Used by ``sentinel.cli.main()`` to warn
        operators when the AWS action corpus is not populated: an empty
        corpus means every policy action classifies as Tier 2 (unknown),
        causing the rewriter to drop them silently in pre-v0.8.0 flows or
        preserve them with a WARNING in v0.8.0+ flows.

        Returns:
            True iff both the ``services`` and ``actions`` tables exist
            AND contain at least one row apiece.  Falsy otherwise.
        """
        return not self.is_empty("services") and not self.is_empty("actions")

    def create_schema(self) -> None:
        """Create database schema with all tables and indexes.

        Raises:
            DatabaseError: If schema creation fails
        """
        with self.get_connection() as conn:
            cursor = conn.cursor()

            # Services Table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS services (
                    service_prefix TEXT PRIMARY KEY,
                    service_name TEXT NOT NULL,
                    service_authorization_url TEXT,
                    api_reference_url TEXT,
                    last_updated TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    data_version TEXT
                )
            """)

            cursor.execute("""
                CREATE INDEX IF NOT EXISTS idx_services_name
                ON services(service_name)
            """)

            # Actions Table
            cursor.execute("""
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

            cursor.execute("""
                CREATE INDEX IF NOT EXISTS idx_actions_service
                ON actions(service_prefix)
            """)

            cursor.execute("""
                CREATE INDEX IF NOT EXISTS idx_actions_access_level
                ON actions(access_level)
            """)

            cursor.execute("""
                CREATE INDEX IF NOT EXISTS idx_actions_is_write
                ON actions(is_write) WHERE is_write = 1
            """)

            cursor.execute("""
                CREATE INDEX IF NOT EXISTS idx_actions_is_permissions_mgmt
                ON actions(is_permissions_management) WHERE is_permissions_management = 1
            """)

            # Resource Types Table
            cursor.execute("""
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

            cursor.execute("""
                CREATE INDEX IF NOT EXISTS idx_resource_types_service
                ON resource_types(service_prefix)
            """)

            # Action-Resource Relationships
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS action_resource_types (
                    action_id INTEGER NOT NULL,
                    resource_type_id INTEGER NOT NULL,
                    is_required BOOLEAN DEFAULT 1,
                    PRIMARY KEY (action_id, resource_type_id),
                    FOREIGN KEY (action_id) REFERENCES actions(action_id) ON DELETE CASCADE,
                    FOREIGN KEY (resource_type_id) REFERENCES resource_types(resource_type_id) ON DELETE CASCADE
                )
            """)

            cursor.execute("""
                CREATE INDEX IF NOT EXISTS idx_action_resources_action
                ON action_resource_types(action_id)
            """)

            cursor.execute("""
                CREATE INDEX IF NOT EXISTS idx_action_resources_resource
                ON action_resource_types(resource_type_id)
            """)

            # Condition Keys Table
            cursor.execute("""
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

            cursor.execute("""
                CREATE INDEX IF NOT EXISTS idx_condition_keys_service
                ON condition_keys(service_prefix)
            """)

            cursor.execute("""
                CREATE INDEX IF NOT EXISTS idx_condition_keys_global
                ON condition_keys(is_global) WHERE is_global = 1
            """)

            # Action-Condition Relationships
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS action_condition_keys (
                    action_id INTEGER NOT NULL,
                    condition_key_id INTEGER NOT NULL,
                    PRIMARY KEY (action_id, condition_key_id),
                    FOREIGN KEY (action_id) REFERENCES actions(action_id) ON DELETE CASCADE,
                    FOREIGN KEY (condition_key_id) REFERENCES condition_keys(condition_key_id) ON DELETE CASCADE
                )
            """)

            cursor.execute("""
                CREATE INDEX IF NOT EXISTS idx_action_conditions_action
                ON action_condition_keys(action_id)
            """)

            cursor.execute("""
                CREATE INDEX IF NOT EXISTS idx_action_conditions_condition
                ON action_condition_keys(condition_key_id)
            """)

            # Dependent Actions Table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS action_dependent_actions (
                    action_id INTEGER NOT NULL,
                    depends_on_action_id INTEGER NOT NULL,
                    PRIMARY KEY (action_id, depends_on_action_id),
                    FOREIGN KEY (action_id) REFERENCES actions(action_id) ON DELETE CASCADE,
                    FOREIGN KEY (depends_on_action_id) REFERENCES actions(action_id) ON DELETE CASCADE,
                    CHECK (action_id != depends_on_action_id)
                )
            """)

            cursor.execute("""
                CREATE INDEX IF NOT EXISTS idx_dependent_actions_action
                ON action_dependent_actions(action_id)
            """)

            cursor.execute("""
                CREATE INDEX IF NOT EXISTS idx_dependent_actions_depends
                ON action_dependent_actions(depends_on_action_id)
            """)

            # Resource-Condition Relationships
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS arn_condition_keys (
                    resource_type_id INTEGER NOT NULL,
                    condition_key_id INTEGER NOT NULL,
                    PRIMARY KEY (resource_type_id, condition_key_id),
                    FOREIGN KEY (resource_type_id) REFERENCES resource_types(resource_type_id) ON DELETE CASCADE,
                    FOREIGN KEY (condition_key_id) REFERENCES condition_keys(condition_key_id) ON DELETE CASCADE
                )
            """)

            cursor.execute("""
                CREATE INDEX IF NOT EXISTS idx_arn_conditions_resource
                ON arn_condition_keys(resource_type_id)
            """)

            cursor.execute("""
                CREATE INDEX IF NOT EXISTS idx_arn_conditions_condition
                ON arn_condition_keys(condition_key_id)
            """)

            # Metadata Table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS metadata (
                    key TEXT PRIMARY KEY,
                    value TEXT NOT NULL,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)

            # Insert initial metadata
            cursor.execute(
                "INSERT OR IGNORE INTO metadata (key, value, updated_at) "
                "VALUES ('schema_version', ?, CURRENT_TIMESTAMP)",
                (SCHEMA_VERSION,),
            )
            cursor.execute("""
                INSERT OR IGNORE INTO metadata (key, value, updated_at) VALUES
                    ('data_source', 'AWS Service Authorization Reference', CURRENT_TIMESTAMP),
                    ('last_full_update', CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
            """)

            # Validation Errors Table
            cursor.execute("""
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

            cursor.execute("""
                CREATE INDEX IF NOT EXISTS idx_validation_errors_policy
                ON validation_errors(policy_id)
            """)

            cursor.execute("""
                CREATE INDEX IF NOT EXISTS idx_validation_errors_severity
                ON validation_errors(severity)
            """)

            # ---- Alembic-head parity (0002..0008) ------------------------
            # The live-fetch migration pipeline (Alembic) adds these tables
            # post-0001.  For tests and demos using Database().create_schema()
            # directly, mirror them here so test_alembic_drift passes.

            # 0002: verb_prefixes
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS verb_prefixes (
                    prefix TEXT PRIMARY KEY,
                    access_category TEXT NOT NULL
                        CHECK (access_category IN ('read','write','admin')),
                    source TEXT NOT NULL
                        CHECK (source IN ('policy_sentry','aws-docs','shipped','managed-policies','cloudsplaining')),
                    refreshed_at TIMESTAMP NOT NULL
                )
            """)

            # 0003: dangerous_actions + idx_dangerous_category
            cursor.execute("""
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
            cursor.execute(
                "CREATE INDEX IF NOT EXISTS idx_dangerous_category "
                "ON dangerous_actions(category, action_name)"
            )

            # 0004: companion_rules
            cursor.execute("""
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

            # 0005: dangerous_combinations + idx_dc_action_b
            cursor.execute("""
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
            cursor.execute(
                "CREATE INDEX IF NOT EXISTS idx_dc_action_b "
                "ON dangerous_combinations(action_b, action_a)"
            )

            # 0006: action_resource_map
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS action_resource_map (
                    action_name TEXT NOT NULL,
                    resource_type TEXT NOT NULL,
                    PRIMARY KEY (action_name, resource_type)
                )
            """)

            # 0007: arn_templates
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS arn_templates (
                    service_prefix TEXT NOT NULL,
                    resource_type TEXT NOT NULL,
                    arn_template TEXT NOT NULL,
                    PRIMARY KEY (service_prefix, resource_type)
                )
            """)

            # 0008: managed_policies (policy_document_hmac per M12)
            cursor.execute("""
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

    def insert_service(self, service: Service) -> None:
        """Insert a service record.

        Args:
            service: Service data model

        Raises:
            DatabaseError: If insertion fails
        """
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                INSERT OR REPLACE INTO services
                (service_prefix, service_name, service_authorization_url, api_reference_url, data_version)
                VALUES (?, ?, ?, ?, ?)
            """,
                (
                    service.service_prefix,
                    service.service_name,
                    service.service_authorization_url,
                    service.api_reference_url,
                    service.data_version,
                ),
            )

    def insert_action(self, action: Action) -> int:
        """Insert an action record.

        Args:
            action: Action data model

        Returns:
            int: action_id of inserted record

        Raises:
            DatabaseError: If insertion fails
        """
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                INSERT OR REPLACE INTO actions
                (service_prefix, action_name, description, access_level, reference_url,
                 is_list, is_read, is_write, is_permissions_management, is_tagging_only)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
                (
                    action.service_prefix,
                    action.action_name,
                    action.description,
                    action.access_level,
                    action.reference_url,
                    action.is_list,
                    action.is_read,
                    action.is_write,
                    action.is_permissions_management,
                    action.is_tagging_only,
                ),
            )
            # lastrowid is int for AUTOINCREMENT INSERTs; narrow from int|None.
            assert cursor.lastrowid is not None
            return cursor.lastrowid

    def get_action(self, service_prefix: str, action_name: str) -> Action | None:
        """Retrieve action by service and name.

        Args:
            service_prefix: AWS service prefix
            action_name: Action name without service prefix

        Returns:
            Action object if found, None otherwise
        """
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                SELECT action_id, service_prefix, action_name,
                       service_prefix || ':' || action_name as full_action,
                       description, access_level, is_list, is_read, is_write,
                       is_permissions_management, is_tagging_only, reference_url
                FROM actions
                WHERE service_prefix = ? AND action_name = ?
            """,
                (service_prefix, action_name),
            )

            row = cursor.fetchone()
            if row:
                return Action(
                    action_id=row["action_id"],
                    service_prefix=row["service_prefix"],
                    action_name=row["action_name"],
                    full_action=row["full_action"],
                    description=row["description"],
                    access_level=row["access_level"],
                    is_list=bool(row["is_list"]),
                    is_read=bool(row["is_read"]),
                    is_write=bool(row["is_write"]),
                    is_permissions_management=bool(row["is_permissions_management"]),
                    is_tagging_only=bool(row["is_tagging_only"]),
                    reference_url=row["reference_url"],
                )
            return None

    def get_actions_by_service(self, service_prefix: str) -> list[Action]:
        """Retrieve all actions for a service.

        Args:
            service_prefix: AWS service prefix

        Returns:
            List of Action objects
        """
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                SELECT action_id, service_prefix, action_name,
                       service_prefix || ':' || action_name as full_action,
                       description, access_level, is_list, is_read, is_write,
                       is_permissions_management, is_tagging_only, reference_url
                FROM actions
                WHERE service_prefix = ?
                ORDER BY action_name
            """,
                (service_prefix,),
            )

            return [
                Action(
                    action_id=row["action_id"],
                    service_prefix=row["service_prefix"],
                    action_name=row["action_name"],
                    full_action=row["full_action"],
                    description=row["description"],
                    access_level=row["access_level"],
                    is_list=bool(row["is_list"]),
                    is_read=bool(row["is_read"]),
                    is_write=bool(row["is_write"]),
                    is_permissions_management=bool(row["is_permissions_management"]),
                    is_tagging_only=bool(row["is_tagging_only"]),
                    reference_url=row["reference_url"],
                )
                for row in cursor.fetchall()
            ]

    def get_services(self) -> list[Service]:
        """Retrieve all services.

        Returns:
            List of Service objects
        """
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT service_prefix, service_name, service_authorization_url,
                       api_reference_url, data_version
                FROM services
                ORDER BY service_prefix
            """)

            return [
                Service(
                    service_prefix=row["service_prefix"],
                    service_name=row["service_name"],
                    service_authorization_url=row["service_authorization_url"],
                    api_reference_url=row["api_reference_url"],
                    data_version=row["data_version"],
                )
                for row in cursor.fetchall()
            ]

    def get_metadata(self, key: str) -> str | None:
        """Retrieve metadata value.

        Args:
            key: Metadata key

        Returns:
            Metadata value if found, None otherwise
        """
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT value FROM metadata WHERE key = ?", (key,))
            row = cursor.fetchone()
            return row["value"] if row else None

    def set_metadata(self, key: str, value: str) -> None:
        """Set metadata value.

        Args:
            key: Metadata key
            value: Metadata value
        """
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                INSERT OR REPLACE INTO metadata (key, value, updated_at)
                VALUES (?, ?, CURRENT_TIMESTAMP)
            """,
                (key, value),
            )

    def action_exists(self, full_action: str) -> bool:
        """Check if action exists in database.

        Args:
            full_action: Full action name (service:action)

        Returns:
            True if action exists, False otherwise
        """
        parts = full_action.split(":", 1)
        if len(parts) != 2:
            return False

        service_prefix, action_name = parts
        return self.get_action(service_prefix, action_name) is not None

    # -- P1-8 β shared-connection variants ----------------------------------
    #
    # Hot-path callers (``PolicyParser.validate_policy``) that classify many
    # actions back-to-back can open one connection and reuse it via these
    # ``_with_conn`` variants.  Saves ~2ms per action in cold SQLite.  The
    # sqlite3 module requires the Connection to be used only by the thread
    # that created it; all validate_policy use is single-thread.

    def _service_exists_with_conn(self, conn: "sqlite3.Connection", service_prefix: str) -> bool:
        """Check if a service prefix exists using a caller-supplied connection.

        Args:
            conn: Open sqlite3.Connection owned by the calling thread.
            service_prefix: AWS service prefix (e.g. ``"s3"``).

        Returns:
            ``True`` if the prefix is present in the ``services`` table.
        """
        cursor = conn.cursor()
        cursor.execute(
            "SELECT COUNT(*) as count FROM services WHERE service_prefix = ?",
            (service_prefix,),
        )
        row = cursor.fetchone()
        return bool(row and row[0] > 0)

    def _get_action_with_conn(
        self, conn: "sqlite3.Connection", service_prefix: str, action_name: str
    ) -> "Action | None":
        """Fetch a single Action row using a caller-supplied connection.

        Args:
            conn: Open sqlite3.Connection owned by the calling thread.
            service_prefix: AWS service prefix (e.g. ``"s3"``).
            action_name: Action name (e.g. ``"GetObject"``).

        Returns:
            A fully-populated :class:`Action` if the row exists, else ``None``.
        """
        cursor = conn.cursor()
        cursor.execute(
            """
            SELECT action_id, service_prefix, action_name,
                   service_prefix || ':' || action_name as full_action,
                   description, access_level, is_list, is_read, is_write,
                   is_permissions_management, is_tagging_only, reference_url
            FROM actions
            WHERE service_prefix = ? AND action_name = ?
            """,
            (service_prefix, action_name),
        )
        row = cursor.fetchone()
        if row is None:
            return None
        return Action(
            action_id=row["action_id"],
            service_prefix=row["service_prefix"],
            action_name=row["action_name"],
            full_action=row["full_action"],
            description=row["description"],
            access_level=row["access_level"],
            is_list=bool(row["is_list"]),
            is_read=bool(row["is_read"]),
            is_write=bool(row["is_write"]),
            is_permissions_management=bool(row["is_permissions_management"]),
            is_tagging_only=bool(row["is_tagging_only"]),
            reference_url=row["reference_url"],
        )

    def _action_exists_with_conn(self, conn: "sqlite3.Connection", full_action: str) -> bool:
        """Check if a fully-qualified action exists using a caller-supplied connection.

        Args:
            conn: Open sqlite3.Connection owned by the calling thread.
            full_action: Dotted action (e.g. ``"s3:GetObject"``).

        Returns:
            ``True`` if the action is present in the ``actions`` table.
        """
        parts = full_action.split(":", 1)
        if len(parts) != 2:
            return False
        return self._get_action_with_conn(conn, parts[0], parts[1]) is not None

    def service_exists(self, service_prefix: str) -> bool:
        """Check if service exists in database.

        Args:
            service_prefix: AWS service prefix

        Returns:
            True if service exists, False otherwise
        """
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                "SELECT COUNT(*) as count FROM services WHERE service_prefix = ?", (service_prefix,)
            )
            row = cursor.fetchone()
            return row["count"] > 0 if row else False

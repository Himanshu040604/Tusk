"""Resource inventory management for IAM Policy Sentinel.

This module provides schema and interfaces for tracking AWS resource ARNs
for policy validation.
"""

import sqlite3
from dataclasses import dataclass
from pathlib import Path
from typing import List, Optional, Dict, Any, Iterator
from contextlib import contextmanager

from .constants import DEFAULT_ACCOUNT_ID, DEFAULT_REGION, SCHEMA_VERSION


@dataclass
class Resource:
    """AWS Resource data model.

    Attributes:
        resource_id: Database primary key
        service_prefix: AWS service prefix (e.g., 's3', 'ec2')
        resource_type: Type of resource (e.g., 'bucket', 'instance')
        resource_arn: Full ARN of the resource
        resource_name: Human-readable resource name
        region: AWS region (e.g., 'us-east-1')
        account_id: AWS account ID (12-digit number)
        metadata: JSON string with additional resource metadata
    """

    resource_id: int | None
    service_prefix: str
    resource_type: str
    resource_arn: str
    resource_name: str | None = None
    region: str | None = None
    account_id: str | None = None
    metadata: str | None = None


class InventoryError(Exception):
    """Base exception for inventory operations."""

    pass


class ResourceInventory:
    """Interface for resource inventory database.

    Manages storage and querying of AWS resource ARNs for policy validation.
    """

    # Task 8: ACTION_RESOURCE_MAP and ARN_TEMPLATES moved out of this
    # class.  Data now lives in the ``action_resource_map`` (migration
    # 0006) and ``arn_templates`` (migration 0007) DB tables on the IAM
    # DB, seeded from ``sentinel.seed_data._BASELINE_*`` tuples.  The
    # PolicyRewriter bulk-loads both dicts once at __init__; the
    # inventory-side helpers below still fall back to generic patterns
    # when no DB-backed template is available.

    def __init__(self, db_path: Path, read_only: bool = False):
        """Initialize resource inventory connection.

        Args:
            db_path: Path to SQLite database file
            read_only: If True, open database in read-only mode

        Raises:
            InventoryError: If database cannot be opened
        """
        self.db_path = Path(db_path)
        self.read_only = read_only

    @contextmanager
    def get_connection(self) -> Iterator[sqlite3.Connection]:
        """Get database connection as context manager.

        Yields:
            sqlite3.Connection: Database connection

        Raises:
            InventoryError: If connection cannot be established
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
            raise InventoryError(f"Database connection failed: {e}") from e
        try:
            yield conn
            if not self.read_only:
                conn.commit()
        except sqlite3.Error as e:
            raise InventoryError(f"Database operation failed: {e}") from e
        finally:
            if conn:
                conn.close()

    def create_schema(self) -> None:
        """Create resource inventory schema.

        Raises:
            InventoryError: If schema creation fails
        """
        with self.get_connection() as conn:
            cursor = conn.cursor()

            # Resources Table
            cursor.execute("""
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

            # Indexes for efficient querying
            cursor.execute("""
                CREATE INDEX IF NOT EXISTS idx_resources_service
                ON resources(service_prefix)
            """)

            cursor.execute("""
                CREATE INDEX IF NOT EXISTS idx_resources_type
                ON resources(resource_type)
            """)

            cursor.execute("""
                CREATE INDEX IF NOT EXISTS idx_resources_arn
                ON resources(resource_arn)
            """)

            cursor.execute("""
                CREATE INDEX IF NOT EXISTS idx_resources_account
                ON resources(account_id)
            """)

            cursor.execute("""
                CREATE INDEX IF NOT EXISTS idx_resources_region
                ON resources(region)
            """)

            # Composite index for service + type queries
            cursor.execute("""
                CREATE INDEX IF NOT EXISTS idx_resources_service_type
                ON resources(service_prefix, resource_type)
            """)

            # Metadata table for inventory tracking
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS inventory_metadata (
                    key TEXT PRIMARY KEY,
                    value TEXT NOT NULL,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)

            # Insert initial metadata
            cursor.execute(
                "INSERT OR IGNORE INTO inventory_metadata (key, value, updated_at) "
                "VALUES ('schema_version', ?, CURRENT_TIMESTAMP)",
                (SCHEMA_VERSION,),
            )
            cursor.execute("""
                INSERT OR IGNORE INTO inventory_metadata (key, value, updated_at) VALUES
                    ('last_sync', CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
            """)

    def insert_resource(self, resource: Resource) -> int:
        """Insert a resource record.

        Args:
            resource: Resource data model

        Returns:
            int: resource_id of inserted record

        Raises:
            InventoryError: If insertion fails
        """
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                INSERT OR REPLACE INTO resources
                (service_prefix, resource_type, resource_arn, resource_name,
                 region, account_id, metadata, last_seen)
                VALUES (?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
            """,
                (
                    resource.service_prefix,
                    resource.resource_type,
                    resource.resource_arn,
                    resource.resource_name,
                    resource.region,
                    resource.account_id,
                    resource.metadata,
                ),
            )
            assert cursor.lastrowid is not None
            return cursor.lastrowid

    def get_resource_by_arn(self, arn: str) -> Resource | None:
        """Retrieve resource by ARN.

        Args:
            arn: Full resource ARN

        Returns:
            Resource object if found, None otherwise
        """
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                SELECT resource_id, service_prefix, resource_type, resource_arn,
                       resource_name, region, account_id, metadata
                FROM resources
                WHERE resource_arn = ?
            """,
                (arn,),
            )

            row = cursor.fetchone()
            if row:
                return Resource(
                    resource_id=row["resource_id"],
                    service_prefix=row["service_prefix"],
                    resource_type=row["resource_type"],
                    resource_arn=row["resource_arn"],
                    resource_name=row["resource_name"],
                    region=row["region"],
                    account_id=row["account_id"],
                    metadata=row["metadata"],
                )
            return None

    def get_resources_by_service(
        self, service_prefix: str, resource_type: str | None = None
    ) -> List[Resource]:
        """Retrieve resources by service and optional type.

        Args:
            service_prefix: AWS service prefix
            resource_type: Optional resource type filter

        Returns:
            List of Resource objects
        """
        with self.get_connection() as conn:
            cursor = conn.cursor()

            if resource_type:
                cursor.execute(
                    """
                    SELECT resource_id, service_prefix, resource_type, resource_arn,
                           resource_name, region, account_id, metadata
                    FROM resources
                    WHERE service_prefix = ? AND resource_type = ?
                    ORDER BY resource_name, resource_arn
                """,
                    (service_prefix, resource_type),
                )
            else:
                cursor.execute(
                    """
                    SELECT resource_id, service_prefix, resource_type, resource_arn,
                           resource_name, region, account_id, metadata
                    FROM resources
                    WHERE service_prefix = ?
                    ORDER BY resource_type, resource_name, resource_arn
                """,
                    (service_prefix,),
                )

            return [
                Resource(
                    resource_id=row["resource_id"],
                    service_prefix=row["service_prefix"],
                    resource_type=row["resource_type"],
                    resource_arn=row["resource_arn"],
                    resource_name=row["resource_name"],
                    region=row["region"],
                    account_id=row["account_id"],
                    metadata=row["metadata"],
                )
                for row in cursor.fetchall()
            ]

    def get_resources_by_account(self, account_id: str) -> List[Resource]:
        """Retrieve all resources for an account.

        Args:
            account_id: AWS account ID

        Returns:
            List of Resource objects
        """
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                SELECT resource_id, service_prefix, resource_type, resource_arn,
                       resource_name, region, account_id, metadata
                FROM resources
                WHERE account_id = ?
                ORDER BY service_prefix, resource_type, resource_name
            """,
                (account_id,),
            )

            return [
                Resource(
                    resource_id=row["resource_id"],
                    service_prefix=row["service_prefix"],
                    resource_type=row["resource_type"],
                    resource_arn=row["resource_arn"],
                    resource_name=row["resource_name"],
                    region=row["region"],
                    account_id=row["account_id"],
                    metadata=row["metadata"],
                )
                for row in cursor.fetchall()
            ]

    def delete_resource(self, arn: str) -> bool:
        """Delete resource by ARN.

        Args:
            arn: Full resource ARN

        Returns:
            True if resource was deleted, False if not found
        """
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("DELETE FROM resources WHERE resource_arn = ?", (arn,))
            return cursor.rowcount > 0

    def get_statistics(self) -> Dict[str, Any]:
        """Get inventory statistics.

        Returns:
            Dictionary with statistics
        """
        with self.get_connection() as conn:
            cursor = conn.cursor()

            # Total resources
            cursor.execute("SELECT COUNT(*) as total FROM resources")
            total = cursor.fetchone()["total"]

            # Resources by service
            cursor.execute("""
                SELECT service_prefix, COUNT(*) as count
                FROM resources
                GROUP BY service_prefix
                ORDER BY count DESC
            """)
            by_service = {row["service_prefix"]: row["count"] for row in cursor.fetchall()}

            # Resources by region
            cursor.execute("""
                SELECT region, COUNT(*) as count
                FROM resources
                WHERE region IS NOT NULL
                GROUP BY region
                ORDER BY count DESC
            """)
            by_region = {row["region"]: row["count"] for row in cursor.fetchall()}

            # Resources by account
            cursor.execute("""
                SELECT account_id, COUNT(*) as count
                FROM resources
                WHERE account_id IS NOT NULL
                GROUP BY account_id
                ORDER BY count DESC
            """)
            by_account = {row["account_id"]: row["count"] for row in cursor.fetchall()}

            return {
                "total_resources": total,
                "by_service": by_service,
                "by_region": by_region,
                "by_account": by_account,
            }

    def get_metadata(self, key: str) -> str | None:
        """Retrieve metadata value.

        Args:
            key: Metadata key

        Returns:
            Metadata value if found, None otherwise
        """
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT value FROM inventory_metadata WHERE key = ?", (key,))
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
                INSERT OR REPLACE INTO inventory_metadata (key, value, updated_at)
                VALUES (?, ?, CURRENT_TIMESTAMP)
            """,
                (key, value),
            )

    def arn_exists(self, arn: str) -> bool:
        """Check if resource ARN exists in inventory.

        Args:
            arn: Full resource ARN

        Returns:
            True if ARN exists, False otherwise
        """
        return self.get_resource_by_arn(arn) is not None

    def resolve_wildcard_resource(
        self, service_prefix: str, resource_type: str | None = None
    ) -> List[str]:
        """Look up real ARNs from inventory to replace wildcard resources.

        Args:
            service_prefix: AWS service prefix (e.g., 's3', 'ec2')
            resource_type: Optional resource type filter

        Returns:
            List of matching resource ARN strings
        """
        resources = self.get_resources_by_service(service_prefix, resource_type)
        return [r.resource_arn for r in resources]

    def get_arns_for_action(self, action: str) -> List[str]:
        """Find appropriate resource ARNs for a given IAM action.

        Parses the service prefix from the action name.  Task 8: the
        action -> resource-type lookup was removed from this class and
        now lives on :class:`sentinel.rewriter.PolicyRewriter` where it
        is bulk-loaded from the IAM DB.  Without that side-channel we
        cannot narrow to a specific resource_type, so we resolve across
        all resources for the service — the caller typically already
        knows the resource type via its own bulk-loaded map and passes
        it to :meth:`resolve_wildcard_resource` directly.

        Args:
            action: IAM action name (e.g., 's3:GetObject').

        Returns:
            List of matching resource ARN strings.
        """
        parts = action.split(":", 1)
        if len(parts) != 2:
            return []

        service_prefix = parts[0]
        return self.resolve_wildcard_resource(service_prefix, None)

    def has_resources_for_service(self, service_prefix: str) -> bool:
        """Check if inventory has any resources for a given service.

        Performs a quick COUNT query without loading full resource objects.

        Args:
            service_prefix: AWS service prefix

        Returns:
            True if at least one resource exists for the service
        """
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                "SELECT COUNT(*) as count FROM resources WHERE service_prefix = ?",
                (service_prefix,),
            )
            row = cursor.fetchone()
            return row["count"] > 0 if row else False

    def generate_placeholder_arn(
        self,
        service_prefix: str,
        resource_type: str,
        account_id: str = DEFAULT_ACCOUNT_ID,
        region: str = DEFAULT_REGION,
    ) -> str:
        """Generate a clearly-marked placeholder ARN.

        Task 8: the service-specific template dict was removed from
        this class.  PolicyRewriter bulk-loads ``arn_templates`` from
        the IAM DB and calls :meth:`generate_placeholder_arn` only as
        a last-resort fallback when its own template resolution misses.
        This implementation returns the generic
        ``arn:aws:<svc>:<region>:<account>:<type>/<placeholder>`` shape
        — sufficient for unit tests and pre-Alembic callers; the
        rewriter-side template already handles every shipped service.

        Args:
            service_prefix: AWS service prefix.
            resource_type: Resource type (e.g., 'bucket', 'instance').
            account_id: AWS account ID (defaults to placeholder).
            region: AWS region (defaults to us-east-1).

        Returns:
            Placeholder ARN string with ``PLACEHOLDER`` markers.
        """
        placeholder_name = f"PLACEHOLDER-{resource_type}-name"
        return f"arn:aws:{service_prefix}:{region}:{account_id}:{resource_type}/{placeholder_name}"

    def get_resource_types_for_service(self, service_prefix: str) -> List[str]:
        """Get distinct resource types available for a service.

        Args:
            service_prefix: AWS service prefix

        Returns:
            Sorted list of unique resource type strings
        """
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                SELECT DISTINCT resource_type
                FROM resources
                WHERE service_prefix = ?
                ORDER BY resource_type
            """,
                (service_prefix,),
            )
            return [row["resource_type"] for row in cursor.fetchall()]

    def bulk_insert_resources(self, resources: List[Resource]) -> int:
        """Insert multiple resources efficiently in a single transaction.

        Args:
            resources: List of Resource objects to insert

        Returns:
            Count of successfully inserted resources
        """
        if not resources:
            return 0

        with self.get_connection() as conn:
            cursor = conn.cursor()
            data = [
                (
                    r.service_prefix,
                    r.resource_type,
                    r.resource_arn,
                    r.resource_name,
                    r.region,
                    r.account_id,
                    r.metadata,
                )
                for r in resources
            ]
            cursor.executemany(
                """
                INSERT OR REPLACE INTO resources
                (service_prefix, resource_type, resource_arn, resource_name,
                 region, account_id, metadata, last_seen)
                VALUES (?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
            """,
                data,
            )
            return len(data)

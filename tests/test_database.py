"""Unit tests for database module."""

import pytest
import sqlite3
import tempfile
from pathlib import Path

from src.sentinel.database import (
    Database,
    DatabaseError,
    Service,
    Action,
    ResourceType,
    ConditionKey,
)


@pytest.fixture
def temp_db():
    """Create temporary database for testing."""
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
        db_path = Path(f.name)

    yield db_path

    # Cleanup
    if db_path.exists():
        db_path.unlink()


@pytest.fixture
def database(temp_db):
    """Create and initialize database for testing."""
    db = Database(temp_db)
    db.create_schema()
    return db


class TestDatabaseSchema:
    """Test database schema creation and validation."""

    def test_create_schema(self, temp_db):
        """Test schema creation."""
        db = Database(temp_db)
        db.create_schema()

        # Verify tables exist
        with db.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT name FROM sqlite_master
                WHERE type='table'
                ORDER BY name
            """)
            tables = [row["name"] for row in cursor.fetchall()]

            expected_tables = [
                "action_condition_keys",
                "action_dependent_actions",
                "action_resource_types",
                "actions",
                "arn_condition_keys",
                "condition_keys",
                "metadata",
                "resource_types",
                "services",
                "validation_errors",
            ]

            for table in expected_tables:
                assert table in tables, f"Table {table} not found"

    def test_schema_idempotent(self, database):
        """Test schema creation is idempotent."""
        # Create schema again - should not raise error
        database.create_schema()

        # Verify tables still exist
        with database.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT COUNT(*) as count FROM sqlite_master WHERE type='table'")
            count = cursor.fetchone()["count"]
            assert count >= 10

    def test_foreign_keys_enabled(self, database):
        """Test foreign key constraints are enabled."""
        with database.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("PRAGMA foreign_keys")
            result = cursor.fetchone()
            assert result[0] == 1

    def test_metadata_initialized(self, database):
        """Test metadata table is initialized."""
        assert database.get_metadata("schema_version") == "1.0"
        assert database.get_metadata("data_source") == "AWS Service Authorization Reference"
        assert database.get_metadata("last_full_update") is not None


class TestServiceOperations:
    """Test service CRUD operations."""

    def test_insert_service(self, database):
        """Test inserting a service."""
        service = Service(
            service_prefix="s3",
            service_name="Amazon S3",
            service_authorization_url="https://docs.aws.amazon.com/s3",
            data_version="v1.4",
        )

        database.insert_service(service)

        # Verify service exists
        assert database.service_exists("s3")

    def test_insert_service_duplicate(self, database):
        """Test inserting duplicate service (should replace)."""
        service1 = Service(service_prefix="s3", service_name="Amazon S3", data_version="v1.0")
        database.insert_service(service1)

        service2 = Service(
            service_prefix="s3", service_name="Amazon S3 Updated", data_version="v1.1"
        )
        database.insert_service(service2)

        # Should have updated, not duplicated
        services = database.get_services()
        s3_services = [s for s in services if s.service_prefix == "s3"]
        assert len(s3_services) == 1
        assert s3_services[0].data_version == "v1.1"

    def test_get_services(self, database):
        """Test retrieving all services."""
        services_data = [
            Service(service_prefix="s3", service_name="Amazon S3"),
            Service(service_prefix="ec2", service_name="Amazon EC2"),
            Service(service_prefix="iam", service_name="AWS IAM"),
        ]

        for service in services_data:
            database.insert_service(service)

        services = database.get_services()
        assert len(services) >= 3

        service_prefixes = [s.service_prefix for s in services]
        assert "s3" in service_prefixes
        assert "ec2" in service_prefixes
        assert "iam" in service_prefixes

    def test_service_exists(self, database):
        """Test checking service existence."""
        service = Service(service_prefix="lambda", service_name="AWS Lambda")
        database.insert_service(service)

        assert database.service_exists("lambda") is True
        assert database.service_exists("nonexistent") is False


class TestActionOperations:
    """Test action CRUD operations."""

    def test_insert_action(self, database):
        """Test inserting an action."""
        # Insert service first (foreign key constraint)
        service = Service(service_prefix="s3", service_name="Amazon S3")
        database.insert_service(service)

        action = Action(
            action_id=None,
            service_prefix="s3",
            action_name="GetObject",
            full_action="s3:GetObject",
            description="Retrieves objects from Amazon S3",
            access_level="Read",
            is_read=True,
        )

        action_id = database.insert_action(action)
        assert action_id > 0

        # Verify action exists
        retrieved = database.get_action("s3", "GetObject")
        assert retrieved is not None
        assert retrieved.action_name == "GetObject"
        assert retrieved.access_level == "Read"
        assert retrieved.is_read is True

    def test_insert_action_all_access_levels(self, database):
        """Test inserting actions with different access levels."""
        service = Service(service_prefix="s3", service_name="Amazon S3")
        database.insert_service(service)

        test_cases = [
            ("ListBuckets", "List", True, False, False, False, False),
            ("GetObject", "Read", False, True, False, False, False),
            ("PutObject", "Write", False, False, True, False, False),
            ("PutBucketPolicy", "Permissions management", False, False, False, True, False),
            ("PutBucketTagging", "Tagging", False, False, False, False, True),
        ]

        for action_name, access_level, is_list, is_read, is_write, is_perm, is_tag in test_cases:
            action = Action(
                action_id=None,
                service_prefix="s3",
                action_name=action_name,
                full_action=f"s3:{action_name}",
                description=f"Test action {action_name}",
                access_level=access_level,
                is_list=is_list,
                is_read=is_read,
                is_write=is_write,
                is_permissions_management=is_perm,
                is_tagging_only=is_tag,
            )
            database.insert_action(action)

            # Verify
            retrieved = database.get_action("s3", action_name)
            assert retrieved.access_level == access_level
            assert retrieved.is_list == is_list
            assert retrieved.is_read == is_read
            assert retrieved.is_write == is_write
            assert retrieved.is_permissions_management == is_perm
            assert retrieved.is_tagging_only == is_tag

    def test_get_action_not_found(self, database):
        """Test retrieving non-existent action."""
        result = database.get_action("s3", "NonExistent")
        assert result is None

    def test_get_actions_by_service(self, database):
        """Test retrieving all actions for a service."""
        service = Service(service_prefix="ec2", service_name="Amazon EC2")
        database.insert_service(service)

        actions_data = [
            ("RunInstances", "Write"),
            ("TerminateInstances", "Write"),
            ("DescribeInstances", "List"),
        ]

        for action_name, access_level in actions_data:
            action = Action(
                action_id=None,
                service_prefix="ec2",
                action_name=action_name,
                full_action=f"ec2:{action_name}",
                description=f"Test {action_name}",
                access_level=access_level,
            )
            database.insert_action(action)

        actions = database.get_actions_by_service("ec2")
        assert len(actions) == 3

        action_names = [a.action_name for a in actions]
        assert "RunInstances" in action_names
        assert "TerminateInstances" in action_names
        assert "DescribeInstances" in action_names

    def test_action_exists(self, database):
        """Test checking action existence."""
        service = Service(service_prefix="iam", service_name="AWS IAM")
        database.insert_service(service)

        action = Action(
            action_id=None,
            service_prefix="iam",
            action_name="ListUsers",
            full_action="iam:ListUsers",
            description="Lists IAM users",
            access_level="List",
        )
        database.insert_action(action)

        assert database.action_exists("iam:ListUsers") is True
        assert database.action_exists("iam:NonExistent") is False
        assert database.action_exists("invalid") is False

    def test_action_foreign_key_constraint(self, database):
        """Test foreign key constraint on actions."""
        # Attempt to insert action without service
        action = Action(
            action_id=None,
            service_prefix="nonexistent",
            action_name="TestAction",
            full_action="nonexistent:TestAction",
            description="Test",
            access_level="Read",
        )

        with pytest.raises(DatabaseError):
            database.insert_action(action)


class TestMetadataOperations:
    """Test metadata operations."""

    def test_get_metadata(self, database):
        """Test retrieving metadata."""
        value = database.get_metadata("schema_version")
        assert value == "1.0"

    def test_get_metadata_not_found(self, database):
        """Test retrieving non-existent metadata."""
        value = database.get_metadata("nonexistent_key")
        assert value is None

    def test_set_metadata(self, database):
        """Test setting metadata."""
        database.set_metadata("test_key", "test_value")

        value = database.get_metadata("test_key")
        assert value == "test_value"

    def test_update_metadata(self, database):
        """Test updating existing metadata."""
        database.set_metadata("update_test", "value1")
        database.set_metadata("update_test", "value2")

        value = database.get_metadata("update_test")
        assert value == "value2"


class TestReadOnlyMode:
    """Test read-only database access."""

    def test_read_only_connection(self, database):
        """Test opening database in read-only mode."""
        # Insert some data first
        service = Service(service_prefix="s3", service_name="Amazon S3")
        database.insert_service(service)

        # Open in read-only mode
        readonly_db = Database(database.db_path, read_only=True)

        # Should be able to read
        assert readonly_db.service_exists("s3")

        # Should not be able to write (will fail on commit or close)
        with pytest.raises(DatabaseError):
            new_service = Service(service_prefix="ec2", service_name="Amazon EC2")
            readonly_db.insert_service(new_service)


class TestConnectionManagement:
    """Test connection management."""

    def test_connection_context_manager(self, database):
        """Test connection is properly managed."""
        with database.get_connection() as conn:
            assert conn is not None
            cursor = conn.cursor()
            cursor.execute("SELECT 1")
            result = cursor.fetchone()
            assert result[0] == 1

    def test_connection_autocommit(self, database):
        """Test connection auto-commits on exit."""
        service = Service(service_prefix="test", service_name="Test Service")

        with database.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                INSERT INTO services (service_prefix, service_name)
                VALUES (?, ?)
            """,
                (service.service_prefix, service.service_name),
            )

        # Verify data was committed
        assert database.service_exists("test")


class TestIndexes:
    """Test database indexes are created."""

    def test_indexes_exist(self, database):
        """Test that indexes are created for performance."""
        with database.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT name FROM sqlite_master
                WHERE type='index' AND name LIKE 'idx_%'
                ORDER BY name
            """)
            indexes = [row["name"] for row in cursor.fetchall()]

            expected_indexes = [
                "idx_services_name",
                "idx_actions_service",
                "idx_actions_access_level",
                "idx_actions_is_write",
                "idx_actions_is_permissions_mgmt",
                "idx_resource_types_service",
                "idx_condition_keys_service",
                "idx_condition_keys_global",
            ]

            for idx in expected_indexes:
                assert idx in indexes, f"Index {idx} not found"


class TestConstraints:
    """Test database constraints."""

    def test_service_unique_constraint(self, database):
        """Test service_prefix is unique."""
        service = Service(service_prefix="s3", service_name="Amazon S3")
        database.insert_service(service)

        # Insert or replace should work
        service2 = Service(service_prefix="s3", service_name="S3 Updated")
        database.insert_service(service2)

        services = database.get_services()
        s3_count = sum(1 for s in services if s.service_prefix == "s3")
        assert s3_count == 1

    def test_action_unique_constraint(self, database):
        """Test (service_prefix, action_name) is unique."""
        service = Service(service_prefix="s3", service_name="Amazon S3")
        database.insert_service(service)

        action1 = Action(
            action_id=None,
            service_prefix="s3",
            action_name="GetObject",
            full_action="s3:GetObject",
            description="First",
            access_level="Read",
        )
        database.insert_action(action1)

        action2 = Action(
            action_id=None,
            service_prefix="s3",
            action_name="GetObject",
            full_action="s3:GetObject",
            description="Second",
            access_level="Read",
        )
        database.insert_action(action2)

        # Should have replaced, not duplicated
        actions = database.get_actions_by_service("s3")
        assert len(actions) == 1
        assert actions[0].description == "Second"

    def test_access_level_constraint(self, database):
        """Test access_level CHECK constraint."""
        service = Service(service_prefix="s3", service_name="Amazon S3")
        database.insert_service(service)

        # Valid access levels should work
        for level in ["List", "Read", "Write", "Permissions management", "Tagging"]:
            action = Action(
                action_id=None,
                service_prefix="s3",
                action_name=f"Test{level}",
                full_action=f"s3:Test{level}",
                description="Test",
                access_level=level,
            )
            database.insert_action(action)

        # Invalid access level should fail
        with pytest.raises(DatabaseError):
            invalid_action = Action(
                action_id=None,
                service_prefix="s3",
                action_name="InvalidLevel",
                full_action="s3:InvalidLevel",
                description="Test",
                access_level="InvalidLevel",
            )
            database.insert_action(invalid_action)


class TestBulkOperations:
    """Test bulk data operations."""

    def test_bulk_insert_services(self, database):
        """Test inserting multiple services."""
        services = [
            Service(service_prefix=f"service{i}", service_name=f"Service {i}") for i in range(100)
        ]

        for service in services:
            database.insert_service(service)

        all_services = database.get_services()
        assert len(all_services) >= 100

    def test_bulk_insert_actions(self, database):
        """Test inserting multiple actions."""
        service = Service(service_prefix="test", service_name="Test Service")
        database.insert_service(service)

        actions = [
            Action(
                action_id=None,
                service_prefix="test",
                action_name=f"Action{i}",
                full_action=f"test:Action{i}",
                description=f"Test action {i}",
                access_level="Read",
            )
            for i in range(50)
        ]

        for action in actions:
            database.insert_action(action)

        retrieved = database.get_actions_by_service("test")
        assert len(retrieved) == 50

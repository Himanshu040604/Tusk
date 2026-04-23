"""Unit tests for the Resource Inventory module (Phase 3 additions).

Tests cover the new methods added in Phase 3: resolve_wildcard_resource,
get_arns_for_action, has_resources_for_service, generate_placeholder_arn,
get_resource_types_for_service, and bulk_insert_resources.
"""

import pytest
from pathlib import Path

from src.sentinel.inventory import ResourceInventory, Resource, InventoryError


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def inventory(tmp_path):
    """Create a resource inventory with sample data."""
    inv_path = tmp_path / "test_inventory.db"
    inv = ResourceInventory(inv_path)
    inv.create_schema()

    # Insert sample S3 resources
    inv.insert_resource(
        Resource(
            resource_id=None,
            service_prefix="s3",
            resource_type="bucket",
            resource_arn="arn:aws:s3:::my-app-data",
            resource_name="my-app-data",
            account_id="123456789012",
        )
    )
    inv.insert_resource(
        Resource(
            resource_id=None,
            service_prefix="s3",
            resource_type="bucket",
            resource_arn="arn:aws:s3:::my-app-logs",
            resource_name="my-app-logs",
            account_id="123456789012",
        )
    )
    inv.insert_resource(
        Resource(
            resource_id=None,
            service_prefix="s3",
            resource_type="object",
            resource_arn="arn:aws:s3:::my-app-data/*",
            resource_name="my-app-data-objects",
            account_id="123456789012",
        )
    )

    # Insert sample EC2 resources
    inv.insert_resource(
        Resource(
            resource_id=None,
            service_prefix="ec2",
            resource_type="instance",
            resource_arn="arn:aws:ec2:us-east-1:123456789012:instance/i-abc123",
            resource_name="web-server",
            region="us-east-1",
            account_id="123456789012",
        )
    )

    # Insert sample Lambda resources
    inv.insert_resource(
        Resource(
            resource_id=None,
            service_prefix="lambda",
            resource_type="function",
            resource_arn="arn:aws:lambda:us-east-1:123456789012:function:processor",
            resource_name="processor",
            region="us-east-1",
            account_id="123456789012",
        )
    )

    # Insert sample DynamoDB resources
    inv.insert_resource(
        Resource(
            resource_id=None,
            service_prefix="dynamodb",
            resource_type="table",
            resource_arn="arn:aws:dynamodb:us-east-1:123456789012:table/users",
            resource_name="users",
            region="us-east-1",
            account_id="123456789012",
        )
    )

    return inv


@pytest.fixture
def empty_inventory(tmp_path):
    """Create an empty resource inventory."""
    inv_path = tmp_path / "empty_inventory.db"
    inv = ResourceInventory(inv_path)
    inv.create_schema()
    return inv


# ---------------------------------------------------------------------------
# Test resolve_wildcard_resource
# ---------------------------------------------------------------------------


class TestResolveWildcardResource:
    """Tests for resolve_wildcard_resource method."""

    def test_resolve_by_service(self, inventory):
        """Resolve all ARNs for a service."""
        arns = inventory.resolve_wildcard_resource("s3")
        assert len(arns) == 3
        assert "arn:aws:s3:::my-app-data" in arns
        assert "arn:aws:s3:::my-app-logs" in arns

    def test_resolve_by_service_and_type(self, inventory):
        """Resolve ARNs filtered by service and resource type."""
        arns = inventory.resolve_wildcard_resource("s3", "bucket")
        assert len(arns) == 2
        assert "arn:aws:s3:::my-app-data" in arns
        assert "arn:aws:s3:::my-app-logs" in arns
        # Object ARN should not be included
        assert "arn:aws:s3:::my-app-data/*" not in arns

    def test_resolve_empty_service(self, inventory):
        """Empty list returned for service with no resources."""
        arns = inventory.resolve_wildcard_resource("rds")
        assert arns == []

    def test_resolve_empty_inventory(self, empty_inventory):
        """Empty list returned from empty inventory."""
        arns = empty_inventory.resolve_wildcard_resource("s3")
        assert arns == []


# ---------------------------------------------------------------------------
# Test get_arns_for_action
# ---------------------------------------------------------------------------


class TestGetArnsForAction:
    """Tests for get_arns_for_action method.

    Task 8: the action -> resource-type refinement dict moved to
    :class:`PolicyRewriter` (DB-backed bulk load).  The inventory-side
    fallback now resolves *all* resources for the service prefix — the
    rewriter narrows by resource_type via ``resolve_wildcard_resource``
    directly when it needs to.
    """

    def test_s3_action_returns_all_s3_resources(self, inventory):
        """Any s3:* action resolves to every s3 resource (fallback)."""
        arns = inventory.get_arns_for_action("s3:GetObject")
        assert len(arns) == 3
        assert "arn:aws:s3:::my-app-data" in arns
        assert "arn:aws:s3:::my-app-logs" in arns
        assert "arn:aws:s3:::my-app-data/*" in arns

    def test_s3_list_bucket_fallback_returns_all(self, inventory):
        arns = inventory.get_arns_for_action("s3:ListBucket")
        assert len(arns) == 3

    def test_ec2_action_returns_ec2_resources(self, inventory):
        arns = inventory.get_arns_for_action("ec2:DescribeInstances")
        assert len(arns) == 1
        assert "i-abc123" in arns[0]

    def test_lambda_action_returns_lambda_resources(self, inventory):
        arns = inventory.get_arns_for_action("lambda:InvokeFunction")
        assert len(arns) == 1
        assert "processor" in arns[0]

    def test_unknown_action_returns_all_service(self, inventory):
        """Unknown action returns all resources for the service."""
        arns = inventory.get_arns_for_action("s3:UnknownAction")
        assert len(arns) == 3

    def test_invalid_action_format(self, inventory):
        """Invalid action format returns empty list."""
        arns = inventory.get_arns_for_action("invalid")
        assert arns == []

    def test_no_resources_for_action(self, inventory):
        """Empty list when no resources for action's service."""
        arns = inventory.get_arns_for_action("rds:DescribeDBInstances")
        assert arns == []


# ---------------------------------------------------------------------------
# Test has_resources_for_service
# ---------------------------------------------------------------------------


class TestHasResourcesForService:
    """Tests for has_resources_for_service method."""

    def test_has_s3_resources(self, inventory):
        """True when service has resources."""
        assert inventory.has_resources_for_service("s3") is True

    def test_has_ec2_resources(self, inventory):
        """True for EC2 with resources."""
        assert inventory.has_resources_for_service("ec2") is True

    def test_no_rds_resources(self, inventory):
        """False when service has no resources."""
        assert inventory.has_resources_for_service("rds") is False

    def test_empty_inventory_false(self, empty_inventory):
        """False for empty inventory."""
        assert empty_inventory.has_resources_for_service("s3") is False


# ---------------------------------------------------------------------------
# Test generate_placeholder_arn
# ---------------------------------------------------------------------------


class TestGeneratePlaceholderArn:
    """Tests for generate_placeholder_arn fallback method.

    Task 8: service-specific ARN templates moved to the ``arn_templates``
    DB table (consumed by :class:`PolicyRewriter`).  The inventory-side
    fallback emits a generic ``arn:aws:<svc>:<region>:<account>:<type>/...``
    shape — the tests below assert that generic contract only.  Service-
    specific assertions (e.g. S3 omitting region/account) are covered by
    rewriter tests that exercise the DB-backed path.
    """

    def test_placeholder_is_generic_arn_shape(self, inventory):
        arn = inventory.generate_placeholder_arn("s3", "bucket")
        assert arn.startswith("arn:aws:s3:")
        assert "PLACEHOLDER" in arn

    def test_ec2_placeholder_uses_region_and_account(self, inventory):
        arn = inventory.generate_placeholder_arn("ec2", "instance", "999888777666", "eu-west-1")
        assert "eu-west-1" in arn
        assert "999888777666" in arn
        assert "PLACEHOLDER" in arn

    def test_lambda_placeholder_embeds_type(self, inventory):
        arn = inventory.generate_placeholder_arn("lambda", "function")
        assert "function" in arn
        assert "PLACEHOLDER" in arn

    def test_unknown_service_placeholder(self, inventory):
        arn = inventory.generate_placeholder_arn("newservice", "widget")
        assert "arn:aws:newservice:" in arn
        assert "PLACEHOLDER" in arn

    def test_default_account_and_region(self, inventory):
        arn = inventory.generate_placeholder_arn("ec2", "instance")
        assert "123456789012" in arn
        assert "us-east-1" in arn

    def test_custom_account_and_region(self, inventory):
        arn = inventory.generate_placeholder_arn(
            "dynamodb", "table", "111222333444", "ap-southeast-1"
        )
        assert "111222333444" in arn
        assert "ap-southeast-1" in arn


# ---------------------------------------------------------------------------
# Test get_resource_types_for_service
# ---------------------------------------------------------------------------


class TestGetResourceTypesForService:
    """Tests for get_resource_types_for_service method."""

    def test_s3_resource_types(self, inventory):
        """S3 has bucket and object types."""
        types = inventory.get_resource_types_for_service("s3")
        assert "bucket" in types
        assert "object" in types
        assert len(types) == 2

    def test_ec2_resource_types(self, inventory):
        """EC2 has instance type."""
        types = inventory.get_resource_types_for_service("ec2")
        assert types == ["instance"]

    def test_empty_service_types(self, inventory):
        """No types for service without resources."""
        types = inventory.get_resource_types_for_service("rds")
        assert types == []

    def test_sorted_output(self, inventory):
        """Resource types returned in sorted order."""
        types = inventory.get_resource_types_for_service("s3")
        assert types == sorted(types)


# ---------------------------------------------------------------------------
# Test bulk_insert_resources
# ---------------------------------------------------------------------------


class TestBulkInsertResources:
    """Tests for bulk_insert_resources method."""

    def test_bulk_insert(self, empty_inventory):
        """Multiple resources inserted in one call."""
        resources = [
            Resource(
                resource_id=None,
                service_prefix="s3",
                resource_type="bucket",
                resource_arn=f"arn:aws:s3:::bucket-{i}",
                resource_name=f"bucket-{i}",
            )
            for i in range(10)
        ]
        count = empty_inventory.bulk_insert_resources(resources)
        assert count == 10

        # Verify all inserted
        stats = empty_inventory.get_statistics()
        assert stats["total_resources"] == 10

    def test_bulk_insert_empty(self, empty_inventory):
        """Bulk insert with empty list returns 0."""
        count = empty_inventory.bulk_insert_resources([])
        assert count == 0

    def test_bulk_insert_upsert(self, inventory):
        """Bulk insert with existing ARNs updates instead of failing."""
        resources = [
            Resource(
                resource_id=None,
                service_prefix="s3",
                resource_type="bucket",
                resource_arn="arn:aws:s3:::my-app-data",
                resource_name="my-app-data-updated",
            ),
            Resource(
                resource_id=None,
                service_prefix="s3",
                resource_type="bucket",
                resource_arn="arn:aws:s3:::new-bucket",
                resource_name="new-bucket",
            ),
        ]
        count = inventory.bulk_insert_resources(resources)
        assert count == 2

        # Verify update
        resource = inventory.get_resource_by_arn("arn:aws:s3:::my-app-data")
        assert resource.resource_name == "my-app-data-updated"


# ---------------------------------------------------------------------------
# Test ACTION_RESOURCE_MAP
# ---------------------------------------------------------------------------

# Tests for removed ACTION_RESOURCE_MAP / ARN_TEMPLATES class constants
# deleted — those dicts migrated to the `action_resource_map` and
# `arn_templates` DB tables in Phase 2 (see migrations 0006, 0007 and the
# corresponding DB-backed API in Database.list_action_resource_map() /
# Database.list_arn_templates()).  Behaviour is covered by Phase 2 DB
# tests; the class-constant assertion pattern is defunct.

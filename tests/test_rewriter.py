"""Unit tests for the Policy Rewriter module.

Tests cover wildcard replacement, resource scoping, companion permissions,
condition key injection, statement reorganization, and JSON serialization.
"""

import json
import pytest
from pathlib import Path

from src.sentinel.parser import Policy, Statement
from src.sentinel.rewriter import (
    PolicyRewriter,
    RewriteConfig,
    RewriteResult,
    RewriteChange,
)
from src.sentinel.database import Database, DatabaseError, Service, Action
from src.sentinel.inventory import ResourceInventory, Resource

from tests.conftest import make_test_db


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def tmp_db(tmp_path, migrated_db_template):
    """Create a migrated + seeded IAM actions DB with sample actions.

    Task 0 migration: make_test_db supplies the Phase 2 tables
    (action_resource_map / arn_templates / dangerous_actions /
    companion_rules) so PolicyRewriter's Task 7 bulk-load finds rows.

    v0.7.0 (Phase 7.3): uses ``template=migrated_db_template`` for the
    session-scoped fast-copy path (~1ms per test vs ~200ms migration).
    """
    db_path = make_test_db(tmp_path, template=migrated_db_template)
    db = Database(db_path)

    # Insert services
    for svc in [
        Service(service_prefix="s3", service_name="Amazon S3"),
        Service(service_prefix="ec2", service_name="Amazon EC2"),
        Service(service_prefix="lambda", service_name="AWS Lambda"),
        Service(service_prefix="iam", service_name="AWS IAM"),
        Service(service_prefix="logs", service_name="CloudWatch Logs"),
        Service(service_prefix="kms", service_name="AWS KMS"),
    ]:
        db.insert_service(svc)

    # Insert S3 actions
    s3_actions = [
        ("GetObject", "Read", True),
        ("PutObject", "Write", False),
        ("DeleteObject", "Write", False),
        ("ListBucket", "List", True),
        ("GetBucketPolicy", "Read", True),
        ("PutBucketPolicy", "Permissions management", False),
        ("GetBucketLocation", "Read", True),
        ("HeadObject", "Read", True),
        ("CopyObject", "Write", False),
        ("CreateMultipartUpload", "Write", False),
    ]
    for name, level, is_read in s3_actions:
        db.insert_action(
            Action(
                action_id=None,
                service_prefix="s3",
                action_name=name,
                full_action=f"s3:{name}",
                description=f"S3 {name}",
                access_level=level,
                is_list=(level == "List"),
                is_read=(level == "Read"),
                is_write=(level == "Write"),
                is_permissions_management=(level == "Permissions management"),
            )
        )

    # Insert EC2 actions
    ec2_actions = [
        ("DescribeInstances", "List", True, False),
        ("RunInstances", "Write", False, True),
        ("TerminateInstances", "Write", False, True),
        ("StartInstances", "Write", False, True),
        ("StopInstances", "Write", False, True),
    ]
    for name, level, is_read, is_write in ec2_actions:
        db.insert_action(
            Action(
                action_id=None,
                service_prefix="ec2",
                action_name=name,
                full_action=f"ec2:{name}",
                description=f"EC2 {name}",
                access_level=level,
                is_list=(level == "List"),
                is_read=is_read,
                is_write=is_write,
            )
        )

    # Insert Lambda actions
    for name in ["InvokeFunction", "CreateFunction", "UpdateFunctionCode"]:
        db.insert_action(
            Action(
                action_id=None,
                service_prefix="lambda",
                action_name=name,
                full_action=f"lambda:{name}",
                description=f"Lambda {name}",
                access_level="Write",
                is_write=True,
            )
        )

    # Insert logs actions
    for name in ["CreateLogGroup", "CreateLogStream", "PutLogEvents"]:
        db.insert_action(
            Action(
                action_id=None,
                service_prefix="logs",
                action_name=name,
                full_action=f"logs:{name}",
                description=f"Logs {name}",
                access_level="Write",
                is_write=True,
            )
        )

    return db


@pytest.fixture
def tmp_inventory(tmp_path):
    """Create a temporary resource inventory with sample data."""
    inv_path = tmp_path / "test_inventory.db"
    inv = ResourceInventory(inv_path)
    inv.create_schema()

    # Insert sample resources
    resources = [
        Resource(
            resource_id=None,
            service_prefix="s3",
            resource_type="bucket",
            resource_arn="arn:aws:s3:::my-app-data",
            resource_name="my-app-data",
            region=None,
            account_id="123456789012",
        ),
        Resource(
            resource_id=None,
            service_prefix="s3",
            resource_type="bucket",
            resource_arn="arn:aws:s3:::my-app-logs",
            resource_name="my-app-logs",
            region=None,
            account_id="123456789012",
        ),
        Resource(
            resource_id=None,
            service_prefix="ec2",
            resource_type="instance",
            resource_arn="arn:aws:ec2:us-east-1:123456789012:instance/i-0123456789abcdef0",
            resource_name="web-server",
            region="us-east-1",
            account_id="123456789012",
        ),
        Resource(
            resource_id=None,
            service_prefix="lambda",
            resource_type="function",
            resource_arn="arn:aws:lambda:us-east-1:123456789012:function:my-function",
            resource_name="my-function",
            region="us-east-1",
            account_id="123456789012",
        ),
    ]
    for r in resources:
        inv.insert_resource(r)

    return inv


@pytest.fixture
def simple_policy():
    """Create a simple test policy."""
    return Policy(
        version="2012-10-17",
        statements=[
            Statement(
                effect="Allow",
                actions=["s3:GetObject", "s3:PutObject"],
                resources=["*"],
            )
        ],
    )


@pytest.fixture
def wildcard_policy():
    """Create a policy with wildcard actions."""
    return Policy(
        version="2012-10-17",
        statements=[
            Statement(
                effect="Allow",
                actions=["s3:*"],
                resources=["*"],
            )
        ],
    )


@pytest.fixture
def full_wildcard_policy():
    """Create a policy with full wildcard."""
    return Policy(
        version="2012-10-17",
        statements=[
            Statement(
                effect="Allow",
                actions=["*"],
                resources=["*"],
            )
        ],
    )


@pytest.fixture
def deny_policy():
    """Create a policy with Deny statement."""
    return Policy(
        version="2012-10-17",
        statements=[
            Statement(
                effect="Allow",
                actions=["s3:GetObject"],
                resources=["*"],
            ),
            Statement(
                effect="Deny",
                actions=["s3:DeleteBucket"],
                resources=["*"],
            ),
        ],
    )


@pytest.fixture
def lambda_policy():
    """Create a Lambda policy (needs companion permissions)."""
    return Policy(
        version="2012-10-17",
        statements=[
            Statement(
                effect="Allow",
                actions=["lambda:InvokeFunction"],
                resources=["*"],
            )
        ],
    )


# ---------------------------------------------------------------------------
# Test PolicyRewriter Initialization
# ---------------------------------------------------------------------------


class TestPolicyRewriterInit:
    """Tests for PolicyRewriter initialization."""

    def test_init_no_args_hard_fails(self):
        """PolicyRewriter() with no DB HARD-FAILS under Task 8b D3.

        Task 8b removed the class-constant fallback path — CompanionPermission
        Detector now requires a seeded Database and raises DatabaseError when
        constructed with None.  PolicyRewriter.__init__ delegates to it, so
        the no-arg form must hard-fail.  This test documents the contract so
        the deleted fallback cannot silently regress.
        """
        with pytest.raises(DatabaseError):
            PolicyRewriter()

    def test_init_with_database(self, tmp_db):
        """Rewriter accepts a Database instance."""
        rewriter = PolicyRewriter(database=tmp_db)
        assert rewriter.database is tmp_db

    def test_init_with_inventory(self, tmp_db, tmp_inventory):
        """Rewriter accepts a ResourceInventory instance.

        Task 8b migration: Database is now mandatory; thread tmp_db as the
        required DB dependency so the test exercises the inventory-assignment
        path without tripping the D3 HARD-FAIL.
        """
        rewriter = PolicyRewriter(database=tmp_db, inventory=tmp_inventory)
        assert rewriter.inventory is tmp_inventory

    def test_init_with_both(self, tmp_db, tmp_inventory):
        """Rewriter accepts both database and inventory."""
        rewriter = PolicyRewriter(database=tmp_db, inventory=tmp_inventory)
        assert rewriter.database is tmp_db
        assert rewriter.inventory is tmp_inventory


# ---------------------------------------------------------------------------
# Test Wildcard Replacement
# ---------------------------------------------------------------------------


class TestWildcardReplacement:
    """Tests for wildcard action replacement."""

    def test_no_wildcards_unchanged(self, tmp_db, simple_policy):
        """Actions without wildcards are not modified."""
        rewriter = PolicyRewriter(database=tmp_db)
        result = rewriter.rewrite_policy(simple_policy)
        actions = result.rewritten_policy.statements[0].actions
        assert "s3:GetObject" in actions
        assert "s3:PutObject" in actions

    def test_service_wildcard_expanded(self, tmp_db, wildcard_policy):
        """service:* is expanded to specific actions."""
        rewriter = PolicyRewriter(database=tmp_db)
        result = rewriter.rewrite_policy(wildcard_policy)
        actions = result.rewritten_policy.statements[0].actions
        assert len(actions) > 1
        assert "s3:GetObject" in actions
        assert "s3:PutObject" in actions
        assert "s3:ListBucket" in actions

    def test_wildcard_change_tracked(self, tmp_db, wildcard_policy):
        """Wildcard replacement creates a change record."""
        rewriter = PolicyRewriter(database=tmp_db)
        result = rewriter.rewrite_policy(wildcard_policy)
        wildcard_changes = [c for c in result.changes if c.change_type == "WILDCARD_REPLACED"]
        assert len(wildcard_changes) >= 1
        assert wildcard_changes[0].original_value == "s3:*"

    def test_prefix_wildcard_expanded(self, tmp_db):
        """service:Get* is expanded to matching actions."""
        policy = Policy(
            version="2012-10-17",
            statements=[
                Statement(
                    effect="Allow",
                    actions=["s3:Get*"],
                    resources=["*"],
                )
            ],
        )
        rewriter = PolicyRewriter(database=tmp_db)
        result = rewriter.rewrite_policy(policy)
        actions = result.rewritten_policy.statements[0].actions
        assert "s3:GetObject" in actions
        assert "s3:GetBucketPolicy" in actions
        assert "s3:GetBucketLocation" in actions
        assert "s3:PutObject" not in actions

    def test_full_wildcard_without_intent(self, tmp_db, full_wildcard_policy):
        """Full wildcard without intent is kept as-is."""
        rewriter = PolicyRewriter(database=tmp_db)
        result = rewriter.rewrite_policy(full_wildcard_policy)
        actions = result.rewritten_policy.statements[0].actions
        assert "*" in actions

    def test_full_wildcard_with_intent(self, tmp_db, full_wildcard_policy):
        """Full wildcard with intent is expanded based on intent."""
        rewriter = PolicyRewriter(database=tmp_db)
        config = RewriteConfig(intent="read-only s3")
        result = rewriter.rewrite_policy(full_wildcard_policy, config)
        actions = result.rewritten_policy.statements[0].actions
        assert "s3:GetObject" in actions
        assert "s3:ListBucket" in actions
        # Write actions should NOT be included for read-only intent
        assert "s3:PutObject" not in actions
        assert "s3:DeleteObject" not in actions

    # NOTE: test_wildcard_no_database and test_no_database_assumption were
    # deleted under Task 8b D3 HARD-FAIL migration.  Both tests explicitly
    # exercised the no-database fallback path ("wildcards kept when no DB",
    # "assumption recorded when no DB").  Task 8b removed the fallback —
    # PolicyRewriter() without a Database now raises DatabaseError at
    # construction, so there is no meaningful "no DB" code path left to
    # test.  The hard-fail contract is documented in
    # TestPolicyRewriterInit.test_init_no_args_hard_fails.


# ---------------------------------------------------------------------------
# Test Resource Scoping
# ---------------------------------------------------------------------------


class TestResourceScoping:
    """Tests for resource ARN scoping."""

    def test_wildcard_resource_replaced_with_real_arns(self, tmp_db, tmp_inventory, simple_policy):
        """Wildcard resource replaced with real ARNs from inventory."""
        rewriter = PolicyRewriter(database=tmp_db, inventory=tmp_inventory)
        result = rewriter.rewrite_policy(simple_policy)
        resources = result.rewritten_policy.statements[0].resources
        assert "*" not in resources
        assert any("my-app-data" in r for r in resources)

    def test_wildcard_resource_placeholder_no_inventory(self, tmp_db, simple_policy):
        """Placeholder ARN generated when no inventory available."""
        rewriter = PolicyRewriter(database=tmp_db)
        config = RewriteConfig(account_id="111222333444", region="eu-west-1")
        result = rewriter.rewrite_policy(simple_policy, config)
        resources = result.rewritten_policy.statements[0].resources
        assert "*" not in resources
        assert any("PLACEHOLDER" in r for r in resources)

    def test_non_wildcard_resource_preserved(self, tmp_db):
        """Non-wildcard resources are not modified."""
        policy = Policy(
            version="2012-10-17",
            statements=[
                Statement(
                    effect="Allow",
                    actions=["s3:GetObject"],
                    resources=["arn:aws:s3:::my-bucket/*"],
                )
            ],
        )
        rewriter = PolicyRewriter(database=tmp_db)
        result = rewriter.rewrite_policy(policy)
        resources = result.rewritten_policy.statements[0].resources
        assert "arn:aws:s3:::my-bucket/*" in resources

    def test_arn_scoped_change_tracked(self, tmp_db, tmp_inventory, simple_policy):
        """Resource scoping creates a change record."""
        rewriter = PolicyRewriter(database=tmp_db, inventory=tmp_inventory)
        result = rewriter.rewrite_policy(simple_policy)
        arn_changes = [c for c in result.changes if c.change_type == "ARN_SCOPED"]
        assert len(arn_changes) >= 1

    def test_no_inventory_assumption(self, tmp_db, simple_policy):
        """Assumption recorded when no inventory is available.

        Task 8b migration: PolicyRewriter now REQUIRES a Database (D3
        HARD-FAIL).  The test's premise — that a missing inventory
        records an assumption — still holds; only the test's construction
        needed to thread the required `tmp_db` fixture.
        """
        rewriter = PolicyRewriter(database=tmp_db)
        result = rewriter.rewrite_policy(simple_policy)
        assert any("inventory" in a.lower() for a in result.assumptions)


# ---------------------------------------------------------------------------
# Test Deny Statement Preservation
# ---------------------------------------------------------------------------


class TestDenyPreservation:
    """Tests for Deny statement preservation."""

    def test_deny_preserved(self, tmp_db, deny_policy):
        """Deny statements are preserved unchanged."""
        rewriter = PolicyRewriter(database=tmp_db)
        result = rewriter.rewrite_policy(deny_policy)
        deny_stmts = [s for s in result.rewritten_policy.statements if s.effect == "Deny"]
        assert len(deny_stmts) == 1
        assert deny_stmts[0].actions == ["s3:DeleteBucket"]
        assert deny_stmts[0].resources == ["*"]

    def test_deny_not_preserved_when_disabled(self, tmp_db, deny_policy):
        """Deny statements processed when preservation disabled."""
        rewriter = PolicyRewriter(database=tmp_db)
        config = RewriteConfig(preserve_deny_statements=False)
        result = rewriter.rewrite_policy(deny_policy, config)
        deny_stmts = [s for s in result.rewritten_policy.statements if s.effect == "Deny"]
        # Deny statement should have a Sid assigned now
        assert len(deny_stmts) >= 1


# ---------------------------------------------------------------------------
# Test Companion Permissions
# ---------------------------------------------------------------------------


class TestCompanionPermissions:
    """Tests for companion permission injection."""

    def test_lambda_companions_added(self, tmp_db, lambda_policy):
        """Lambda InvokeFunction gets CloudWatch Logs companions."""
        rewriter = PolicyRewriter(database=tmp_db)
        result = rewriter.rewrite_policy(lambda_policy)
        all_actions = []
        for stmt in result.rewritten_policy.statements:
            all_actions.extend(stmt.actions)
        assert "logs:CreateLogGroup" in all_actions
        assert "logs:CreateLogStream" in all_actions
        assert "logs:PutLogEvents" in all_actions

    def test_companion_change_tracked(self, tmp_db, lambda_policy):
        """Companion addition creates a change record."""
        rewriter = PolicyRewriter(database=tmp_db)
        result = rewriter.rewrite_policy(lambda_policy)
        companion_changes = [c for c in result.changes if c.change_type == "COMPANION_ADDED"]
        assert len(companion_changes) >= 1

    def test_companions_not_added_when_disabled(self, tmp_db, lambda_policy):
        """Companions not added when config disables them."""
        rewriter = PolicyRewriter(database=tmp_db)
        config = RewriteConfig(add_companions=False)
        result = rewriter.rewrite_policy(lambda_policy, config)
        all_actions = []
        for stmt in result.rewritten_policy.statements:
            all_actions.extend(stmt.actions)
        assert "logs:CreateLogGroup" not in all_actions

    def test_companions_recorded_in_result(self, tmp_db, lambda_policy):
        """Companion permissions appear in result.companion_permissions_added."""
        rewriter = PolicyRewriter(database=tmp_db)
        result = rewriter.rewrite_policy(lambda_policy)
        assert len(result.companion_permissions_added) >= 1
        assert result.companion_permissions_added[0].primary_action == ("lambda:InvokeFunction")

    def test_existing_companions_not_duplicated(self, tmp_db):
        """Already-present companion actions are not added again."""
        policy = Policy(
            version="2012-10-17",
            statements=[
                Statement(
                    effect="Allow",
                    actions=[
                        "lambda:InvokeFunction",
                        "logs:CreateLogGroup",
                        "logs:CreateLogStream",
                        "logs:PutLogEvents",
                    ],
                    resources=["*"],
                )
            ],
        )
        rewriter = PolicyRewriter(database=tmp_db)
        result = rewriter.rewrite_policy(policy)
        assert len(result.companion_permissions_added) == 0


# ---------------------------------------------------------------------------
# Test Condition Key Injection
# ---------------------------------------------------------------------------


class TestConditionKeyInjection:
    """Tests for condition key injection."""

    def test_region_condition_added(self, tmp_db, simple_policy):
        """Region restriction added when region specified."""
        rewriter = PolicyRewriter(database=tmp_db)
        config = RewriteConfig(region="us-east-1")
        result = rewriter.rewrite_policy(simple_policy, config)
        stmt = result.rewritten_policy.statements[0]
        assert stmt.conditions is not None
        assert stmt.conditions["StringEquals"]["aws:RequestedRegion"] == ("us-east-1")

    def test_s3_encryption_condition_added(self, tmp_db):
        """S3 encryption condition added for PutObject."""
        policy = Policy(
            version="2012-10-17",
            statements=[
                Statement(
                    effect="Allow",
                    actions=["s3:PutObject"],
                    resources=["arn:aws:s3:::my-bucket/*"],
                )
            ],
        )
        rewriter = PolicyRewriter(database=tmp_db)
        config = RewriteConfig(add_conditions=True)
        result = rewriter.rewrite_policy(policy, config)
        stmt = result.rewritten_policy.statements[0]
        assert stmt.conditions is not None
        assert "s3:x-amz-server-side-encryption" in (stmt.conditions.get("StringEquals", {}))

    def test_source_account_condition_added(self, tmp_db):
        """Source account condition added for resource-based policies only."""
        # aws:SourceAccount is meaningful in resource-based policies
        # (with Principal), not identity policies.
        policy = Policy(
            version="2012-10-17",
            statements=[
                Statement(
                    effect="Allow",
                    actions=["lambda:InvokeFunction"],
                    resources=["*"],
                    principals={"AWS": "arn:aws:iam::111222333444:root"},
                )
            ],
        )
        rewriter = PolicyRewriter(database=tmp_db)
        config = RewriteConfig(account_id="123456789012")
        result = rewriter.rewrite_policy(policy, config)
        for stmt in result.rewritten_policy.statements:
            if "lambda:InvokeFunction" in stmt.actions:
                assert stmt.conditions is not None
                assert stmt.conditions["StringEquals"]["aws:SourceAccount"] == "123456789012"
                break

    def test_conditions_not_added_when_disabled(self, tmp_db, simple_policy):
        """Conditions not added when disabled in config."""
        rewriter = PolicyRewriter(database=tmp_db)
        config = RewriteConfig(add_conditions=False, region="us-east-1")
        result = rewriter.rewrite_policy(simple_policy, config)
        stmt = result.rewritten_policy.statements[0]
        assert stmt.conditions is None

    def test_existing_conditions_preserved(self, tmp_db):
        """Existing conditions are preserved and merged."""
        policy = Policy(
            version="2012-10-17",
            statements=[
                Statement(
                    effect="Allow",
                    actions=["s3:GetObject"],
                    resources=["*"],
                    conditions={"StringEquals": {"aws:PrincipalOrgID": "o-123456"}},
                )
            ],
        )
        rewriter = PolicyRewriter(database=tmp_db)
        config = RewriteConfig(region="us-east-1")
        result = rewriter.rewrite_policy(policy, config)
        stmt = result.rewritten_policy.statements[0]
        assert stmt.conditions["StringEquals"]["aws:PrincipalOrgID"] == ("o-123456")
        assert "aws:RequestedRegion" in stmt.conditions["StringEquals"]

    def test_condition_change_tracked(self, tmp_db, simple_policy):
        """Condition injection creates a change record."""
        rewriter = PolicyRewriter(database=tmp_db)
        config = RewriteConfig(region="us-east-1")
        result = rewriter.rewrite_policy(simple_policy, config)
        condition_changes = [c for c in result.changes if c.change_type == "CONDITION_ADDED"]
        assert len(condition_changes) >= 1

    def test_global_service_no_region_condition(self, tmp_db):
        """Global services (IAM) do not get region restriction."""
        policy = Policy(
            version="2012-10-17",
            statements=[
                Statement(
                    effect="Allow",
                    actions=["iam:GetUser"],
                    resources=["*"],
                )
            ],
        )
        rewriter = PolicyRewriter(database=tmp_db)
        config = RewriteConfig(region="us-east-1")
        result = rewriter.rewrite_policy(policy, config)
        stmt = result.rewritten_policy.statements[0]
        # IAM is global, should not have region restriction
        if stmt.conditions:
            assert "aws:RequestedRegion" not in (stmt.conditions.get("StringEquals", {}))


# ---------------------------------------------------------------------------
# Test Statement Reorganization
# ---------------------------------------------------------------------------


class TestStatementReorganization:
    """Tests for statement reorganization."""

    def test_sid_generated(self, tmp_db, simple_policy):
        """Descriptive Sid generated for statements."""
        rewriter = PolicyRewriter(database=tmp_db)
        result = rewriter.rewrite_policy(simple_policy)
        for stmt in result.rewritten_policy.statements:
            assert stmt.sid is not None
            assert len(stmt.sid) > 0

    def test_large_statement_split(self, tmp_db):
        """Large statements are split into smaller ones."""
        actions = [
            f"s3:{name}"
            for name in [
                "GetObject",
                "PutObject",
                "DeleteObject",
                "ListBucket",
                "GetBucketPolicy",
                "PutBucketPolicy",
                "GetBucketLocation",
                "HeadObject",
                "CopyObject",
                "CreateMultipartUpload",
            ]
        ]
        # Add more to exceed max_actions_per_statement
        actions.extend(
            [
                "ec2:DescribeInstances",
                "ec2:RunInstances",
                "ec2:TerminateInstances",
                "ec2:StartInstances",
                "ec2:StopInstances",
                "lambda:InvokeFunction",
            ]
        )
        policy = Policy(
            version="2012-10-17",
            statements=[
                Statement(
                    effect="Allow",
                    actions=actions,
                    resources=["*"],
                )
            ],
        )
        rewriter = PolicyRewriter(database=tmp_db)
        config = RewriteConfig(
            max_actions_per_statement=5,
            add_companions=False,
        )
        result = rewriter.rewrite_policy(policy, config)
        # Should have multiple statements now
        assert len(result.rewritten_policy.statements) > 1

    def test_sid_format_valid(self, tmp_db, simple_policy):
        """Generated Sids contain only valid characters."""
        rewriter = PolicyRewriter(database=tmp_db)
        result = rewriter.rewrite_policy(simple_policy)
        import re

        for stmt in result.rewritten_policy.statements:
            if stmt.sid:
                assert re.match(r"^[A-Za-z0-9]+$", stmt.sid), f"Invalid Sid: {stmt.sid}"


# ---------------------------------------------------------------------------
# Test NotAction / NotResource Handling
# ---------------------------------------------------------------------------


class TestNotActionNotResource:
    """Tests for NotAction and NotResource handling."""

    def test_not_action_preserved(self, tmp_db):
        """NotAction statements preserved with warning."""
        policy = Policy(
            version="2012-10-17",
            statements=[
                Statement(
                    effect="Allow",
                    actions=[],
                    resources=["*"],
                    not_actions=["iam:*"],
                )
            ],
        )
        rewriter = PolicyRewriter(database=tmp_db)
        result = rewriter.rewrite_policy(policy)
        assert result.rewritten_policy.statements[0].not_actions == ["iam:*"]
        assert any("NotAction" in w for w in result.warnings)

    def test_not_resource_preserved(self, tmp_db):
        """NotResource statements preserved with warning."""
        policy = Policy(
            version="2012-10-17",
            statements=[
                Statement(
                    effect="Allow",
                    actions=["s3:*"],
                    resources=[],
                    not_resources=["arn:aws:s3:::sensitive-bucket"],
                )
            ],
        )
        rewriter = PolicyRewriter(database=tmp_db)
        result = rewriter.rewrite_policy(policy)
        assert result.rewritten_policy.statements[0].not_resources == [
            "arn:aws:s3:::sensitive-bucket"
        ]
        assert any("NotResource" in w for w in result.warnings)


# ---------------------------------------------------------------------------
# Test JSON Serialization
# ---------------------------------------------------------------------------


class TestJsonSerialization:
    """Tests for policy JSON serialization."""

    def test_to_policy_json_basic(self, tmp_db, simple_policy):
        """Basic policy converts to valid JSON."""
        rewriter = PolicyRewriter(database=tmp_db)
        result = rewriter.rewrite_policy(simple_policy)
        json_output = rewriter.to_policy_json(result.rewritten_policy)
        assert json_output["Version"] == "2012-10-17"
        assert "Statement" in json_output
        assert len(json_output["Statement"]) >= 1

    def test_to_policy_json_serializable(self, tmp_db, simple_policy):
        """Output is JSON-serializable."""
        rewriter = PolicyRewriter(database=tmp_db)
        result = rewriter.rewrite_policy(simple_policy)
        json_output = rewriter.to_policy_json(result.rewritten_policy)
        json_str = json.dumps(json_output, indent=2)
        assert isinstance(json_str, str)

    def test_to_policy_json_single_action(self, tmp_db):
        """Single action serialized as string, not list."""
        policy = Policy(
            version="2012-10-17",
            statements=[
                Statement(
                    effect="Allow",
                    actions=["s3:GetObject"],
                    resources=["arn:aws:s3:::my-bucket/*"],
                )
            ],
        )
        rewriter = PolicyRewriter(database=tmp_db)
        config = RewriteConfig(add_conditions=False, add_companions=False)
        result = rewriter.rewrite_policy(policy, config)
        json_output = rewriter.to_policy_json(result.rewritten_policy)
        stmt = json_output["Statement"][0]
        assert isinstance(stmt["Action"], str)
        assert isinstance(stmt["Resource"], str)

    def test_to_policy_json_conditions_included(self, tmp_db):
        """Conditions included in JSON output."""
        policy = Policy(
            version="2012-10-17",
            statements=[
                Statement(
                    effect="Allow",
                    actions=["s3:GetObject"],
                    resources=["*"],
                    conditions={"StringEquals": {"aws:PrincipalOrgID": "o-123"}},
                )
            ],
        )
        rewriter = PolicyRewriter(database=tmp_db)
        config = RewriteConfig(add_conditions=False)
        result = rewriter.rewrite_policy(policy, config)
        json_output = rewriter.to_policy_json(result.rewritten_policy)
        stmt = json_output["Statement"][0]
        assert "Condition" in stmt
        assert stmt["Condition"]["StringEquals"]["aws:PrincipalOrgID"] == ("o-123")

    def test_to_policy_json_sid_included(self, tmp_db, simple_policy):
        """Sid included in JSON output."""
        rewriter = PolicyRewriter(database=tmp_db)
        result = rewriter.rewrite_policy(simple_policy)
        json_output = rewriter.to_policy_json(result.rewritten_policy)
        stmt = json_output["Statement"][0]
        assert "Sid" in stmt

    def test_to_policy_json_with_not_action(self, tmp_db):
        """NotAction serialized correctly."""
        policy = Policy(
            version="2012-10-17",
            statements=[
                Statement(
                    effect="Allow",
                    actions=[],
                    resources=["*"],
                    not_actions=["iam:*"],
                )
            ],
        )
        rewriter = PolicyRewriter(database=tmp_db)
        result = rewriter.rewrite_policy(policy)
        json_output = rewriter.to_policy_json(result.rewritten_policy)
        stmt = json_output["Statement"][0]
        assert "NotAction" in stmt
        assert "Action" not in stmt


# ---------------------------------------------------------------------------
# Test RewriteResult
# ---------------------------------------------------------------------------


class TestRewriteResult:
    """Tests for RewriteResult structure."""

    def test_original_policy_preserved(self, tmp_db, simple_policy):
        """Original policy is preserved in result."""
        rewriter = PolicyRewriter(database=tmp_db)
        result = rewriter.rewrite_policy(simple_policy)
        assert result.original_policy is simple_policy

    def test_result_has_changes(self, tmp_db, wildcard_policy):
        """Result contains change records."""
        rewriter = PolicyRewriter(database=tmp_db)
        result = rewriter.rewrite_policy(wildcard_policy)
        assert len(result.changes) > 0

    # NOTE: test_result_has_assumptions was deleted under Task 8b D3
    # HARD-FAIL migration.  The test explicitly exercised the "DB missing"
    # assumption-population path — PolicyRewriter() with no DB now raises
    # DatabaseError, so the scenario is unreachable.  Inventory-missing
    # assumption coverage is preserved in
    # TestResourceScoping.test_no_inventory_assumption (which passes a DB
    # and omits inventory).

    def test_intent_assumption_recorded(self, tmp_db, simple_policy):
        """Intent recorded in assumptions."""
        rewriter = PolicyRewriter(database=tmp_db)
        config = RewriteConfig(intent="read-only s3 access")
        result = rewriter.rewrite_policy(simple_policy, config)
        assert any("read-only s3 access" in a for a in result.assumptions)


# ---------------------------------------------------------------------------
# Test Default Config
# ---------------------------------------------------------------------------


class TestRewriteConfig:
    """Tests for RewriteConfig defaults."""

    def test_default_config(self):
        """Default config has sensible defaults."""
        config = RewriteConfig()
        assert config.add_companions is True
        assert config.add_conditions is True
        assert config.preserve_deny_statements is True
        assert config.max_actions_per_statement == 15
        assert config.placeholder_format == "PLACEHOLDER"

    def test_config_no_mutation(self, tmp_db, simple_policy):
        """Rewriting with default config works without error."""
        rewriter = PolicyRewriter(database=tmp_db)
        result = rewriter.rewrite_policy(simple_policy)
        assert result.rewritten_policy is not None


class TestRewriteConfigIntentSpec:
    """RewriteConfig carries an optional IntentSpec alongside intent: str."""

    def test_rewrite_config_accepts_intent_spec(self):
        from sentinel.intent_spec import IntentSpec

        spec = IntentSpec.from_string("read s3 deploy")
        config = RewriteConfig(intent="read s3 deploy", intent_spec=spec)
        assert config.intent_spec is spec
        assert config.intent == "read s3 deploy"

    def test_rewrite_config_intent_spec_optional(self):
        config = RewriteConfig()
        assert config.intent is None
        assert config.intent_spec is None

    def test_resolved_intent_spec_parses_string(self):
        """When only intent string is set, resolved_intent_spec() lazily parses it."""
        config = RewriteConfig(intent="read s3")
        spec = config.resolved_intent_spec()
        assert spec is not None
        assert "s3" in spec.services

    def test_resolved_intent_spec_returns_none_when_neither_set(self):
        config = RewriteConfig()
        assert config.resolved_intent_spec() is None

    def test_resolved_intent_spec_prefers_intent_spec_over_string(self):
        """If both fields are set, the typed intent_spec wins."""
        from sentinel.intent_spec import IntentSpec

        typed = IntentSpec.from_string("read s3")
        config = RewriteConfig(intent="completely different string", intent_spec=typed)
        assert config.resolved_intent_spec() is typed

    def test_resolved_intent_spec_emits_deprecation_warning(self):
        """Issue 6: lazy-parse fallback warns once per call (DeprecationWarning).

        Mirrors the tier2_excluded shim precedent at self_check.py:170.
        Library callers using only the legacy ``intent: str`` field get
        a clear migration prompt; CLI users (who now always pass
        intent_spec) won't trigger this path.
        """
        import warnings

        config = RewriteConfig(intent="read s3")
        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter("always")
            config.resolved_intent_spec()

        deprecations = [w for w in caught if issubclass(w.category, DeprecationWarning)]
        assert len(deprecations) == 1
        msg = str(deprecations[0].message)
        assert "intent_spec" in msg
        assert "v1.0.0" in msg

    def test_resolved_intent_spec_no_warning_when_intent_spec_set(self):
        """Modern callers passing intent_spec see no DeprecationWarning."""
        import warnings
        from sentinel.intent_spec import IntentSpec

        spec = IntentSpec.from_string("read s3")
        config = RewriteConfig(intent_spec=spec)
        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter("always")
            config.resolved_intent_spec()

        assert not any(issubclass(w.category, DeprecationWarning) for w in caught)


class TestFilterArnsByIntentHints:
    """The hint filter narrows candidate ARNs to those matching user intent."""

    def test_filter_keeps_only_matching_arns(self):
        arns = [
            "arn:aws:s3:::prod-deploy-artifacts",
            "arn:aws:s3:::prod-customer-data",
            "arn:aws:s3:::staging-deploy-artifacts",
        ]
        filtered = PolicyRewriter._filter_arns_by_intent_hints(arns, ["deploy"])
        assert "arn:aws:s3:::prod-deploy-artifacts" in filtered
        assert "arn:aws:s3:::staging-deploy-artifacts" in filtered
        assert "arn:aws:s3:::prod-customer-data" not in filtered

    def test_filter_passthrough_when_no_hints(self):
        arns = ["arn:aws:s3:::a", "arn:aws:s3:::b"]
        assert PolicyRewriter._filter_arns_by_intent_hints(arns, []) == arns

    def test_filter_passthrough_when_no_arns_match(self):
        """If no ARN matches any hint, return original list (typo safeguard)."""
        arns = ["arn:aws:s3:::prod-customer-data"]
        result = PolicyRewriter._filter_arns_by_intent_hints(arns, ["nonexistent"])
        assert result == arns

    def test_filter_word_boundary(self):
        """Hint matches at word boundaries (hyphen-delimited)."""
        arns = [
            "arn:aws:s3:::deploys-prod",
            "arn:aws:s3:::deploy-prod",
            "arn:aws:s3:::predeploy-prod",
        ]
        filtered = PolicyRewriter._filter_arns_by_intent_hints(arns, ["deploy"])
        assert "arn:aws:s3:::deploy-prod" in filtered
        assert "arn:aws:s3:::deploys-prod" not in filtered
        assert "arn:aws:s3:::predeploy-prod" not in filtered

    def test_filter_multiple_hints_or_logic(self):
        """Multiple hints use OR logic — any match keeps the ARN."""
        arns = [
            "arn:aws:s3:::deploy-bucket",
            "arn:aws:s3:::artifacts-bucket",
            "arn:aws:s3:::other-bucket",
        ]
        filtered = PolicyRewriter._filter_arns_by_intent_hints(arns, ["deploy", "artifacts"])
        assert "arn:aws:s3:::deploy-bucket" in filtered
        assert "arn:aws:s3:::artifacts-bucket" in filtered
        assert "arn:aws:s3:::other-bucket" not in filtered


class TestIntentDrivenScoping:
    """End-to-end: intent_spec narrows resource scope in the rewrite step."""

    def test_intent_hints_narrow_inventory_arns(self, tmp_db, tmp_path):
        """Inventory with multiple S3 buckets — intent hints select a subset."""
        from sentinel.intent_spec import IntentSpec

        inv_path = tmp_path / "intent_inv.db"
        inventory = ResourceInventory(inv_path)
        inventory.create_schema()
        for arn, name in [
            ("arn:aws:s3:::prod-deploy-artifacts", "prod-deploy-artifacts"),
            ("arn:aws:s3:::prod-customer-data", "prod-customer-data"),
            ("arn:aws:s3:::staging-deploy-builds", "staging-deploy-builds"),
        ]:
            inventory.insert_resource(
                Resource(
                    resource_id=None,
                    service_prefix="s3",
                    resource_type="bucket",
                    resource_arn=arn,
                    resource_name=name,
                    region=None,
                    account_id="123456789012",
                )
            )

        rewriter = PolicyRewriter(database=tmp_db, inventory=inventory)
        statement = Statement(effect="Allow", actions=["s3:GetObject"], resources=["*"])
        spec = IntentSpec.from_string("read s3 deploy artifacts")
        config = RewriteConfig(intent_spec=spec)

        scoped, changes = rewriter._scope_resources(statement, config, stmt_index=0)

        assert "arn:aws:s3:::prod-deploy-artifacts" in scoped.resources
        assert "arn:aws:s3:::staging-deploy-builds" in scoped.resources
        assert "arn:aws:s3:::prod-customer-data" not in scoped.resources

        filter_changes = [c for c in changes if c.change_type == "ARN_FILTERED_BY_INTENT"]
        assert len(filter_changes) >= 1, "expected ARN_FILTERED_BY_INTENT in audit trail"

    def test_no_intent_does_not_filter(self, tmp_db, tmp_inventory):
        """Without intent_spec, _scope_resources keeps existing behavior."""
        statement = Statement(effect="Allow", actions=["s3:GetObject"], resources=["*"])
        rewriter = PolicyRewriter(database=tmp_db, inventory=tmp_inventory)
        config = RewriteConfig()  # no intent

        scoped, changes = rewriter._scope_resources(statement, config, stmt_index=0)

        # Both my-app-data and my-app-logs should be scoped (no narrowing)
        assert any("my-app-data" in r for r in scoped.resources)
        assert any("my-app-logs" in r for r in scoped.resources)
        # No filter changes when no hints
        assert all(c.change_type != "ARN_FILTERED_BY_INTENT" for c in changes)

    def test_intent_hints_no_match_emits_warning_change(self, tmp_db, tmp_path):
        """Issue 1: hints matching 0 ARNs emit ARN_INTENT_FILTER_NO_MATCH (confidence 0.4).

        confidence=0.4 trips _check_low_confidence (self_check.py:845, strict
        ``<0.5``) so the operator sees a WARNING instead of silently keeping
        the full unfiltered candidate set when their hint is a typo.
        """
        from sentinel.intent_spec import IntentSpec

        inv = ResourceInventory(tmp_path / "no_match_inv.db")
        inv.create_schema()
        inv.insert_resource(
            Resource(
                resource_id=None,
                service_prefix="s3",
                resource_type="bucket",
                resource_arn="arn:aws:s3:::prod-customer-data",
                resource_name="prod-customer-data",
                region=None,
                account_id="123456789012",
            )
        )
        rewriter = PolicyRewriter(database=tmp_db, inventory=inv)
        stmt = Statement(effect="Allow", actions=["s3:GetObject"], resources=["*"])
        spec = IntentSpec.from_string("read s3 prodd")  # typo: "prodd"
        config = RewriteConfig(intent_spec=spec)

        scoped, changes = rewriter._scope_resources(stmt, config, stmt_index=0)

        # Passthrough: full candidate ARN list preserved.
        assert "arn:aws:s3:::prod-customer-data" in scoped.resources

        # And — the new audit signal MUST be present.
        no_match = [c for c in changes if c.change_type == "ARN_INTENT_FILTER_NO_MATCH"]
        assert len(no_match) == 1, "expected ARN_INTENT_FILTER_NO_MATCH change record"
        assert no_match[0].confidence == 0.4
        assert no_match[0].confidence < 0.5  # trips _check_low_confidence gate

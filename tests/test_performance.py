"""Performance and stress tests for IAM Policy Sentinel.

Tests cover large policies, large databases, large inventories, and
pipeline stress scenarios. Each test uses time.time() to measure
execution time and asserts completion within a generous time limit
to guard against infinite loops or algorithmic regressions.
"""

import json
import time
from pathlib import Path

import pytest

from src.sentinel.parser import PolicyParser
from src.sentinel.database import Database, Service, Action
from src.sentinel.inventory import ResourceInventory, Resource
from src.sentinel.self_check import Pipeline, PipelineConfig, PipelineResult
from src.sentinel.analyzer import RiskAnalyzer
from src.sentinel.rewriter import PolicyRewriter, RewriteConfig


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

MAX_ALLOWED_SECONDS = 60
ACCESS_LEVELS = ["Read", "Write", "List"]


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _rotating_access_level(index: int) -> str:
    """Return an access level rotating through Read, Write, List."""
    return ACCESS_LEVELS[index % len(ACCESS_LEVELS)]


def _access_level_flags(level: str):
    """Return (is_list, is_read, is_write) flags for a given access level."""
    return (
        level == "List",
        level == "Read",
        level == "Write",
    )


def _build_db_with_services(tmp_path, num_services, actions_per_service=0):
    """Build a temporary database with generated services and optional actions.

    Uses a single connection for bulk action insertion to avoid per-row
    connection overhead (the Database API opens/closes per call).

    Args:
        tmp_path: pytest tmp_path fixture.
        num_services: Number of services to insert.
        actions_per_service: Number of actions to insert per service.

    Returns:
        Database instance.
    """
    db_path = tmp_path / "perf_test.db"
    db = Database(db_path)
    db.create_schema()

    for i in range(num_services):
        db.insert_service(
            Service(
                service_prefix=f"svc{i}",
                service_name=f"Service {i}",
            )
        )

    if actions_per_service > 0:
        # Use a single connection for bulk inserts to avoid per-row overhead
        with db.get_connection() as conn:
            cursor = conn.cursor()
            rows = []
            for i in range(num_services):
                for j in range(actions_per_service):
                    level = _rotating_access_level(j)
                    is_list, is_read, is_write = _access_level_flags(level)
                    rows.append((
                        f"svc{i}",
                        f"Action{j}",
                        f"Service {i} action {j}",
                        level,
                        None,
                        is_list,
                        is_read,
                        is_write,
                        False,
                        False,
                    ))
            cursor.executemany(
                "INSERT OR REPLACE INTO actions "
                "(service_prefix, action_name, description, access_level, "
                "reference_url, is_list, is_read, is_write, "
                "is_permissions_management, is_tagging_only) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                rows,
            )

    return db


def _build_inventory_with_resources(tmp_path, num_resources):
    """Build a temporary inventory with generated resources.

    Args:
        tmp_path: pytest tmp_path fixture.
        num_resources: Number of resources to insert.

    Returns:
        ResourceInventory instance.
    """
    inv_path = tmp_path / "perf_inventory.db"
    inv = ResourceInventory(inv_path)
    inv.create_schema()

    resources = []
    for i in range(num_resources):
        svc_index = i % 10
        resources.append(
            Resource(
                resource_id=None,
                service_prefix=f"svc{svc_index}",
                resource_type="bucket",
                resource_arn=f"arn:aws:svc{svc_index}:us-east-1:123456789012:bucket/res-{i}",
                resource_name=f"res-{i}",
                region="us-east-1",
                account_id="123456789012",
            )
        )

    inv.bulk_insert_resources(resources)
    return inv


def _build_pipeline_db(tmp_path):
    """Build a database with known services and actions for pipeline tests.

    Includes s3, ec2, lambda, logs, kms, and iam with realistic actions
    so that the pipeline (parser, analyzer, rewriter, self-check) can
    operate end-to-end.

    Returns:
        Database instance.
    """
    db_path = tmp_path / "pipeline_perf.db"
    db = Database(db_path)
    db.create_schema()

    for svc in [
        Service(service_prefix="s3", service_name="Amazon S3"),
        Service(service_prefix="ec2", service_name="Amazon EC2"),
        Service(service_prefix="lambda", service_name="AWS Lambda"),
        Service(service_prefix="logs", service_name="CloudWatch Logs"),
        Service(service_prefix="kms", service_name="AWS KMS"),
        Service(service_prefix="iam", service_name="AWS IAM"),
        Service(service_prefix="sqs", service_name="Amazon SQS"),
        Service(service_prefix="dynamodb", service_name="Amazon DynamoDB"),
    ]:
        db.insert_service(svc)

    s3_actions = [
        ("GetObject", "Read", False, True, False),
        ("PutObject", "Write", False, False, True),
        ("DeleteObject", "Write", False, False, True),
        ("ListBucket", "List", True, False, False),
        ("GetBucketPolicy", "Read", False, True, False),
        ("GetBucketLocation", "Read", False, True, False),
        ("HeadObject", "Read", False, True, False),
    ]
    for name, level, is_list, is_read, is_write in s3_actions:
        db.insert_action(Action(
            action_id=None,
            service_prefix="s3",
            action_name=name,
            full_action=f"s3:{name}",
            description=f"S3 {name}",
            access_level=level,
            is_list=is_list,
            is_read=is_read,
            is_write=is_write,
        ))

    ec2_actions = [
        ("DescribeInstances", "List", True, False, False),
        ("RunInstances", "Write", False, False, True),
        ("TerminateInstances", "Write", False, False, True),
    ]
    for name, level, is_list, is_read, is_write in ec2_actions:
        db.insert_action(Action(
            action_id=None,
            service_prefix="ec2",
            action_name=name,
            full_action=f"ec2:{name}",
            description=f"EC2 {name}",
            access_level=level,
            is_list=is_list,
            is_read=is_read,
            is_write=is_write,
        ))

    for name in ["InvokeFunction", "CreateFunction", "UpdateFunctionCode"]:
        db.insert_action(Action(
            action_id=None,
            service_prefix="lambda",
            action_name=name,
            full_action=f"lambda:{name}",
            description=f"Lambda {name}",
            access_level="Write",
            is_write=True,
        ))

    for name in ["CreateLogGroup", "CreateLogStream", "PutLogEvents"]:
        db.insert_action(Action(
            action_id=None,
            service_prefix="logs",
            action_name=name,
            full_action=f"logs:{name}",
            description=f"Logs {name}",
            access_level="Write",
            is_write=True,
        ))

    for name in ["Decrypt", "Encrypt", "GenerateDataKey"]:
        db.insert_action(Action(
            action_id=None,
            service_prefix="kms",
            action_name=name,
            full_action=f"kms:{name}",
            description=f"KMS {name}",
            access_level="Write",
            is_write=True,
        ))

    iam_actions = [
        ("PassRole", "Permissions management", False, False, False, True),
        ("CreatePolicyVersion", "Permissions management", False, False, False, True),
        ("AttachRolePolicy", "Permissions management", False, False, False, True),
        ("GetUser", "Read", False, True, False, False),
    ]
    for name, level, is_list, is_read, is_write, is_perms in iam_actions:
        db.insert_action(Action(
            action_id=None,
            service_prefix="iam",
            action_name=name,
            full_action=f"iam:{name}",
            description=f"IAM {name}",
            access_level=level,
            is_list=is_list,
            is_read=is_read,
            is_write=is_write,
            is_permissions_management=is_perms,
        ))

    for name in ["SendMessage", "ReceiveMessage", "DeleteMessage",
                  "GetQueueAttributes", "ChangeMessageVisibility"]:
        db.insert_action(Action(
            action_id=None,
            service_prefix="sqs",
            action_name=name,
            full_action=f"sqs:{name}",
            description=f"SQS {name}",
            access_level="Write",
            is_write=True,
        ))

    for name in ["GetItem", "PutItem", "DeleteItem", "Query", "Scan"]:
        db.insert_action(Action(
            action_id=None,
            service_prefix="dynamodb",
            action_name=name,
            full_action=f"dynamodb:{name}",
            description=f"DynamoDB {name}",
            access_level="Write" if name in ("PutItem", "DeleteItem") else "Read",
            is_read=name not in ("PutItem", "DeleteItem"),
            is_write=name in ("PutItem", "DeleteItem"),
        ))

    return db


def _build_pipeline_inventory(tmp_path):
    """Build a resource inventory for pipeline stress tests.

    Returns:
        ResourceInventory instance.
    """
    inv_path = tmp_path / "pipeline_perf_inv.db"
    inv = ResourceInventory(inv_path)
    inv.create_schema()

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
            service_prefix="lambda",
            resource_type="function",
            resource_arn="arn:aws:lambda:us-east-1:123456789012:function:my-func",
            resource_name="my-func",
            region="us-east-1",
            account_id="123456789012",
        ),
        Resource(
            resource_id=None,
            service_prefix="ec2",
            resource_type="instance",
            resource_arn="arn:aws:ec2:us-east-1:123456789012:instance/i-abc123",
            resource_name="web-server",
            region="us-east-1",
            account_id="123456789012",
        ),
    ]
    for r in resources:
        inv.insert_resource(r)

    return inv


# ---------------------------------------------------------------------------
# TestLargePolicies
# ---------------------------------------------------------------------------

class TestLargePolicies:
    """Tests for parsing and validating large IAM policies."""

    def test_policy_with_50_statements(self, tmp_path):
        """Policy with 50 Allow statements parses and validates within time limit."""
        db = _build_pipeline_db(tmp_path)
        parser = PolicyParser(db)

        statements = []
        for i in range(50):
            statements.append({
                "Effect": "Allow",
                "Action": [f"s3:GetObject"],
                "Resource": [f"arn:aws:s3:::bucket-{i}/*"],
            })

        policy_json = json.dumps({
            "Version": "2012-10-17",
            "Statement": statements,
        })

        start = time.time()
        policy = parser.parse_policy(policy_json)
        results = parser.validate_policy(policy)
        elapsed = time.time() - start

        assert elapsed < MAX_ALLOWED_SECONDS, (
            f"Parsing 50-statement policy took {elapsed:.2f}s"
        )
        assert len(policy.statements) == 50
        assert len(results) > 0

    def test_policy_with_100_actions_per_statement(self, tmp_path):
        """Single statement with 100 actions parses correctly."""
        db = _build_pipeline_db(tmp_path)
        parser = PolicyParser(db)

        actions = [f"s3:Action{i}" for i in range(100)]
        policy_json = json.dumps({
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": actions,
                    "Resource": "*",
                }
            ],
        })

        start = time.time()
        policy = parser.parse_policy(policy_json)
        results = parser.validate_policy(policy)
        elapsed = time.time() - start

        assert elapsed < MAX_ALLOWED_SECONDS, (
            f"Parsing 100-action statement took {elapsed:.2f}s"
        )
        assert len(policy.statements) == 1
        assert len(policy.statements[0].actions) == 100
        assert len(results) == 100

    def test_policy_with_mixed_effects(self, tmp_path):
        """Policy with 30 Allow + 20 Deny statements runs through the pipeline."""
        db = _build_pipeline_db(tmp_path)
        pipeline = Pipeline(database=db)

        statements = []
        for i in range(30):
            statements.append({
                "Effect": "Allow",
                "Action": ["s3:GetObject"],
                "Resource": [f"arn:aws:s3:::allow-bucket-{i}/*"],
            })
        for i in range(20):
            statements.append({
                "Effect": "Deny",
                "Action": ["s3:DeleteObject"],
                "Resource": [f"arn:aws:s3:::deny-bucket-{i}/*"],
            })

        policy_json = json.dumps({
            "Version": "2012-10-17",
            "Statement": statements,
        })

        start = time.time()
        result = pipeline.run(policy_json)
        elapsed = time.time() - start

        assert elapsed < MAX_ALLOWED_SECONDS, (
            f"Pipeline with 50 mixed statements took {elapsed:.2f}s"
        )
        assert isinstance(result, PipelineResult)
        assert result.original_policy is not None
        assert result.rewritten_policy is not None


# ---------------------------------------------------------------------------
# TestLargeDatabase
# ---------------------------------------------------------------------------

class TestLargeDatabase:
    """Tests for database operations with large datasets."""

    def test_db_with_500_services(self, tmp_path):
        """Database with 500 services returns all via get_services()."""
        start = time.time()
        db = _build_db_with_services(tmp_path, num_services=500)
        services = db.get_services()
        elapsed = time.time() - start

        assert elapsed < MAX_ALLOWED_SECONDS, (
            f"Inserting and querying 500 services took {elapsed:.2f}s"
        )
        assert len(services) == 500

    def test_db_with_5000_actions(self, tmp_path):
        """Database with 5000 actions across 50 services handles lookups."""
        start = time.time()
        db = _build_db_with_services(
            tmp_path, num_services=50, actions_per_service=100
        )

        # Verify a sample of actions via lookup
        found_count = 0
        for i in range(0, 50, 10):
            for j in range(0, 100, 20):
                action = db.get_action(f"svc{i}", f"Action{j}")
                if action is not None:
                    found_count += 1

        # Verify listing all actions for a service
        svc0_actions = db.get_actions_by_service("svc0")

        elapsed = time.time() - start

        assert elapsed < MAX_ALLOWED_SECONDS, (
            f"Inserting and querying 5000 actions took {elapsed:.2f}s"
        )
        assert found_count == 25  # 5 services * 5 actions sampled
        assert len(svc0_actions) == 100

    def test_parser_init_merge_large_db(self, tmp_path):
        """PolicyParser init with a 500-service DB merges known_services correctly."""
        db = _build_db_with_services(tmp_path, num_services=500)

        start = time.time()
        parser = PolicyParser(db)
        elapsed = time.time() - start

        assert elapsed < MAX_ALLOWED_SECONDS, (
            f"PolicyParser init with 500 services took {elapsed:.2f}s"
        )
        # The parser should have merged all 500 generated service prefixes
        for i in range(500):
            assert f"svc{i}" in parser.known_services


# ---------------------------------------------------------------------------
# TestLargeInventory
# ---------------------------------------------------------------------------

class TestLargeInventory:
    """Tests for inventory operations with large datasets."""

    def test_inventory_with_1000_resources(self, tmp_path):
        """Inventory with 1000 resources supports queries."""
        start = time.time()
        inv = _build_inventory_with_resources(tmp_path, num_resources=1000)

        # Query resources by service
        svc0_resources = inv.get_resources_by_service("svc0")
        # Query statistics
        stats = inv.get_statistics()
        elapsed = time.time() - start

        assert elapsed < MAX_ALLOWED_SECONDS, (
            f"Building and querying 1000-resource inventory took {elapsed:.2f}s"
        )
        assert stats["total_resources"] == 1000
        # Each of 10 services should have 100 resources
        assert len(svc0_resources) == 100

    def test_wildcard_resolution_large_inventory(self, tmp_path):
        """Wildcard resource resolution against 1000 resources completes in time."""
        inv = _build_inventory_with_resources(tmp_path, num_resources=1000)

        start = time.time()
        # Resolve wildcards for each of the 10 services
        total_resolved = 0
        for i in range(10):
            arns = inv.resolve_wildcard_resource(f"svc{i}")
            total_resolved += len(arns)
        elapsed = time.time() - start

        assert elapsed < MAX_ALLOWED_SECONDS, (
            f"Resolving wildcards across 10 services took {elapsed:.2f}s"
        )
        assert total_resolved == 1000


# ---------------------------------------------------------------------------
# TestPipelineStress
# ---------------------------------------------------------------------------

class TestPipelineStress:
    """Stress tests for the full pipeline."""

    def test_full_pipeline_large_policy(self, tmp_path):
        """20-statement policy runs through full pipeline with DB and inventory."""
        db = _build_pipeline_db(tmp_path)
        inv = _build_pipeline_inventory(tmp_path)
        pipeline = Pipeline(database=db, inventory=inv)

        statements = []
        known_actions = [
            "s3:GetObject", "s3:PutObject", "s3:ListBucket",
            "s3:DeleteObject", "s3:GetBucketPolicy",
            "ec2:DescribeInstances", "ec2:RunInstances",
            "ec2:TerminateInstances",
            "lambda:InvokeFunction", "lambda:CreateFunction",
            "kms:Decrypt", "kms:Encrypt",
            "sqs:SendMessage", "sqs:ReceiveMessage",
            "dynamodb:GetItem", "dynamodb:PutItem",
            "dynamodb:Query", "dynamodb:Scan",
            "iam:GetUser", "logs:CreateLogGroup",
        ]
        for i in range(20):
            statements.append({
                "Effect": "Allow",
                "Action": [known_actions[i % len(known_actions)]],
                "Resource": "*",
            })

        policy_json = json.dumps({
            "Version": "2012-10-17",
            "Statement": statements,
        })

        start = time.time()
        result = pipeline.run(policy_json)
        elapsed = time.time() - start

        assert elapsed < MAX_ALLOWED_SECONDS, (
            f"Pipeline with 20-statement policy took {elapsed:.2f}s"
        )
        assert isinstance(result, PipelineResult)
        assert result.iterations >= 1
        assert result.final_verdict is not None
        assert len(result.pipeline_summary) > 0

    def test_pipeline_many_wildcards(self, tmp_path):
        """Policy with 15 wildcard actions runs through the pipeline."""
        db = _build_pipeline_db(tmp_path)
        pipeline = Pipeline(database=db)

        # 15 service-level wildcards
        wildcard_actions = [
            "s3:*", "ec2:*", "lambda:*", "logs:*", "kms:*",
            "iam:*", "sqs:*", "dynamodb:*",
            "s3:Get*", "s3:Put*", "s3:List*",
            "ec2:Describe*", "lambda:Invoke*",
            "kms:Decrypt", "logs:Create*",
        ]
        policy_json = json.dumps({
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": wildcard_actions,
                    "Resource": "*",
                }
            ],
        })

        start = time.time()
        result = pipeline.run(policy_json)
        elapsed = time.time() - start

        assert elapsed < MAX_ALLOWED_SECONDS, (
            f"Pipeline with 15 wildcard actions took {elapsed:.2f}s"
        )
        assert isinstance(result, PipelineResult)
        assert result.iterations >= 1
        # Wildcards should have been expanded or flagged
        assert len(result.validation_results) > 0

    def test_pipeline_all_companions_triggered(self, tmp_path):
        """Policy with actions that trigger multiple companion rules."""
        db = _build_pipeline_db(tmp_path)
        inv = _build_pipeline_inventory(tmp_path)
        pipeline = Pipeline(database=db, inventory=inv)

        # Actions known to trigger companion rules (from constants.py)
        companion_triggering_actions = [
            "lambda:InvokeFunction",
            "lambda:CreateFunction",
            "s3:GetObject",
            "s3:PutObject",
            "sqs:ReceiveMessage",
            "ec2:TerminateInstances",
            "kms:Decrypt",
        ]
        policy_json = json.dumps({
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": companion_triggering_actions,
                    "Resource": "*",
                }
            ],
        })

        config = PipelineConfig(
            add_companions=True,
            add_conditions=True,
            max_self_check_retries=3,
        )

        start = time.time()
        result = pipeline.run(policy_json, config)
        elapsed = time.time() - start

        assert elapsed < MAX_ALLOWED_SECONDS, (
            f"Pipeline with companion-triggering actions took {elapsed:.2f}s"
        )
        assert isinstance(result, PipelineResult)
        assert result.iterations >= 1

        # Verify that companion permissions were considered
        all_rewritten_actions = []
        for stmt in result.rewritten_policy.statements:
            all_rewritten_actions.extend(stmt.actions)

        # At minimum, the original actions (or their expansions) should be present
        assert len(all_rewritten_actions) > 0

        # CloudWatch Logs companions from lambda should be present
        has_logs_companion = any(
            a.startswith("logs:") for a in all_rewritten_actions
        )
        assert has_logs_companion, (
            "Expected CloudWatch Logs companion actions for lambda triggers"
        )

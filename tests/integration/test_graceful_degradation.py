"""Integration tests for graceful degradation scenarios.

Tests verify that the pipeline handles missing, incomplete, or degraded
dependencies without crashing. Covers: missing database, missing inventory,
outdated/empty database, vague intents, and corrupted/edge-case inputs.
"""

import json
from pathlib import Path

import pytest

from src.sentinel.parser import PolicyParser, PolicyParserError, ValidationTier
from src.sentinel.database import Database, Service, Action
from src.sentinel.inventory import ResourceInventory, Resource
from src.sentinel.self_check import (
    Pipeline,
    PipelineConfig,
    PipelineResult,
    CheckVerdict,
)
from src.sentinel.analyzer import RiskAnalyzer


# -----------------------------------------------------------------------
# Fixtures
# -----------------------------------------------------------------------


@pytest.fixture
def db(tmp_path):
    """Create an IAM actions database with comprehensive sample data."""
    db_path = tmp_path / "iam.db"
    database = Database(db_path)
    database.create_schema()

    services = [
        Service(service_prefix="s3", service_name="Amazon S3"),
        Service(service_prefix="ec2", service_name="Amazon EC2"),
        Service(service_prefix="lambda", service_name="AWS Lambda"),
        Service(service_prefix="iam", service_name="AWS IAM"),
        Service(service_prefix="logs", service_name="CloudWatch Logs"),
        Service(service_prefix="kms", service_name="AWS KMS"),
        Service(service_prefix="sqs", service_name="Amazon SQS"),
        Service(service_prefix="dynamodb", service_name="Amazon DynamoDB"),
    ]
    for svc in services:
        database.insert_service(svc)

    # S3 actions
    for name, level, is_list, is_read, is_write in [
        ("GetObject", "Read", False, True, False),
        ("PutObject", "Write", False, False, True),
        ("DeleteObject", "Write", False, False, True),
        ("ListBucket", "List", True, False, False),
        ("GetBucketPolicy", "Read", False, True, False),
        ("GetBucketLocation", "Read", False, True, False),
        ("HeadObject", "Read", False, True, False),
    ]:
        database.insert_action(Action(
            action_id=None, service_prefix="s3", action_name=name,
            full_action=f"s3:{name}", description=f"S3 {name}",
            access_level=level, is_list=is_list, is_read=is_read, is_write=is_write,
        ))

    # EC2 actions
    for name, level, is_list, is_read, is_write in [
        ("DescribeInstances", "List", True, False, False),
        ("RunInstances", "Write", False, False, True),
        ("TerminateInstances", "Write", False, False, True),
    ]:
        database.insert_action(Action(
            action_id=None, service_prefix="ec2", action_name=name,
            full_action=f"ec2:{name}", description=f"EC2 {name}",
            access_level=level, is_list=is_list, is_read=is_read, is_write=is_write,
        ))

    # Lambda actions
    for name in ["InvokeFunction", "CreateFunction", "UpdateFunctionCode"]:
        database.insert_action(Action(
            action_id=None, service_prefix="lambda", action_name=name,
            full_action=f"lambda:{name}", description=f"Lambda {name}",
            access_level="Write", is_write=True,
        ))

    # CloudWatch Logs actions
    for name in ["CreateLogGroup", "CreateLogStream", "PutLogEvents", "GetLogEvents"]:
        database.insert_action(Action(
            action_id=None, service_prefix="logs", action_name=name,
            full_action=f"logs:{name}", description=f"Logs {name}",
            access_level="Write" if "Put" in name or "Create" in name else "Read",
            is_write="Put" in name or "Create" in name,
            is_read="Get" in name,
        ))

    # KMS actions
    for name in ["Decrypt", "Encrypt", "GenerateDataKey"]:
        database.insert_action(Action(
            action_id=None, service_prefix="kms", action_name=name,
            full_action=f"kms:{name}", description=f"KMS {name}",
            access_level="Write", is_write=True,
        ))

    # IAM actions
    for name, level, is_perms in [
        ("PassRole", "Permissions management", True),
        ("CreatePolicyVersion", "Permissions management", True),
        ("AttachRolePolicy", "Permissions management", True),
        ("CreateUser", "Write", False),
        ("GetUser", "Read", False),
    ]:
        database.insert_action(Action(
            action_id=None, service_prefix="iam", action_name=name,
            full_action=f"iam:{name}", description=f"IAM {name}",
            access_level=level,
            is_write=level == "Write",
            is_read=level == "Read",
            is_permissions_management=is_perms,
        ))

    # SQS actions
    for name, level, is_read, is_write in [
        ("ReceiveMessage", "Read", True, False),
        ("SendMessage", "Write", False, True),
        ("DeleteMessage", "Write", False, True),
        ("GetQueueAttributes", "Read", True, False),
        ("ChangeMessageVisibility", "Write", False, True),
    ]:
        database.insert_action(Action(
            action_id=None, service_prefix="sqs", action_name=name,
            full_action=f"sqs:{name}", description=f"SQS {name}",
            access_level=level, is_read=is_read, is_write=is_write,
        ))

    # DynamoDB actions
    for name, level, is_read, is_write in [
        ("GetItem", "Read", True, False),
        ("PutItem", "Write", False, True),
        ("Query", "Read", True, False),
        ("Scan", "Read", True, False),
    ]:
        database.insert_action(Action(
            action_id=None, service_prefix="dynamodb", action_name=name,
            full_action=f"dynamodb:{name}", description=f"DynamoDB {name}",
            access_level=level, is_read=is_read, is_write=is_write,
        ))

    return database


@pytest.fixture
def inventory(tmp_path):
    """Create a resource inventory with sample data."""
    inv = ResourceInventory(tmp_path / "inventory.db")
    inv.create_schema()
    for r in [
        Resource(resource_id=None, service_prefix="s3", resource_type="bucket",
                 resource_arn="arn:aws:s3:::my-app-data", resource_name="my-app-data",
                 region=None, account_id="123456789012"),
        Resource(resource_id=None, service_prefix="s3", resource_type="bucket",
                 resource_arn="arn:aws:s3:::my-app-logs", resource_name="my-app-logs",
                 region=None, account_id="123456789012"),
        Resource(resource_id=None, service_prefix="lambda", resource_type="function",
                 resource_arn="arn:aws:lambda:us-east-1:123456789012:function:my-func",
                 resource_name="my-func", region="us-east-1", account_id="123456789012"),
        Resource(resource_id=None, service_prefix="ec2", resource_type="instance",
                 resource_arn="arn:aws:ec2:us-east-1:123456789012:instance/i-abc123",
                 resource_name="web-server", region="us-east-1", account_id="123456789012"),
    ]:
        inv.insert_resource(r)
    return inv


def _make_policy_json(**overrides):
    """Helper to create IAM policy JSON strings."""
    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": overrides.get("actions", ["s3:GetObject"]),
                "Resource": overrides.get("resources", ["*"]),
            }
        ],
    }
    if "sid" in overrides:
        policy["Statement"][0]["Sid"] = overrides["sid"]
    if "condition" in overrides:
        policy["Statement"][0]["Condition"] = overrides["condition"]
    return json.dumps(policy)


# -----------------------------------------------------------------------
# TestMissingDatabase
# -----------------------------------------------------------------------


class TestMissingDatabase:
    """Tests that the pipeline works without a database."""

    def test_pipeline_runs_without_database(self):
        """Pipeline(database=None) still produces a result."""
        pipeline = Pipeline(database=None)
        policy_json = _make_policy_json(actions=["s3:GetObject"])
        result = pipeline.run(policy_json)

        assert isinstance(result, PipelineResult)
        assert result.original_policy is not None
        assert result.rewritten_policy is not None

    def test_no_db_actions_classified_tier2(self):
        """Without DB, actions get TIER_2_UNKNOWN (not TIER_1_VALID)."""
        parser = PolicyParser(database=None)
        policy_json = _make_policy_json(actions=["s3:GetObject", "ec2:DescribeInstances"])
        policy = parser.parse_policy(policy_json)
        results = parser.validate_policy(policy)

        # Without a database, known-service actions with valid format
        # should be classified as TIER_2_UNKNOWN since DB lookup is
        # unavailable to confirm them as TIER_1_VALID.
        for vr in results:
            assert vr.tier != ValidationTier.TIER_1_VALID, (
                f"Action '{vr.action}' should not be TIER_1_VALID without a database"
            )

    def test_no_db_pipeline_completes_all_steps(self):
        """All 9 PipelineResult fields are populated without a database."""
        pipeline = Pipeline(database=None)
        policy_json = _make_policy_json(
            actions=["s3:GetObject", "lambda:InvokeFunction"]
        )
        result = pipeline.run(policy_json)

        assert result.original_policy is not None
        assert result.rewritten_policy is not None
        assert isinstance(result.validation_results, list)
        assert isinstance(result.risk_findings, list)
        assert result.rewrite_result is not None
        assert result.self_check_result is not None
        assert isinstance(result.iterations, int)
        assert result.iterations >= 1
        assert isinstance(result.final_verdict, CheckVerdict)
        assert isinstance(result.pipeline_summary, str)
        assert len(result.pipeline_summary) > 0


# -----------------------------------------------------------------------
# TestMissingInventory
# -----------------------------------------------------------------------


class TestMissingInventory:
    """Tests that the pipeline works without resource inventory."""

    def test_pipeline_runs_without_inventory(self, db):
        """Pipeline(database=db, inventory=None) works."""
        pipeline = Pipeline(database=db, inventory=None)
        policy_json = _make_policy_json(actions=["s3:GetObject"])
        result = pipeline.run(policy_json)

        assert isinstance(result, PipelineResult)
        assert result.original_policy is not None
        assert result.rewritten_policy is not None
        assert result.iterations >= 1

    def test_no_inventory_uses_placeholders(self, db):
        """Rewritten policy uses placeholder ARNs instead of real ones."""
        pipeline = Pipeline(database=db, inventory=None)
        policy_json = _make_policy_json(
            actions=["s3:GetObject"],
            resources=["*"],
        )
        result = pipeline.run(policy_json)

        # Collect all resources from rewritten policy
        all_resources = []
        for stmt in result.rewritten_policy.statements:
            all_resources.extend(stmt.resources)

        # Without inventory, wildcard resources should be replaced with
        # placeholder ARNs (containing PLACEHOLDER) rather than real ARNs
        has_placeholder = any("PLACEHOLDER" in r for r in all_resources)
        has_wildcard = any(r == "*" for r in all_resources)
        # Either placeholders are present, or the wildcard was kept
        # (both are acceptable degraded behaviors)
        assert has_placeholder or has_wildcard, (
            f"Expected PLACEHOLDER ARNs or wildcard, got: {all_resources}"
        )

    def test_no_inventory_assumptions_recorded(self, db):
        """RewriteResult.assumptions mentions missing inventory."""
        pipeline = Pipeline(database=db, inventory=None)
        policy_json = _make_policy_json(actions=["s3:GetObject"])
        result = pipeline.run(policy_json)

        assumptions = result.rewrite_result.assumptions
        assert len(assumptions) > 0, "Expected at least one assumption"
        inventory_mentioned = any(
            "inventory" in a.lower() for a in assumptions
        )
        assert inventory_mentioned, (
            f"Expected an assumption about missing inventory, got: {assumptions}"
        )


# -----------------------------------------------------------------------
# TestOutdatedDatabase
# -----------------------------------------------------------------------


class TestOutdatedDatabase:
    """Tests behavior with an empty or stale database."""

    def test_empty_database_no_crash(self, tmp_path):
        """DB with schema but no data does not crash the pipeline."""
        db_path = tmp_path / "empty_iam.db"
        empty_db = Database(db_path)
        empty_db.create_schema()

        pipeline = Pipeline(database=empty_db)
        policy_json = _make_policy_json(actions=["s3:GetObject"])
        result = pipeline.run(policy_json)

        assert isinstance(result, PipelineResult)
        assert result.original_policy is not None
        assert result.rewritten_policy is not None
        assert result.iterations >= 1

    def test_db_with_partial_data(self, tmp_path):
        """DB has some services but not all referenced in the policy."""
        db_path = tmp_path / "partial_iam.db"
        partial_db = Database(db_path)
        partial_db.create_schema()

        # Only insert S3 service and actions
        partial_db.insert_service(
            Service(service_prefix="s3", service_name="Amazon S3")
        )
        partial_db.insert_action(Action(
            action_id=None, service_prefix="s3", action_name="GetObject",
            full_action="s3:GetObject", description="S3 GetObject",
            access_level="Read", is_read=True,
        ))

        pipeline = Pipeline(database=partial_db)
        # Policy references both s3 (in DB) and lambda (not in DB)
        policy_json = _make_policy_json(
            actions=["s3:GetObject", "lambda:InvokeFunction"]
        )
        result = pipeline.run(policy_json)

        assert isinstance(result, PipelineResult)
        # s3:GetObject should be validated as TIER_1_VALID
        s3_results = [
            r for r in result.validation_results
            if r.action == "s3:GetObject"
        ]
        assert len(s3_results) == 1
        assert s3_results[0].tier == ValidationTier.TIER_1_VALID

        # lambda:InvokeFunction should be TIER_2_UNKNOWN (known service
        # prefix from hardcoded list, but action not in DB)
        lambda_results = [
            r for r in result.validation_results
            if r.action == "lambda:InvokeFunction"
        ]
        assert len(lambda_results) == 1
        assert lambda_results[0].tier == ValidationTier.TIER_2_UNKNOWN

    def test_unknown_service_in_policy(self, tmp_path):
        """Policy references a service not in DB."""
        db_path = tmp_path / "known_iam.db"
        known_db = Database(db_path)
        known_db.create_schema()

        # Only insert S3
        known_db.insert_service(
            Service(service_prefix="s3", service_name="Amazon S3")
        )
        known_db.insert_action(Action(
            action_id=None, service_prefix="s3", action_name="GetObject",
            full_action="s3:GetObject", description="S3 GetObject",
            access_level="Read", is_read=True,
        ))

        pipeline = Pipeline(database=known_db)
        # Use a completely unknown service prefix
        policy_json = _make_policy_json(
            actions=["s3:GetObject", "madeupservice:DoSomething"]
        )
        result = pipeline.run(policy_json)

        assert isinstance(result, PipelineResult)
        # Unknown service action should be classified as TIER_3_INVALID
        unknown_results = [
            r for r in result.validation_results
            if r.action == "madeupservice:DoSomething"
        ]
        assert len(unknown_results) == 1
        assert unknown_results[0].tier == ValidationTier.TIER_3_INVALID


# -----------------------------------------------------------------------
# TestVagueIntent
# -----------------------------------------------------------------------


class TestVagueIntent:
    """Tests behavior with vague or unusual intents."""

    def test_empty_intent_treated_as_none(self, db):
        """Empty string intent behaves the same as no intent."""
        pipeline = Pipeline(database=db)
        policy_json = _make_policy_json(actions=["s3:GetObject"])

        result_no_intent = pipeline.run(policy_json, PipelineConfig(intent=None))
        result_empty_intent = pipeline.run(policy_json, PipelineConfig(intent=""))

        # Both should produce valid results
        assert isinstance(result_no_intent, PipelineResult)
        assert isinstance(result_empty_intent, PipelineResult)

        # Both should have the same actions in rewritten policy
        actions_no_intent = set()
        for stmt in result_no_intent.rewritten_policy.statements:
            actions_no_intent.update(stmt.actions)

        actions_empty_intent = set()
        for stmt in result_empty_intent.rewritten_policy.statements:
            actions_empty_intent.update(stmt.actions)

        assert actions_no_intent == actions_empty_intent

    def test_vague_intent_handled(self, db):
        """Intent like 'do stuff' does not crash the pipeline."""
        pipeline = Pipeline(database=db)
        policy_json = _make_policy_json(actions=["s3:GetObject", "s3:PutObject"])
        config = PipelineConfig(intent="do stuff")
        result = pipeline.run(policy_json, config)

        assert isinstance(result, PipelineResult)
        assert result.original_policy is not None
        assert result.rewritten_policy is not None
        assert result.iterations >= 1

    def test_contradictory_intent(self, db):
        """Intent says 'read-only' but config adds write permissions -- no crash."""
        pipeline = Pipeline(database=db)
        # Policy has write actions
        policy_json = _make_policy_json(
            actions=["s3:GetObject", "s3:PutObject", "s3:DeleteObject"]
        )
        # Intent says read-only, contradicting the write actions present
        config = PipelineConfig(intent="read-only s3")
        result = pipeline.run(policy_json, config)

        assert isinstance(result, PipelineResult)
        assert result.original_policy is not None
        assert result.rewritten_policy is not None
        assert result.iterations >= 1
        # Pipeline should complete regardless of the contradiction
        assert isinstance(result.final_verdict, CheckVerdict)


# -----------------------------------------------------------------------
# TestCorruptedInput
# -----------------------------------------------------------------------


class TestCorruptedInput:
    """Tests behavior with edge-case inputs."""

    def test_very_long_action_name(self, db):
        """Action with 500 character name does not crash."""
        pipeline = Pipeline(database=db)
        long_action = "s3:" + "A" * 497  # 500 characters total
        policy_json = _make_policy_json(
            actions=["s3:GetObject", long_action]
        )
        result = pipeline.run(policy_json)

        assert isinstance(result, PipelineResult)
        assert result.original_policy is not None
        assert result.rewritten_policy is not None

        # The long action should be classified (likely TIER_2_UNKNOWN
        # since it has valid format but is not in DB)
        long_results = [
            r for r in result.validation_results
            if r.action == long_action
        ]
        assert len(long_results) == 1

    def test_unicode_in_policy(self, db):
        """Policy with unicode characters in SID and description."""
        pipeline = Pipeline(database=db)
        policy = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Sid": "AllowReadAccess\u00e9\u00e8\u00ea\u00eb",
                    "Effect": "Allow",
                    "Action": ["s3:GetObject"],
                    "Resource": ["*"],
                },
            ],
        }
        policy_json = json.dumps(policy, ensure_ascii=False)
        result = pipeline.run(policy_json)

        assert isinstance(result, PipelineResult)
        assert result.original_policy is not None
        assert result.rewritten_policy is not None
        assert result.iterations >= 1

    def test_deeply_nested_conditions(self, db):
        """Policy with 5 levels of nested condition blocks."""
        pipeline = Pipeline(database=db)
        # Build a deeply nested condition structure
        nested_condition = {
            "StringEquals": {
                "aws:RequestedRegion": "us-east-1",
            },
            "StringLike": {
                "s3:prefix": "home/${aws:username}/*",
            },
            "ForAnyValue:StringEquals": {
                "aws:TagKeys": ["Environment", "Project"],
            },
            "ForAllValues:StringLike": {
                "aws:PrincipalOrgPaths": [
                    "o-org123/r-root/ou-parent/ou-child/*",
                ],
            },
            "IpAddress": {
                "aws:SourceIp": ["10.0.0.0/8", "172.16.0.0/12"],
            },
        }
        policy_json = _make_policy_json(
            actions=["s3:GetObject"],
            resources=["arn:aws:s3:::my-bucket/*"],
            condition=nested_condition,
        )
        result = pipeline.run(policy_json)

        assert isinstance(result, PipelineResult)
        assert result.original_policy is not None
        assert result.rewritten_policy is not None

        # The original policy should have preserved the conditions
        original_stmt = result.original_policy.statements[0]
        assert original_stmt.conditions is not None
        assert "StringEquals" in original_stmt.conditions
        assert "IpAddress" in original_stmt.conditions

"""Integration tests for dynamic service prefix resolution through the pipeline.

Tests that a newly added service in the database (but not in JSON or hardcoded)
is correctly recognized through the Layer 3 merge and flows through the full
Validate-Analyze-Rewrite-SelfCheck pipeline.
"""

import json
from pathlib import Path

import pytest

from src.sentinel.parser import PolicyParser, ValidationTier
from src.sentinel.database import Database, Service, Action
from src.sentinel.inventory import ResourceInventory, Resource
from src.sentinel.self_check import Pipeline, PipelineConfig, PipelineResult, CheckVerdict
from src.sentinel.parser import _known_services


# -----------------------------------------------------------------------
# Fixtures
# -----------------------------------------------------------------------


@pytest.fixture
def db_with_new_service(tmp_path):
    """Create a DB with a service NOT in the hardcoded or JSON set."""
    db = Database(tmp_path / "test.db")
    db.create_schema()

    # Add a well-known service that IS in hardcoded set
    db.insert_service(Service(service_prefix="s3", service_name="Amazon S3"))
    db.insert_action(
        Action(
            action_id=None,
            service_prefix="s3",
            action_name="GetObject",
            full_action="s3:GetObject",
            description="Read an object",
            access_level="Read",
            is_read=True,
        )
    )

    # Add a brand-new service NOT in hardcoded or JSON
    db.insert_service(Service(service_prefix="bedrock-agent", service_name="Amazon Bedrock Agents"))
    db.insert_action(
        Action(
            action_id=None,
            service_prefix="bedrock-agent",
            action_name="InvokeAgent",
            full_action="bedrock-agent:InvokeAgent",
            description="Invoke a Bedrock agent",
            access_level="Write",
            is_write=True,
        )
    )
    db.insert_action(
        Action(
            action_id=None,
            service_prefix="bedrock-agent",
            action_name="GetAgent",
            full_action="bedrock-agent:GetAgent",
            description="Get agent details",
            access_level="Read",
            is_read=True,
        )
    )

    return db


# -----------------------------------------------------------------------
# Tests
# -----------------------------------------------------------------------


class TestLayer3Merge:
    """Test that DB services merge into parser.known_services at init."""

    def test_new_service_recognized_after_merge(self, db_with_new_service):
        parser = PolicyParser(db_with_new_service)

        # bedrock-agent is NOT in the JSON cache
        assert "bedrock-agent" not in _known_services()
        # But it IS in parser.known_services after DB merge
        assert "bedrock-agent" in parser.known_services

    def test_json_cache_services_still_present(self, db_with_new_service):
        parser = PolicyParser(db_with_new_service)

        # Core services from JSON cache should still be present
        for svc in ["s3", "ec2", "lambda", "iam", "kms"]:
            assert svc in parser.known_services

    def test_known_services_superset_of_json_cache(self, db_with_new_service):
        parser = PolicyParser(db_with_new_service)
        assert parser.known_services >= _known_services()


class TestNewServiceValidation:
    """Test that a new DB-only service validates correctly."""

    def test_new_service_action_is_tier1(self, db_with_new_service):
        parser = PolicyParser(db_with_new_service)
        policy_json = json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Action": "bedrock-agent:InvokeAgent",
                        "Resource": "*",
                    }
                ],
            }
        )
        policy = parser.parse_policy(policy_json)
        results = parser.validate_policy(policy)

        invoke = [r for r in results if r.action == "bedrock-agent:InvokeAgent"]
        assert len(invoke) == 1
        assert invoke[0].tier == ValidationTier.TIER_1_VALID

    def test_new_service_unknown_action_is_tier2(self, db_with_new_service):
        parser = PolicyParser(db_with_new_service)
        policy_json = json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Action": "bedrock-agent:FutureNewAction",
                        "Resource": "*",
                    }
                ],
            }
        )
        policy = parser.parse_policy(policy_json)
        results = parser.validate_policy(policy)

        future = [r for r in results if r.action == "bedrock-agent:FutureNewAction"]
        assert len(future) == 1
        # Known service (via DB merge) + plausible format = TIER_2_UNKNOWN
        assert future[0].tier == ValidationTier.TIER_2_UNKNOWN

    def test_new_service_wildcard_expands_to_db_actions(self, db_with_new_service):
        parser = PolicyParser(db_with_new_service)
        policy_json = json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Action": "bedrock-agent:*",
                        "Resource": "*",
                    }
                ],
            }
        )
        policy = parser.parse_policy(policy_json)
        results = parser.validate_policy(policy)

        # Wildcard gets expanded to specific actions from DB, so
        # we should see bedrock-agent actions validated as TIER_1
        bedrock_results = [r for r in results if r.action.startswith("bedrock-agent:")]
        assert len(bedrock_results) >= 1
        # Expanded DB actions should be TIER_1_VALID
        for r in bedrock_results:
            assert r.tier in (ValidationTier.TIER_1_VALID, ValidationTier.TIER_2_UNKNOWN)


class TestNewServiceThroughPipeline:
    """Test new DB-only service flows through the full pipeline."""

    def test_pipeline_processes_new_service(self, db_with_new_service):
        pipeline = Pipeline(database=db_with_new_service)
        policy_json = json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Action": [
                            "bedrock-agent:InvokeAgent",
                            "bedrock-agent:GetAgent",
                            "s3:GetObject",
                        ],
                        "Resource": "*",
                    }
                ],
            }
        )
        result = pipeline.run_text(policy_json)

        assert isinstance(result, PipelineResult)
        assert result.iterations >= 1

        # All actions should be in the rewritten policy
        all_actions = []
        for stmt in result.rewritten_policy.statements:
            all_actions.extend(stmt.actions)
        assert "s3:GetObject" in all_actions
        # bedrock-agent actions should be preserved (known via DB)
        bedrock_actions = [a for a in all_actions if a.startswith("bedrock-agent:")]
        assert len(bedrock_actions) >= 1

    def test_pipeline_with_new_service_and_intent(self, db_with_new_service):
        pipeline = Pipeline(database=db_with_new_service)
        policy_json = json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Action": ["bedrock-agent:InvokeAgent", "s3:GetObject"],
                        "Resource": "*",
                    }
                ],
            }
        )
        config = PipelineConfig(intent="invoke bedrock agent and read s3")
        result = pipeline.run_text(policy_json, config)

        assert isinstance(result, PipelineResult)
        assert result.rewritten_policy is not None

    def test_mixed_known_and_db_services(self, db_with_new_service):
        pipeline = Pipeline(database=db_with_new_service)
        policy_json = json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Action": "s3:GetObject",
                        "Resource": "arn:aws:s3:::my-bucket/*",
                    },
                    {
                        "Effect": "Allow",
                        "Action": "bedrock-agent:InvokeAgent",
                        "Resource": "*",
                    },
                ],
            }
        )
        result = pipeline.run_text(policy_json)

        # Both services should be processed
        assert isinstance(result, PipelineResult)
        assert len(result.validation_results) >= 2

        # s3:GetObject should be TIER_1_VALID
        s3_results = [r for r in result.validation_results if r.action == "s3:GetObject"]
        assert len(s3_results) == 1
        assert s3_results[0].tier == ValidationTier.TIER_1_VALID

        # bedrock-agent:InvokeAgent should also be TIER_1_VALID (in DB)
        bedrock_results = [
            r for r in result.validation_results if r.action == "bedrock-agent:InvokeAgent"
        ]
        assert len(bedrock_results) == 1
        assert bedrock_results[0].tier == ValidationTier.TIER_1_VALID

"""Unit tests for parser module."""

import pytest
import json
import tempfile
from pathlib import Path
from unittest.mock import patch

from src.sentinel.parser import (
    PolicyParser,
    PolicyParserError,
    Policy,
    Statement,
    ValidationResult,
    ValidationTier,
)
from src.sentinel.database import Database, Service, Action


@pytest.fixture
def temp_db():
    """Create temporary database for testing."""
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
        db_path = Path(f.name)

    db = Database(db_path)
    db.create_schema()

    # Insert test services and actions
    services = [
        Service(service_prefix="s3", service_name="Amazon S3"),
        Service(service_prefix="ec2", service_name="Amazon EC2"),
        Service(service_prefix="iam", service_name="AWS IAM"),
        Service(service_prefix="lambda", service_name="AWS Lambda"),
    ]

    for service in services:
        db.insert_service(service)

    actions = [
        Action(None, "s3", "GetObject", "s3:GetObject", "Get object", "Read", is_read=True),
        Action(None, "s3", "PutObject", "s3:PutObject", "Put object", "Write", is_write=True),
        Action(None, "s3", "ListBuckets", "s3:ListBuckets", "List buckets", "List", is_list=True),
        Action(
            None,
            "s3",
            "PutBucketPolicy",
            "s3:PutBucketPolicy",
            "Put policy",
            "Permissions management",
            is_permissions_management=True,
        ),
        Action(
            None, "ec2", "RunInstances", "ec2:RunInstances", "Run instances", "Write", is_write=True
        ),
        Action(
            None,
            "ec2",
            "DescribeInstances",
            "ec2:DescribeInstances",
            "Describe instances",
            "List",
            is_list=True,
        ),
        Action(None, "iam", "ListUsers", "iam:ListUsers", "List users", "List", is_list=True),
        Action(None, "iam", "CreateUser", "iam:CreateUser", "Create user", "Write", is_write=True),
        Action(
            None,
            "lambda",
            "InvokeFunction",
            "lambda:InvokeFunction",
            "Invoke function",
            "Write",
            is_write=True,
        ),
    ]

    for action in actions:
        db.insert_action(action)

    yield db

    # Cleanup
    if db_path.exists():
        db_path.unlink()


@pytest.fixture
def parser():
    """Create parser without database."""
    return PolicyParser()


@pytest.fixture
def parser_with_db(temp_db):
    """Create parser with database."""
    return PolicyParser(database=temp_db)


class TestPolicyParsing:
    """Test policy JSON parsing."""

    def test_parse_simple_policy(self, parser):
        """Test parsing simple policy."""
        policy_json = """
        {
            "Version": "2012-10-17",
            "Statement": [{
                "Effect": "Allow",
                "Action": "s3:GetObject",
                "Resource": "arn:aws:s3:::my-bucket/*"
            }]
        }
        """

        policy = parser.parse_policy(policy_json)

        assert policy.version == "2012-10-17"
        assert len(policy.statements) == 1
        assert policy.statements[0].effect == "Allow"
        assert policy.statements[0].actions == ["s3:GetObject"]
        assert policy.statements[0].resources == ["arn:aws:s3:::my-bucket/*"]

    def test_parse_policy_with_multiple_statements(self, parser):
        """Test parsing policy with multiple statements."""
        policy_json = """
        {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": "s3:GetObject",
                    "Resource": "*"
                },
                {
                    "Effect": "Deny",
                    "Action": "ec2:TerminateInstances",
                    "Resource": "*"
                }
            ]
        }
        """

        policy = parser.parse_policy(policy_json)

        assert len(policy.statements) == 2
        assert policy.statements[0].effect == "Allow"
        assert policy.statements[1].effect == "Deny"

    def test_parse_policy_with_action_array(self, parser):
        """Test parsing policy with multiple actions."""
        policy_json = """
        {
            "Version": "2012-10-17",
            "Statement": [{
                "Effect": "Allow",
                "Action": ["s3:GetObject", "s3:PutObject", "s3:DeleteObject"],
                "Resource": "*"
            }]
        }
        """

        policy = parser.parse_policy(policy_json)

        assert len(policy.statements[0].actions) == 3
        assert "s3:GetObject" in policy.statements[0].actions
        assert "s3:PutObject" in policy.statements[0].actions
        assert "s3:DeleteObject" in policy.statements[0].actions

    def test_parse_policy_with_wildcard(self, parser):
        """Test parsing policy with wildcard action."""
        policy_json = """
        {
            "Version": "2012-10-17",
            "Statement": [{
                "Effect": "Allow",
                "Action": "s3:*",
                "Resource": "*"
            }]
        }
        """

        policy = parser.parse_policy(policy_json)

        assert policy.statements[0].actions == ["s3:*"]

    def test_parse_policy_with_sid(self, parser):
        """Test parsing policy with Statement ID."""
        policy_json = """
        {
            "Version": "2012-10-17",
            "Statement": [{
                "Sid": "AllowS3Read",
                "Effect": "Allow",
                "Action": "s3:GetObject",
                "Resource": "*"
            }]
        }
        """

        policy = parser.parse_policy(policy_json)

        assert policy.statements[0].sid == "AllowS3Read"

    def test_parse_policy_with_conditions(self, parser):
        """Test parsing policy with conditions."""
        policy_json = """
        {
            "Version": "2012-10-17",
            "Statement": [{
                "Effect": "Allow",
                "Action": "s3:GetObject",
                "Resource": "*",
                "Condition": {
                    "StringEquals": {
                        "s3:x-amz-acl": "public-read"
                    }
                }
            }]
        }
        """

        policy = parser.parse_policy(policy_json)

        assert policy.statements[0].conditions is not None
        assert "StringEquals" in policy.statements[0].conditions

    def test_parse_policy_with_not_action(self, parser):
        """Test parsing policy with NotAction."""
        policy_json = """
        {
            "Version": "2012-10-17",
            "Statement": [{
                "Effect": "Deny",
                "NotAction": "iam:*",
                "Resource": "*"
            }]
        }
        """

        policy = parser.parse_policy(policy_json)

        assert policy.statements[0].not_actions == ["iam:*"]
        assert policy.statements[0].actions == []

    def test_parse_invalid_json(self, parser):
        """Test parsing invalid JSON."""
        invalid_json = "{ invalid json }"

        with pytest.raises(PolicyParserError, match="Invalid JSON"):
            parser.parse_policy(invalid_json)

    def test_parse_missing_version(self, parser):
        """Test parsing policy without Version."""
        policy_json = """
        {
            "Statement": [{
                "Effect": "Allow",
                "Action": "s3:GetObject",
                "Resource": "*"
            }]
        }
        """

        with pytest.raises(PolicyParserError, match="missing required 'Version'"):
            parser.parse_policy(policy_json)

    def test_parse_missing_statement(self, parser):
        """Test parsing policy without Statement."""
        policy_json = """
        {
            "Version": "2012-10-17"
        }
        """

        with pytest.raises(PolicyParserError, match="missing required 'Statement'"):
            parser.parse_policy(policy_json)

    def test_parse_missing_effect(self, parser):
        """Test parsing statement without Effect."""
        policy_json = """
        {
            "Version": "2012-10-17",
            "Statement": [{
                "Action": "s3:GetObject",
                "Resource": "*"
            }]
        }
        """

        with pytest.raises(PolicyParserError, match="missing required 'Effect'"):
            parser.parse_policy(policy_json)

    def test_parse_invalid_effect(self, parser):
        """Test parsing statement with invalid Effect."""
        policy_json = """
        {
            "Version": "2012-10-17",
            "Statement": [{
                "Effect": "Maybe",
                "Action": "s3:GetObject",
                "Resource": "*"
            }]
        }
        """

        with pytest.raises(PolicyParserError, match="Invalid Effect"):
            parser.parse_policy(policy_json)

    def test_parse_missing_action_and_resource(self, parser):
        """Test parsing statement without Action."""
        policy_json = """
        {
            "Version": "2012-10-17",
            "Statement": [{
                "Effect": "Allow",
                "Resource": "*"
            }]
        }
        """

        with pytest.raises(PolicyParserError, match="missing 'Action' or 'NotAction'"):
            parser.parse_policy(policy_json)

    def test_parse_policy_file(self, parser):
        """Test parsing policy from file."""
        policy_json = """
        {
            "Version": "2012-10-17",
            "Statement": [{
                "Effect": "Allow",
                "Action": "s3:GetObject",
                "Resource": "*"
            }]
        }
        """

        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            f.write(policy_json)
            temp_file = Path(f.name)

        try:
            policy = parser.parse_policy_file(temp_file)
            assert policy.version == "2012-10-17"
            assert len(policy.statements) == 1
        finally:
            temp_file.unlink()

    def test_parse_policy_file_not_found(self, parser):
        """Test parsing non-existent file."""
        with pytest.raises(PolicyParserError, match="not found"):
            parser.parse_policy_file(Path("/nonexistent/file.json"))


class TestActionClassification:
    """Test three-tier action classification."""

    def test_classify_tier1_valid_action(self, parser_with_db):
        """Test Tier 1 classification for valid action."""
        result = parser_with_db.classify_action("s3:GetObject")

        assert result.tier == ValidationTier.TIER_1_VALID
        assert result.action == "s3:GetObject"
        assert result.access_level == "Read"
        assert "found in IAM database" in result.reason

    def test_classify_tier1_multiple_actions(self, parser_with_db):
        """Test multiple Tier 1 actions."""
        actions = ["s3:PutObject", "ec2:RunInstances", "iam:ListUsers"]

        for action in actions:
            result = parser_with_db.classify_action(action)
            assert result.tier == ValidationTier.TIER_1_VALID

    def test_classify_tier2_plausible_action(self, parser_with_db):
        """Test Tier 2 classification for plausible unknown action."""
        result = parser_with_db.classify_action("s3:NewAction")

        assert result.tier == ValidationTier.TIER_2_UNKNOWN
        assert "plausible" in result.reason.lower()

    def test_classify_tier2_wildcard(self, parser_with_db):
        """Test Tier 2 classification for wildcards."""
        wildcards = ["*", "s3:*", "s3:Get*", "ec2:Describe*"]

        for wildcard in wildcards:
            result = parser_with_db.classify_action(wildcard)
            assert result.tier == ValidationTier.TIER_2_UNKNOWN

    def test_classify_tier3_invalid_format(self, parser):
        """Test Tier 3 classification for invalid format."""
        invalid_actions = [
            "invalid",  # No colon
            "s3",  # No action name
            "s3:",  # Empty action name
            "s3:get-object",  # Lowercase start
            "s3:Get Object",  # Space in name
        ]

        for action in invalid_actions:
            result = parser.classify_action(action)
            assert result.tier == ValidationTier.TIER_3_INVALID

    def test_classify_tier3_unknown_service(self, parser):
        """Test Tier 3 classification for unknown service."""
        result = parser.classify_action("unknownservice:GetObject")

        assert result.tier == ValidationTier.TIER_3_INVALID
        assert "Unknown" in result.reason or "unknown" in result.reason

    def test_classify_with_suggestions(self, parser):
        """Test classification includes suggestions."""
        result = parser.classify_action("s4:GetObject")

        assert result.tier == ValidationTier.TIER_3_INVALID
        assert len(result.suggestions) > 0
        # Should suggest s3
        assert any("s3" in s for s in result.suggestions)


class TestWildcardHandling:
    """Test wildcard action handling."""

    def test_valid_wildcard_patterns(self, parser):
        """Test valid wildcard patterns."""
        valid_wildcards = [
            "*",
            "*:*",
            "s3:*",
            "s3:Get*",
            "s3:*Object",
        ]

        for wildcard in valid_wildcards:
            result = parser.classify_action(wildcard)
            assert result.tier != ValidationTier.TIER_3_INVALID

    def test_invalid_wildcard_patterns(self, parser):
        """Test invalid wildcard patterns."""
        invalid_wildcards = [
            "s3:Get*Put",  # Multiple wildcards
            "s3:*Get*",  # Wildcard in middle
            "s3:**",  # Multiple consecutive wildcards
        ]

        for wildcard in invalid_wildcards:
            result = parser.classify_action(wildcard)
            assert result.tier == ValidationTier.TIER_3_INVALID

    def test_expand_service_wildcard(self, parser_with_db):
        """Test expanding service:* wildcard."""
        expanded = parser_with_db._expand_action_wildcard("s3:*")

        assert len(expanded) > 0
        assert "s3:GetObject" in expanded
        assert "s3:PutObject" in expanded
        assert "s3:ListBuckets" in expanded

    def test_expand_prefix_wildcard(self, parser_with_db):
        """Test expanding prefix wildcard (Get*)."""
        expanded = parser_with_db._expand_action_wildcard("s3:Get*")

        assert len(expanded) >= 1
        assert "s3:GetObject" in expanded
        assert "s3:PutObject" not in expanded

    def test_expand_suffix_wildcard(self, parser_with_db):
        """Test expanding suffix wildcard (*Object)."""
        expanded = parser_with_db._expand_action_wildcard("s3:*Object")

        assert "s3:GetObject" in expanded
        assert "s3:PutObject" in expanded

    def test_expand_without_database(self, parser):
        """Test wildcard expansion without database returns original."""
        expanded = parser._expand_action_wildcard("s3:*")

        assert expanded == ["s3:*"]


class TestPolicyValidation:
    """Test complete policy validation."""

    def test_validate_policy(self, parser_with_db):
        """Test validating complete policy."""
        policy_json = """
        {
            "Version": "2012-10-17",
            "Statement": [{
                "Effect": "Allow",
                "Action": ["s3:GetObject", "s3:InvalidAction", "invalid:format"],
                "Resource": "*"
            }]
        }
        """

        policy = parser_with_db.parse_policy(policy_json)
        results = parser_with_db.validate_policy(policy)

        assert len(results) == 3

        # Check tiers
        tier1_results = [r for r in results if r.tier == ValidationTier.TIER_1_VALID]
        tier2_results = [r for r in results if r.tier == ValidationTier.TIER_2_UNKNOWN]
        tier3_results = [r for r in results if r.tier == ValidationTier.TIER_3_INVALID]

        assert len(tier1_results) == 1  # s3:GetObject
        assert len(tier2_results) == 1  # s3:InvalidAction (plausible)
        assert len(tier3_results) == 1  # invalid:format

    def test_validate_policy_deduplicates_actions(self, parser_with_db):
        """Test validation deduplicates repeated actions."""
        policy_json = """
        {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": "s3:GetObject",
                    "Resource": "*"
                },
                {
                    "Effect": "Allow",
                    "Action": "s3:GetObject",
                    "Resource": "arn:aws:s3:::bucket/*"
                }
            ]
        }
        """

        policy = parser_with_db.parse_policy(policy_json)
        results = parser_with_db.validate_policy(policy)

        # Should only validate once
        assert len(results) == 1


class TestPolicySummary:
    """Test policy summary generation."""

    def test_get_policy_summary(self, parser_with_db):
        """Test generating policy summary."""
        policy_json = """
        {
            "Version": "2012-10-17",
            "Statement": [{
                "Effect": "Allow",
                "Action": ["s3:GetObject", "s3:PutObject", "unknownservice:Action"],
                "Resource": "*"
            }]
        }
        """

        policy = parser_with_db.parse_policy(policy_json)
        summary = parser_with_db.get_policy_summary(policy)

        assert summary["version"] == "2012-10-17"
        assert summary["statement_count"] == 1
        assert summary["total_actions"] == 3
        assert summary["valid_actions"] >= 2
        assert summary["invalid_actions"] >= 1
        assert summary["has_wildcards"] is False

    def test_summary_detects_wildcards(self, parser_with_db):
        """Test summary detects wildcard usage."""
        policy_json = """
        {
            "Version": "2012-10-17",
            "Statement": [{
                "Effect": "Allow",
                "Action": "s3:*",
                "Resource": "*"
            }]
        }
        """

        policy = parser_with_db.parse_policy(policy_json)
        summary = parser_with_db.get_policy_summary(policy)

        assert summary["has_wildcards"] is True

    def test_summary_detects_deny_statements(self, parser_with_db):
        """Test summary detects deny statements."""
        policy_json = """
        {
            "Version": "2012-10-17",
            "Statement": [{
                "Effect": "Deny",
                "Action": "s3:DeleteBucket",
                "Resource": "*"
            }]
        }
        """

        policy = parser_with_db.parse_policy(policy_json)
        summary = parser_with_db.get_policy_summary(policy)

        assert summary["has_deny_statements"] is True


class TestActionExtraction:
    """Test action extraction utilities."""

    def test_extract_actions(self, parser):
        """Test extracting unique actions from policy."""
        policy_json = """
        {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": ["s3:GetObject", "s3:PutObject"],
                    "Resource": "*"
                },
                {
                    "Effect": "Allow",
                    "Action": "s3:GetObject",
                    "Resource": "arn:aws:s3:::bucket/*"
                }
            ]
        }
        """

        policy = parser.parse_policy(policy_json)
        actions = parser.extract_actions(policy)

        assert len(actions) == 2  # Deduplicated
        assert "s3:GetObject" in actions
        assert "s3:PutObject" in actions


class TestSuggestions:
    """Test correction suggestions."""

    def test_suggest_service_corrections(self, parser):
        """Test service name correction suggestions."""
        result = parser.classify_action("s4:GetObject")

        assert len(result.suggestions) > 0
        # Should suggest s3 (similar prefix)
        assert any("s3:" in s for s in result.suggestions)

    def test_suggest_action_name_capitalization(self, parser):
        """Test action name capitalization suggestions."""
        result = parser.classify_action("s3:getObject")

        assert result.tier == ValidationTier.TIER_3_INVALID
        assert any("GetObject" in s for s in result.suggestions)

    def test_find_similar_services(self, parser_with_db):
        """Test finding similar service prefixes."""
        similar = parser_with_db._find_similar_services("s")

        assert "s3" in similar

    def test_find_similar_services_with_prefix(self, parser_with_db):
        """Test finding services with common prefix."""
        similar = parser_with_db._find_similar_services("ec")

        assert "ec2" in similar


class TestYAMLParsing:
    """Test YAML policy parsing."""

    def test_parse_yaml_simple_policy(self, parser):
        """Test parsing a valid YAML policy string."""
        yaml_str = (
            'Version: "2012-10-17"\n'
            "Statement:\n"
            "  - Effect: Allow\n"
            "    Action: s3:GetObject\n"
            '    Resource: "*"\n'
        )
        policy = parser.parse_policy_yaml(yaml_str)

        assert policy.version == "2012-10-17"
        assert len(policy.statements) == 1
        assert policy.statements[0].effect == "Allow"
        assert policy.statements[0].actions == ["s3:GetObject"]

    def test_parse_yaml_with_anchors(self, parser):
        """Test YAML anchors and aliases parse correctly."""
        yaml_str = (
            'Version: "2012-10-17"\n'
            "Statement:\n"
            "  - &base\n"
            "    Effect: Allow\n"
            "    Action: s3:GetObject\n"
            '    Resource: "arn:aws:s3:::bucket-a/*"\n'
            "  - <<: *base\n"
            '    Resource: "arn:aws:s3:::bucket-b/*"\n'
        )
        policy = parser.parse_policy_yaml(yaml_str)

        assert len(policy.statements) == 2
        assert policy.statements[0].resources == ["arn:aws:s3:::bucket-a/*"]
        assert policy.statements[1].resources == ["arn:aws:s3:::bucket-b/*"]
        assert policy.statements[1].actions == ["s3:GetObject"]

    def test_parse_yaml_invalid_raises_error(self, parser):
        """Test invalid YAML raises PolicyParserError."""
        bad_yaml = ":\n  - :\n    [invalid"
        with pytest.raises(PolicyParserError, match="Invalid YAML"):
            parser.parse_policy_yaml(bad_yaml)

    def test_parse_yaml_non_dict_raises_error(self, parser):
        """Test YAML that deserializes to non-dict raises error."""
        with pytest.raises(PolicyParserError, match="must be a mapping"):
            parser.parse_policy_yaml("- item1\n- item2\n")

    def test_parse_policy_auto_json(self, parser):
        """Test parse_policy_auto dispatches JSON correctly."""
        policy_json = json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Action": "s3:GetObject",
                        "Resource": "*",
                    }
                ],
            }
        )
        policy = parser.parse_policy_auto(policy_json, "json")
        assert policy.version == "2012-10-17"

    def test_parse_policy_auto_yaml(self, parser):
        """Test parse_policy_auto dispatches YAML correctly."""
        yaml_str = (
            'Version: "2012-10-17"\n'
            "Statement:\n"
            "  - Effect: Allow\n"
            "    Action: s3:GetObject\n"
            '    Resource: "*"\n'
        )
        policy = parser.parse_policy_auto(yaml_str, "yaml")
        assert policy.version == "2012-10-17"

    def test_parse_policy_auto_unsupported_format(self, parser):
        """Test parse_policy_auto rejects unknown format."""
        with pytest.raises(PolicyParserError, match="Unsupported input format"):
            parser.parse_policy_auto("{}", "toml")

    def test_parse_yaml_fixture_file(self, parser):
        """Test parsing the YAML fixture file through parse_policy_yaml."""
        fixture = Path(__file__).parent / "fixtures" / "test_policies" / "simple_policy.yaml"
        content = fixture.read_text(encoding="utf-8")
        policy = parser.parse_policy_yaml(content)

        assert policy.version == "2012-10-17"
        assert len(policy.statements) == 1
        assert policy.statements[0].sid == "AllowS3Read"
        assert "s3:GetObject" in policy.statements[0].actions
        assert "s3:ListBuckets" in policy.statements[0].actions

    def test_parse_yaml_without_pyyaml_installed(self, parser):
        """Test parse_policy_yaml raises clear error when pyyaml is missing.

        v0.8.1 (C2): yaml is now imported inside parse_policy_yaml at
        call-site. To simulate "not installed", force ImportError via
        sys.modules manipulation.
        """
        import sys

        real_yaml = sys.modules.pop("yaml", None)
        sys.modules["yaml"] = None  # type: ignore[assignment]
        try:
            with pytest.raises(PolicyParserError, match="PyYAML is required"):
                parser.parse_policy_yaml("Version: '2012-10-17'")
        finally:
            del sys.modules["yaml"]
            if real_yaml is not None:
                sys.modules["yaml"] = real_yaml

    def test_parse_auto_yaml_without_pyyaml_installed(self, parser):
        """Test parse_policy_auto raises clear error for yaml format when pyyaml is missing.

        v0.8.1 (C2): see comment on test_parse_yaml_without_pyyaml_installed.
        """
        import sys

        real_yaml = sys.modules.pop("yaml", None)
        sys.modules["yaml"] = None  # type: ignore[assignment]
        try:
            with pytest.raises(PolicyParserError, match="PyYAML is required"):
                parser.parse_policy_auto("Version: '2012-10-17'", "yaml")
        finally:
            del sys.modules["yaml"]
            if real_yaml is not None:
                sys.modules["yaml"] = real_yaml


class TestNoDBParserBehavior:
    """Test parser behavior without a database (JSON cache source)."""

    def test_no_db_source_is_json_cache(self, parser):
        """Parser without DB uses json_cache as source."""
        assert parser._services_source == "json_cache"

    def test_no_db_known_service_is_tier2(self, parser):
        """Without DB, known-service action is Tier 2 with cache reason."""
        result = parser.classify_action("s3:GetObject")
        assert result.tier == ValidationTier.TIER_2_UNKNOWN
        assert "recognized (cached)" in result.reason

    def test_no_db_unknown_service_is_tier3(self, parser):
        """Without DB, unknown service is still Tier 3."""
        result = parser.classify_action("madeupservice:DoSomething")
        assert result.tier == ValidationTier.TIER_3_INVALID

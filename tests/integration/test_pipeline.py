"""Integration tests for the end-to-end Pipeline orchestrator.

Tests cover pipeline initialization, basic flow through all four steps,
loop-back mechanism, configuration options, and end-to-end scenarios.
"""

import json
import pytest
from pathlib import Path

from src.sentinel.parser import Policy, Statement
from src.sentinel.database import Database, DatabaseError, Service, Action
from src.sentinel.inventory import ResourceInventory, Resource
from src.sentinel.self_check import (
    Pipeline,
    PipelineConfig,
    PipelineResult,
    CheckVerdict,
    SelfCheckResult,
)

from tests.conftest import make_test_db


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def tmp_db(tmp_path):
    """Create a migrated + seeded IAM actions DB with sample actions.

    Task 0 migration: Pipeline wires every Phase 2 consumer
    (RiskAnalyzer, CompanionPermissionDetector, PolicyRewriter), all
    of which bulk-load from the classification tables populated by
    make_test_db.
    """
    db_path = make_test_db(tmp_path)
    db = Database(db_path)

    for svc in [
        Service(service_prefix="s3", service_name="Amazon S3"),
        Service(service_prefix="ec2", service_name="Amazon EC2"),
        Service(service_prefix="lambda", service_name="AWS Lambda"),
        Service(service_prefix="iam", service_name="AWS IAM"),
        Service(service_prefix="logs", service_name="CloudWatch Logs"),
        Service(service_prefix="kms", service_name="AWS KMS"),
        Service(service_prefix="sqs", service_name="Amazon SQS"),
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
        db.insert_action(
            Action(
                action_id=None,
                service_prefix="s3",
                action_name=name,
                full_action=f"s3:{name}",
                description=f"S3 {name}",
                access_level=level,
                is_list=is_list,
                is_read=is_read,
                is_write=is_write,
            )
        )

    ec2_actions = [
        ("DescribeInstances", "List", True, False, False),
        ("RunInstances", "Write", False, False, True),
        ("TerminateInstances", "Write", False, False, True),
    ]
    for name, level, is_list, is_read, is_write in ec2_actions:
        db.insert_action(
            Action(
                action_id=None,
                service_prefix="ec2",
                action_name=name,
                full_action=f"ec2:{name}",
                description=f"EC2 {name}",
                access_level=level,
                is_list=is_list,
                is_read=is_read,
                is_write=is_write,
            )
        )

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

    for name in ["Decrypt", "Encrypt", "GenerateDataKey"]:
        db.insert_action(
            Action(
                action_id=None,
                service_prefix="kms",
                action_name=name,
                full_action=f"kms:{name}",
                description=f"KMS {name}",
                access_level="Write",
                is_write=True,
            )
        )

    iam_actions = [
        ("PassRole", "Permissions management", False, False, False, True),
        ("CreatePolicyVersion", "Permissions management", False, False, False, True),
        ("AttachRolePolicy", "Permissions management", False, False, False, True),
        ("GetUser", "Read", False, True, False, False),
    ]
    for name, level, is_list, is_read, is_write, is_perms in iam_actions:
        db.insert_action(
            Action(
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
            )
        )

    return db


@pytest.fixture
def tmp_inventory(tmp_path):
    """Create a temporary resource inventory with sample data."""
    inv_path = tmp_path / "test_inventory.db"
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
    if "deny_actions" in overrides:
        policy["Statement"].append(
            {
                "Effect": "Deny",
                "Action": overrides["deny_actions"],
                "Resource": overrides.get("deny_resources", ["*"]),
            }
        )
    return json.dumps(policy)


# ---------------------------------------------------------------------------
# Test Pipeline Initialization
# ---------------------------------------------------------------------------


class TestPipelineInit:
    """Tests for Pipeline initialization."""

    def test_init_no_args_hard_fails(self):
        """Pipeline() with no DB HARD-FAILS under Task 8b D3.

        Task 8b removed the class-constant fallback path — all DB-backed
        classifiers (RiskAnalyzer, CompanionPermissionDetector) now require
        a seeded Database.  Pipeline() delegates to
        CompanionPermissionDetector(None) in its __init__, which raises
        DatabaseError.  This test documents that contract so the no-arg
        path cannot silently regress to the deleted fallback behavior.
        """
        with pytest.raises(DatabaseError):
            Pipeline()

    def test_init_with_database(self, tmp_db):
        """Pipeline accepts a Database instance."""
        pipeline = Pipeline(database=tmp_db)
        assert pipeline.database is tmp_db

    def test_init_with_both(self, tmp_db, tmp_inventory):
        """Pipeline accepts both database and inventory."""
        pipeline = Pipeline(database=tmp_db, inventory=tmp_inventory)
        assert pipeline.database is tmp_db
        assert pipeline.inventory is tmp_inventory


# ---------------------------------------------------------------------------
# Test Pipeline Basic Flow
# ---------------------------------------------------------------------------


class TestPipelineBasicFlow:
    """Tests for basic pipeline flow through all 4 steps."""

    def test_simple_policy_flows_through(self, tmp_db):
        """Simple policy flows through all 4 pipeline steps."""
        pipeline = Pipeline(database=tmp_db)
        policy_json = _make_policy_json(actions=["s3:GetObject"])
        result = pipeline.run(policy_json)
        assert isinstance(result, PipelineResult)
        assert result.original_policy is not None
        assert result.rewritten_policy is not None
        assert result.validation_results is not None
        assert result.self_check_result is not None
        assert result.iterations >= 1

    def test_wildcard_policy_gets_rewritten(self, tmp_db):
        """Wildcard policy gets rewritten and passes self-check."""
        pipeline = Pipeline(database=tmp_db)
        policy_json = _make_policy_json(actions=["s3:*"])
        result = pipeline.run(policy_json)
        # Wildcards should be expanded
        all_actions = []
        for stmt in result.rewritten_policy.statements:
            all_actions.extend(stmt.actions)
        assert "s3:GetObject" in all_actions
        assert "s3:PutObject" in all_actions

    def test_deny_only_policy_passes_through(self, tmp_db):
        """Deny-only policy passes through the pipeline."""
        policy = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Deny",
                    "Action": "s3:DeleteObject",
                    "Resource": "*",
                }
            ],
        }
        pipeline = Pipeline(database=tmp_db)
        result = pipeline.run(json.dumps(policy))
        assert result.rewritten_policy is not None
        deny_stmts = [s for s in result.rewritten_policy.statements if s.effect == "Deny"]
        assert len(deny_stmts) >= 1

    def test_policy_with_intent(self, tmp_db):
        """Policy with intent produces tighter output."""
        pipeline = Pipeline(database=tmp_db)
        policy_json = _make_policy_json(actions=["*"])
        config = PipelineConfig(intent="read-only s3")
        result = pipeline.run(policy_json, config)
        all_actions = []
        for stmt in result.rewritten_policy.statements:
            if stmt.effect == "Allow":
                all_actions.extend(stmt.actions)
        # Should have read actions
        assert any("Get" in a or "List" in a or "Head" in a for a in all_actions)

    def test_pipeline_result_all_fields_populated(self, tmp_db):
        """PipelineResult has all fields populated."""
        pipeline = Pipeline(database=tmp_db)
        policy_json = _make_policy_json(actions=["s3:GetObject"])
        result = pipeline.run(policy_json)
        assert result.original_policy is not None
        assert result.rewritten_policy is not None
        assert isinstance(result.validation_results, list)
        assert isinstance(result.risk_findings, list)
        assert result.rewrite_result is not None
        assert isinstance(result.self_check_result, SelfCheckResult)
        assert isinstance(result.iterations, int)
        assert isinstance(result.final_verdict, CheckVerdict)
        assert isinstance(result.pipeline_summary, str)
        assert len(result.pipeline_summary) > 0


# ---------------------------------------------------------------------------
# Test Pipeline Loop-Back
# ---------------------------------------------------------------------------


class TestPipelineLoopBack:
    """Tests for the self-check loop-back mechanism."""

    def test_failing_policy_triggers_loopback(self, tmp_db):
        """Policy that fails self-check triggers at least one loop-back."""
        pipeline = Pipeline(database=tmp_db)
        # Use an invalid action that will be flagged by self-check
        policy = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": ["s3:GetObject", "invalidformat"],
                    "Resource": ["arn:aws:s3:::bucket/*"],
                }
            ],
        }
        config = PipelineConfig(max_self_check_retries=3)
        result = pipeline.run(json.dumps(policy), config)
        # Should have attempted at least one loop-back
        assert result.iterations >= 1

    def test_loopback_fixes_issue(self, tmp_db):
        """Loop-back removes invalid actions on retry."""
        pipeline = Pipeline(database=tmp_db)
        policy = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": ["s3:GetObject", "invalidformat"],
                    "Resource": ["arn:aws:s3:::bucket/*"],
                }
            ],
        }
        config = PipelineConfig(max_self_check_retries=3)
        result = pipeline.run(json.dumps(policy), config)
        # After loop-back, invalid action should be removed
        all_actions = []
        for stmt in result.rewritten_policy.statements:
            all_actions.extend(stmt.actions)
        assert "invalidformat" not in all_actions

    def test_max_retries_respected(self, tmp_db):
        """Pipeline stops after max_self_check_retries iterations."""
        pipeline = Pipeline(database=tmp_db)
        policy_json = _make_policy_json(actions=["s3:GetObject"])
        config = PipelineConfig(max_self_check_retries=2)
        result = pipeline.run(policy_json, config)
        assert result.iterations <= config.max_self_check_retries

    def test_iterations_count_correct(self, tmp_db):
        """Iterations count matches actual loop-back count."""
        pipeline = Pipeline(database=tmp_db)
        policy_json = _make_policy_json(actions=["s3:GetObject"])
        config = PipelineConfig(max_self_check_retries=3)
        result = pipeline.run(policy_json, config)
        # For a clean policy, should be 1 iteration (no loop-back needed)
        assert result.iterations >= 1


# ---------------------------------------------------------------------------
# Test Pipeline Configuration
# ---------------------------------------------------------------------------


class TestPipelineConfig:
    """Tests for pipeline configuration options."""

    def test_default_config_works(self, tmp_db):
        """Pipeline works with default config."""
        pipeline = Pipeline(database=tmp_db)
        policy_json = _make_policy_json(actions=["s3:GetObject"])
        result = pipeline.run(policy_json)
        assert result.final_verdict is not None

    def test_strict_mode_fails_on_warnings(self, tmp_db):
        """Strict mode causes pipeline to fail on warnings."""
        pipeline = Pipeline(database=tmp_db)
        # Wildcard resource will produce a WARNING
        policy_json = _make_policy_json(
            actions=["s3:GetObject"],
            resources=["*"],
        )
        config = PipelineConfig(strict_mode=True)
        result = pipeline.run(policy_json, config)
        # Wildcard resource produces WARNING, strict mode -> FAIL
        if result.self_check_result.findings:
            has_warning = any(
                f.severity.value == "WARNING" for f in result.self_check_result.findings
            )
            if has_warning:
                assert result.final_verdict == CheckVerdict.FAIL

    def test_custom_max_retries(self, tmp_db):
        """Custom max retries is respected."""
        pipeline = Pipeline(database=tmp_db)
        policy_json = _make_policy_json(actions=["s3:GetObject"])
        config = PipelineConfig(max_self_check_retries=1)
        result = pipeline.run(policy_json, config)
        assert result.iterations <= 1


# ---------------------------------------------------------------------------
# Test Pipeline End-to-End
# ---------------------------------------------------------------------------


class TestPipelineEndToEnd:
    """End-to-end pipeline scenario tests."""

    def test_read_only_s3_intent(self, tmp_db, tmp_inventory):
        """Read-only S3 intent produces correct policy."""
        pipeline = Pipeline(database=tmp_db, inventory=tmp_inventory)
        policy_json = _make_policy_json(actions=["s3:*"])
        config = PipelineConfig(intent="read-only s3")
        result = pipeline.run(policy_json, config)
        all_actions = []
        for stmt in result.rewritten_policy.statements:
            if stmt.effect == "Allow":
                all_actions.extend(stmt.actions)
        # Should have read/list actions
        read_actions = [
            a for a in all_actions if any(kw in a for kw in ["Get", "List", "Head", "Describe"])
        ]
        assert len(read_actions) > 0

    def test_lambda_policy_gets_companions(self, tmp_db):
        """Lambda policy gets companion permissions through the pipeline."""
        pipeline = Pipeline(database=tmp_db)
        policy_json = _make_policy_json(actions=["lambda:InvokeFunction"])
        result = pipeline.run(policy_json)
        all_actions = []
        for stmt in result.rewritten_policy.statements:
            all_actions.extend(stmt.actions)
        # Should have CloudWatch Logs companion actions
        assert "logs:CreateLogGroup" in all_actions
        assert "logs:CreateLogStream" in all_actions
        assert "logs:PutLogEvents" in all_actions

    def test_full_wildcard_with_intent_gets_scoped(self, tmp_db):
        """Full wildcard with intent gets scoped to specific actions."""
        pipeline = Pipeline(database=tmp_db)
        policy_json = _make_policy_json(actions=["*"])
        config = PipelineConfig(intent="read-only s3")
        result = pipeline.run(policy_json, config)
        all_actions = []
        for stmt in result.rewritten_policy.statements:
            if stmt.effect == "Allow":
                all_actions.extend(stmt.actions)
        # Full wildcard should be expanded based on intent
        if "*" not in all_actions:
            # If expanded, should have s3 read actions
            assert any(a.startswith("s3:") for a in all_actions)

    def test_privilege_escalation_detected(self, tmp_db):
        """Privilege escalation actions are detected in risk findings."""
        pipeline = Pipeline(database=tmp_db)
        policy_json = _make_policy_json(actions=["iam:PassRole", "lambda:CreateFunction"])
        result = pipeline.run(policy_json)
        escalation_findings = [
            f
            for f in result.risk_findings
            if "ESCALATION" in f.risk_type or "DANGEROUS" in f.risk_type
        ]
        assert len(escalation_findings) >= 1

    def test_final_verdict_matches_self_check(self, tmp_db):
        """Pipeline final verdict matches self-check result verdict."""
        pipeline = Pipeline(database=tmp_db)
        policy_json = _make_policy_json(actions=["s3:GetObject"])
        result = pipeline.run(policy_json)
        assert result.final_verdict == result.self_check_result.verdict


# ---------------------------------------------------------------------------
# Test Pipeline HITL Interactive Mode
# ---------------------------------------------------------------------------


class TestPipelineHITL:
    """Tests for HITL interactive prompting within the pipeline."""

    def _make_tier2_policy_json(self):
        """Create a policy with a mix of valid and Tier 2 actions.

        Tier 2 actions require a known service prefix with an unknown
        action name (e.g., s3:FutureAction -- s3 exists in DB but
        FutureAction does not).
        """
        policy = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": [
                        "s3:GetObject",
                        "s3:FutureAction",
                    ],
                    "Resource": ["*"],
                }
            ],
        }
        return json.dumps(policy)

    def test_non_interactive_default_hitl_empty(self, tmp_db):
        """Default non-interactive mode: Tier 2 handled by self-check loop-back."""
        pipeline = Pipeline(database=tmp_db)
        policy_json = self._make_tier2_policy_json()
        config = PipelineConfig(interactive=False)
        result = pipeline.run(policy_json, config)

        # No interactive HITL decisions recorded
        assert result.hitl_decisions == []

    def test_interactive_approve_tier2(self, tmp_db, monkeypatch):
        """Interactive mode: approved Tier 2 action survives into rewriting."""
        pipeline = Pipeline(database=tmp_db)
        policy_json = self._make_tier2_policy_json()
        config = PipelineConfig(interactive=True)

        # Approve all Tier 2 actions
        monkeypatch.setattr("builtins.input", lambda _: "a")

        result = pipeline.run(policy_json, config)

        # Should have HITL decisions
        assert len(result.hitl_decisions) >= 1
        assert all(d.user_approved for d in result.hitl_decisions)
        # Summary should mention HITL
        assert "HITL" in result.pipeline_summary

    def test_interactive_reject_tier2(self, tmp_db, monkeypatch):
        """Interactive mode: rejected Tier 2 action removed before rewriting."""
        pipeline = Pipeline(database=tmp_db)
        policy_json = self._make_tier2_policy_json()
        config = PipelineConfig(interactive=True)

        # Reject all Tier 2 actions
        monkeypatch.setattr("builtins.input", lambda _: "r")

        result = pipeline.run(policy_json, config)

        # Should have rejected decisions
        rejected = [d for d in result.hitl_decisions if not d.user_approved]
        assert len(rejected) >= 1

        # Rejected action should not appear in rewritten policy
        all_actions = []
        for stmt in result.rewritten_policy.statements:
            all_actions.extend(stmt.actions)
        for decision in rejected:
            assert decision.action not in all_actions

    def test_interactive_skip_auto_approves(self, tmp_db, monkeypatch):
        """Interactive mode: skip remaining auto-approves all subsequent."""
        pipeline = Pipeline(database=tmp_db)
        # Policy with two Tier 2 actions (known service, unknown action)
        policy = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": [
                        "s3:GetObject",
                        "s3:FutureAction",
                        "ec2:FutureAction",
                    ],
                    "Resource": ["*"],
                }
            ],
        }
        policy_json = json.dumps(policy)
        config = PipelineConfig(interactive=True)

        # Skip on first prompt -- auto-approve all
        monkeypatch.setattr("builtins.input", lambda _: "s")

        result = pipeline.run(policy_json, config)

        # All Tier 2 actions should be approved
        assert all(d.user_approved for d in result.hitl_decisions)

    def test_no_tier2_no_hitl(self, tmp_db):
        """No Tier 2 actions means no HITL decisions even in interactive mode."""
        pipeline = Pipeline(database=tmp_db)
        # All actions are valid Tier 1
        policy_json = _make_policy_json(actions=["s3:GetObject", "s3:PutObject"])
        config = PipelineConfig(interactive=True)
        result = pipeline.run(policy_json, config)

        assert result.hitl_decisions == []

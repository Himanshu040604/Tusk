"""Unit tests for the Self-Check Validator module.

Tests cover dataclass initialization, action validation, ARN format checking,
functional completeness scoring, overly broad detection, Tier 2 exclusion,
assumption validation, verdict computation, and completeness scoring.
"""

import pytest
from pathlib import Path

from src.sentinel.parser import Policy, Statement, ValidationResult, ValidationTier
from src.sentinel.rewriter import RewriteResult, RewriteConfig, RewriteChange
from src.sentinel.analyzer import CompanionPermission, RiskSeverity
from src.sentinel.database import Database, DatabaseError, Service, Action
from src.sentinel.inventory import ResourceInventory, Resource
from src.sentinel.self_check import (
    SelfCheckValidator,
    CheckFinding,
    CheckSeverity,
    CheckVerdict,
    SelfCheckResult,
    PipelineConfig,
    PipelineResult,
)

from tests.conftest import make_test_db


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def tmp_db(tmp_path, migrated_db_template):
    """Create a migrated + seeded IAM actions DB with sample actions.

    Task 0 migration: Pipeline constructs RiskAnalyzer +
    CompanionPermissionDetector + PolicyRewriter, each of which
    bulk-loads from the Phase 2 tables — make_test_db seeds those
    so the bulk-load finds rows post-Task-8.

    v0.7.0 (Phase 7.3): uses ``template=migrated_db_template`` for the
    session-scoped fast-copy path (~1ms per test vs ~200ms migration).
    """
    db_path = make_test_db(tmp_path, template=migrated_db_template)
    db = Database(db_path)

    for svc in [
        Service(service_prefix="s3", service_name="Amazon S3"),
        Service(service_prefix="ec2", service_name="Amazon EC2"),
        Service(service_prefix="lambda", service_name="AWS Lambda"),
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
            service_prefix="lambda",
            resource_type="function",
            resource_arn="arn:aws:lambda:us-east-1:123456789012:function:my-func",
            resource_name="my-func",
            region="us-east-1",
            account_id="123456789012",
        ),
    ]
    for r in resources:
        inv.insert_resource(r)

    return inv


def _make_rewrite_result(
    original_policy=None,
    rewritten_policy=None,
    changes=None,
    assumptions=None,
    warnings=None,
):
    """Helper to build a RewriteResult with defaults."""
    if original_policy is None:
        original_policy = Policy(
            version="2012-10-17",
            statements=[
                Statement(
                    effect="Allow",
                    actions=["s3:GetObject"],
                    resources=["*"],
                )
            ],
        )
    if rewritten_policy is None:
        rewritten_policy = Policy(
            version="2012-10-17",
            statements=[
                Statement(
                    effect="Allow",
                    actions=["s3:GetObject"],
                    resources=["arn:aws:s3:::my-bucket/*"],
                )
            ],
        )
    return RewriteResult(
        original_policy=original_policy,
        rewritten_policy=rewritten_policy,
        changes=changes or [],
        assumptions=assumptions
        if assumptions is not None
        else ["No resource inventory available."],
        warnings=warnings or [],
    )


# ---------------------------------------------------------------------------
# Test CheckFinding Dataclass
# ---------------------------------------------------------------------------


class TestCheckFindingDataclass:
    """Tests for CheckFinding dataclass initialization."""

    def test_required_fields(self):
        """CheckFinding requires check_type, severity, and message."""
        finding = CheckFinding(
            check_type="ACTION_VALIDATION",
            severity=CheckSeverity.ERROR,
            message="test finding",
        )
        assert finding.check_type == "ACTION_VALIDATION"
        assert finding.severity == CheckSeverity.ERROR
        assert finding.message == "test finding"

    def test_optional_fields_default_none(self):
        """Optional fields default to None."""
        finding = CheckFinding(
            check_type="ARN_FORMAT",
            severity=CheckSeverity.WARNING,
            message="test",
        )
        assert finding.action is None
        assert finding.resource is None
        assert finding.remediation is None

    def test_all_fields(self):
        """All fields can be set."""
        finding = CheckFinding(
            check_type="TIER2_IN_POLICY",
            severity=CheckSeverity.INFO,
            message="info message",
            action="s3:GetObject",
            resource="arn:aws:s3:::bucket",
            remediation="Remove action",
        )
        assert finding.action == "s3:GetObject"
        assert finding.resource == "arn:aws:s3:::bucket"
        assert finding.remediation == "Remove action"


# ---------------------------------------------------------------------------
# Test SelfCheckResult Dataclass
# ---------------------------------------------------------------------------


class TestSelfCheckResultDataclass:
    """Tests for SelfCheckResult dataclass initialization."""

    def test_required_fields(self):
        """SelfCheckResult requires all fields."""
        result = SelfCheckResult(
            verdict=CheckVerdict.PASS,
            findings=[],
            completeness_score=1.0,
            assumptions_valid=True,
            tier2_preserved_actions=[],
            summary="All checks passed",
        )
        assert result.verdict == CheckVerdict.PASS
        assert result.completeness_score == 1.0

    def test_findings_list(self):
        """Findings list contains CheckFinding objects."""
        finding = CheckFinding(
            check_type="TEST",
            severity=CheckSeverity.INFO,
            message="test",
        )
        result = SelfCheckResult(
            verdict=CheckVerdict.WARNING,
            findings=[finding],
            completeness_score=0.8,
            assumptions_valid=True,
            tier2_preserved_actions=[],
            summary="One warning",
        )
        assert len(result.findings) == 1
        assert result.findings[0].check_type == "TEST"

    def test_verdict_values(self):
        """CheckVerdict has PASS, FAIL, WARNING values."""
        assert CheckVerdict.PASS.value == "PASS"
        assert CheckVerdict.FAIL.value == "FAIL"
        assert CheckVerdict.WARNING.value == "WARNING"

    def test_tier2_excluded_shim_emits_deprecation_warning(self):
        """v0.8.1 (L4): tier2_excluded property emits DeprecationWarning.

        The shim is semantically lossy — True == "no Tier-2 in rewrite"
        looks identical to v0.7.0 "Tier-2 actions were dropped", which
        is a false-negative for legacy consumers. Removal in v0.9.0.
        """
        import warnings

        result = SelfCheckResult(
            verdict=CheckVerdict.PASS,
            findings=[],
            completeness_score=1.0,
            assumptions_valid=True,
            tier2_preserved_actions=[],
            summary="clean",
        )
        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter("always")
            _ = result.tier2_excluded
            deprecations = [w for w in caught if issubclass(w.category, DeprecationWarning)]
            assert len(deprecations) == 1
            assert "tier2_excluded is deprecated" in str(deprecations[0].message)
            assert "tier2_preserved_actions" in str(deprecations[0].message)
            assert "v0.9.0" in str(deprecations[0].message)

    def test_tier2_excluded_shim_still_returns_bool(self):
        """v0.8.1 (L4): DeprecationWarning does not change return value."""
        import warnings

        result_empty = SelfCheckResult(
            verdict=CheckVerdict.PASS,
            findings=[],
            completeness_score=1.0,
            assumptions_valid=True,
            tier2_preserved_actions=[],
            summary="clean",
        )
        result_nonempty = SelfCheckResult(
            verdict=CheckVerdict.WARNING,
            findings=[],
            completeness_score=0.5,
            assumptions_valid=True,
            tier2_preserved_actions=["s3:NewAction"],
            summary="with tier-2",
        )
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", DeprecationWarning)
            assert result_empty.tier2_excluded is True
            assert result_nonempty.tier2_excluded is False


# ---------------------------------------------------------------------------
# Test PipelineConfig Dataclass
# ---------------------------------------------------------------------------


class TestPipelineConfigDataclass:
    """Tests for PipelineConfig dataclass defaults."""

    def test_default_values(self):
        """PipelineConfig defaults are sensible."""
        config = PipelineConfig()
        assert config.intent is None
        assert config.account_id is None
        assert config.region is None
        assert config.strict_mode is False
        assert config.max_self_check_retries == 3
        assert config.add_companions is True
        assert config.add_conditions is True

    def test_custom_values(self):
        """PipelineConfig accepts custom values."""
        config = PipelineConfig(
            intent="read-only s3",
            strict_mode=True,
            max_self_check_retries=5,
        )
        assert config.intent == "read-only s3"
        assert config.strict_mode is True
        assert config.max_self_check_retries == 5

    def test_all_fields_settable(self):
        """All PipelineConfig fields can be set."""
        config = PipelineConfig(
            intent="admin",
            account_id="111222333444",
            region="eu-west-1",
            strict_mode=True,
            max_self_check_retries=1,
            add_companions=False,
            add_conditions=False,
        )
        assert config.account_id == "111222333444"
        assert config.add_companions is False


# ---------------------------------------------------------------------------
# Test SelfCheckValidator Initialization
# ---------------------------------------------------------------------------


class TestSelfCheckValidatorInit:
    """Tests for SelfCheckValidator initialization."""

    def test_init_no_args_hard_fails(self):
        """SelfCheckValidator() with no DB HARD-FAILS under Task 8b D3.

        Task 8b removed the class-constant fallback path.  SelfCheckValidator
        constructs RiskAnalyzer(database) and CompanionPermissionDetector
        (database) in its __init__; both raise DatabaseError when database
        is None.  This test documents the contract so the deleted fallback
        behavior cannot silently regress.
        """
        with pytest.raises(DatabaseError):
            SelfCheckValidator()

    def test_init_with_database(self, tmp_db):
        """Validator accepts a Database instance."""
        validator = SelfCheckValidator(database=tmp_db)
        assert validator.database is tmp_db

    def test_init_with_both(self, tmp_db, tmp_inventory):
        """Validator accepts both database and inventory."""
        validator = SelfCheckValidator(database=tmp_db, inventory=tmp_inventory)
        assert validator.database is tmp_db
        assert validator.inventory is tmp_inventory


# ---------------------------------------------------------------------------
# Test Action Validation
# ---------------------------------------------------------------------------


class TestActionValidation:
    """Tests for _validate_actions check."""

    def test_valid_tier1_actions_pass(self, tmp_db):
        """Valid Tier 1 actions produce no findings."""
        validator = SelfCheckValidator(database=tmp_db)
        policy = Policy(
            version="2012-10-17",
            statements=[
                Statement(
                    effect="Allow",
                    actions=["s3:GetObject", "s3:PutObject"],
                    resources=["arn:aws:s3:::bucket/*"],
                )
            ],
        )
        findings = validator._validate_actions(policy)
        assert len(findings) == 0

    def test_tier3_invalid_action_detected(self, tmp_db):
        """Tier 3 invalid action flagged as ERROR."""
        validator = SelfCheckValidator(database=tmp_db)
        policy = Policy(
            version="2012-10-17",
            statements=[
                Statement(
                    effect="Allow",
                    actions=["s3:GetObject", "invalidformat"],
                    resources=["*"],
                )
            ],
        )
        findings = validator._validate_actions(policy)
        errors = [f for f in findings if f.severity == CheckSeverity.ERROR]
        assert len(errors) >= 1
        assert any("invalidformat" in f.message for f in errors)

    def test_tier2_unknown_action_detected(self, tmp_db):
        """Tier 2 unknown action flagged as ERROR."""
        validator = SelfCheckValidator(database=tmp_db)
        policy = Policy(
            version="2012-10-17",
            statements=[
                Statement(
                    effect="Allow",
                    actions=["s3:GetObject", "s3:SomeNewAction"],
                    resources=["*"],
                )
            ],
        )
        findings = validator._validate_actions(policy)
        tier2_findings = [
            f for f in findings if "Tier 2" in f.message or "unknown" in f.message.lower()
        ]
        assert len(tier2_findings) >= 1

    def test_wildcard_action_skipped(self, tmp_db):
        """Full wildcard actions are not re-validated."""
        validator = SelfCheckValidator(database=tmp_db)
        policy = Policy(
            version="2012-10-17",
            statements=[
                Statement(
                    effect="Allow",
                    actions=["*"],
                    resources=["*"],
                )
            ],
        )
        findings = validator._validate_actions(policy)
        assert len(findings) == 0

    def test_empty_policy_passes(self, tmp_db):
        """Empty policy with no statements produces no findings."""
        validator = SelfCheckValidator(database=tmp_db)
        policy = Policy(version="2012-10-17", statements=[])
        findings = validator._validate_actions(policy)
        assert len(findings) == 0

    def test_mixed_valid_invalid_actions(self, tmp_db):
        """Mixed valid/invalid actions each produce appropriate findings."""
        validator = SelfCheckValidator(database=tmp_db)
        policy = Policy(
            version="2012-10-17",
            statements=[
                Statement(
                    effect="Allow",
                    actions=["s3:GetObject", "badformat", "s3:ListBucket"],
                    resources=["*"],
                )
            ],
        )
        findings = validator._validate_actions(policy)
        assert len(findings) >= 1
        action_messages = [f.action for f in findings]
        assert "badformat" in action_messages


# ---------------------------------------------------------------------------
# Test ARN Format Validation
# ---------------------------------------------------------------------------


class TestArnFormatValidation:
    """Tests for _check_arn_formats check."""

    def test_valid_arn_passes(self, tmp_db):
        """Valid ARN produces no findings."""
        validator = SelfCheckValidator(database=tmp_db)
        policy = Policy(
            version="2012-10-17",
            statements=[
                Statement(
                    effect="Allow",
                    actions=["s3:GetObject"],
                    resources=["arn:aws:s3:us-east-1:123456789012:bucket/my-bucket"],
                )
            ],
        )
        findings = validator._check_arn_formats(policy)
        assert len(findings) == 0

    def test_wildcard_resource_flagged_error_by_default(self, tmp_db):
        """Wildcard resource flagged as ERROR by default (fail-closed)."""
        validator = SelfCheckValidator(database=tmp_db)
        policy = Policy(
            version="2012-10-17",
            statements=[
                Statement(
                    effect="Allow",
                    actions=["s3:GetObject"],
                    resources=["*"],
                )
            ],
        )
        findings = validator._check_arn_formats(policy)
        errors = [f for f in findings if f.severity == CheckSeverity.ERROR]
        assert len(errors) >= 1
        assert errors[0].check_type == "REMAINING_WILDCARD"

    def test_placeholder_arn_flagged_info(self, tmp_db):
        """Placeholder ARN flagged as INFO (not error)."""
        validator = SelfCheckValidator(database=tmp_db)
        policy = Policy(
            version="2012-10-17",
            statements=[
                Statement(
                    effect="Allow",
                    actions=["s3:GetObject"],
                    resources=["arn:aws:s3:::PLACEHOLDER-bucket-name"],
                )
            ],
        )
        findings = validator._check_arn_formats(policy)
        info_findings = [f for f in findings if f.severity == CheckSeverity.INFO]
        assert len(info_findings) >= 1
        assert info_findings[0].check_type == "PLACEHOLDER_ARN"

    def test_malformed_arn_flagged_error(self, tmp_db):
        """Malformed ARN flagged as ERROR."""
        validator = SelfCheckValidator(database=tmp_db)
        policy = Policy(
            version="2012-10-17",
            statements=[
                Statement(
                    effect="Allow",
                    actions=["s3:GetObject"],
                    resources=["arn:aws:s3"],
                )
            ],
        )
        findings = validator._check_arn_formats(policy)
        errors = [f for f in findings if f.severity == CheckSeverity.ERROR]
        assert len(errors) >= 1
        assert errors[0].check_type == "ARN_FORMAT"

    def test_multiple_resources_all_checked(self, tmp_db):
        """Multiple resources are all individually checked."""
        validator = SelfCheckValidator(database=tmp_db)
        policy = Policy(
            version="2012-10-17",
            statements=[
                Statement(
                    effect="Allow",
                    actions=["s3:GetObject"],
                    resources=[
                        "*",
                        "arn:aws:s3:::PLACEHOLDER-bucket",
                        "arn:aws:s3:us-east-1:123456789012:bucket/ok",
                    ],
                )
            ],
        )
        findings = validator._check_arn_formats(policy)
        types = {f.check_type for f in findings}
        assert "REMAINING_WILDCARD" in types
        assert "PLACEHOLDER_ARN" in types


# ---------------------------------------------------------------------------
# Test Functional Completeness
# ---------------------------------------------------------------------------


class TestFunctionalCompleteness:
    """Tests for _check_functional_completeness check."""

    def test_complete_policy_high_score(self, tmp_db):
        """Policy covering all original services scores high."""
        validator = SelfCheckValidator(database=tmp_db)
        original = Policy(
            version="2012-10-17",
            statements=[
                Statement(
                    effect="Allow",
                    actions=["s3:GetObject"],
                    resources=["*"],
                )
            ],
        )
        rewritten = Policy(
            version="2012-10-17",
            statements=[
                Statement(
                    effect="Allow",
                    actions=["s3:GetObject"],
                    resources=["arn:aws:s3:::bucket/*"],
                )
            ],
        )
        result = _make_rewrite_result(
            original_policy=original,
            rewritten_policy=rewritten,
        )
        config = PipelineConfig()
        findings, score = validator._check_functional_completeness(rewritten, result, config)
        assert score >= 0.8

    def test_missing_companion_lowers_score(self, tmp_db):
        """Missing companion permissions lower the completeness score."""
        validator = SelfCheckValidator(database=tmp_db)
        original = Policy(
            version="2012-10-17",
            statements=[
                Statement(
                    effect="Allow",
                    actions=["lambda:InvokeFunction"],
                    resources=["*"],
                )
            ],
        )
        rewritten = Policy(
            version="2012-10-17",
            statements=[
                Statement(
                    effect="Allow",
                    actions=["lambda:InvokeFunction"],
                    resources=["*"],
                )
            ],
        )
        result = _make_rewrite_result(
            original_policy=original,
            rewritten_policy=rewritten,
        )
        config = PipelineConfig()
        findings, score = validator._check_functional_completeness(rewritten, result, config)
        companion_findings = [f for f in findings if f.check_type == "MISSING_COMPANION"]
        assert len(companion_findings) >= 1
        assert score < 1.0

    def test_intent_mismatch_detected(self, tmp_db):
        """Read-only intent with write actions is flagged."""
        validator = SelfCheckValidator(database=tmp_db)
        original = Policy(
            version="2012-10-17",
            statements=[
                Statement(
                    effect="Allow",
                    actions=["s3:GetObject", "s3:PutObject"],
                    resources=["*"],
                )
            ],
        )
        rewritten = Policy(
            version="2012-10-17",
            statements=[
                Statement(
                    effect="Allow",
                    actions=["s3:GetObject", "s3:PutObject"],
                    resources=["*"],
                )
            ],
        )
        result = _make_rewrite_result(
            original_policy=original,
            rewritten_policy=rewritten,
        )
        config = PipelineConfig(intent="read-only s3")
        findings, score = validator._check_functional_completeness(rewritten, result, config)
        mismatch = [f for f in findings if f.check_type == "INTENT_MISMATCH"]
        assert len(mismatch) >= 1

    def test_service_coverage_checked(self, tmp_db):
        """Missing service in rewritten policy is flagged."""
        validator = SelfCheckValidator(database=tmp_db)
        original = Policy(
            version="2012-10-17",
            statements=[
                Statement(
                    effect="Allow",
                    actions=["s3:GetObject", "ec2:DescribeInstances"],
                    resources=["*"],
                )
            ],
        )
        rewritten = Policy(
            version="2012-10-17",
            statements=[
                Statement(
                    effect="Allow",
                    actions=["s3:GetObject"],
                    resources=["*"],
                )
            ],
        )
        result = _make_rewrite_result(
            original_policy=original,
            rewritten_policy=rewritten,
        )
        config = PipelineConfig()
        findings, score = validator._check_functional_completeness(rewritten, result, config)
        svc_findings = [f for f in findings if f.check_type == "MISSING_SERVICE_COVERAGE"]
        assert len(svc_findings) >= 1

    def test_empty_rewrite_low_score(self, tmp_db):
        """Empty rewritten policy gets a low score."""
        validator = SelfCheckValidator(database=tmp_db)
        original = Policy(
            version="2012-10-17",
            statements=[
                Statement(
                    effect="Allow",
                    actions=["s3:GetObject"],
                    resources=["*"],
                )
            ],
        )
        rewritten = Policy(version="2012-10-17", statements=[])
        result = _make_rewrite_result(
            original_policy=original,
            rewritten_policy=rewritten,
        )
        config = PipelineConfig()
        findings, score = validator._check_functional_completeness(rewritten, result, config)
        assert score <= 0.5

    def test_score_range(self, tmp_db):
        """Completeness score is always between 0.0 and 1.0."""
        validator = SelfCheckValidator(database=tmp_db)
        rewritten = Policy(
            version="2012-10-17",
            statements=[
                Statement(
                    effect="Allow",
                    actions=["s3:GetObject"],
                    resources=["*"],
                )
            ],
        )
        result = _make_rewrite_result(rewritten_policy=rewritten)
        config = PipelineConfig()
        _, score = validator._check_functional_completeness(rewritten, result, config)
        assert 0.0 <= score <= 1.0


# ---------------------------------------------------------------------------
# Test Overly Broad Permissions
# ---------------------------------------------------------------------------


class TestOverlyBroadPermissions:
    """Tests for _check_overly_broad_permissions check."""

    def test_no_wildcards_passes_clean(self, tmp_db):
        """Policy without wildcards produces no findings."""
        validator = SelfCheckValidator(database=tmp_db)
        policy = Policy(
            version="2012-10-17",
            statements=[
                Statement(
                    effect="Allow",
                    actions=["s3:GetObject"],
                    resources=["arn:aws:s3:::bucket/*"],
                )
            ],
        )
        findings = validator._check_overly_broad_permissions(policy)
        assert len(findings) == 0

    def test_full_wildcard_action_detected_as_error(self, tmp_db):
        """Full wildcard action flagged as ERROR by default (fail-closed)."""
        validator = SelfCheckValidator(database=tmp_db)
        policy = Policy(
            version="2012-10-17",
            statements=[
                Statement(
                    effect="Allow",
                    actions=["*"],
                    resources=["*"],
                )
            ],
        )
        findings = validator._check_overly_broad_permissions(policy)
        errors = [
            f
            for f in findings
            if f.check_type == "OVERLY_BROAD_ACTION" and f.severity == CheckSeverity.ERROR
        ]
        assert len(errors) >= 1

    def test_service_wildcard_detected(self, tmp_db):
        """Service wildcard action flagged as WARNING."""
        validator = SelfCheckValidator(database=tmp_db)
        policy = Policy(
            version="2012-10-17",
            statements=[
                Statement(
                    effect="Allow",
                    actions=["s3:*"],
                    resources=["*"],
                )
            ],
        )
        findings = validator._check_overly_broad_permissions(policy)
        svc_wildcards = [
            f
            for f in findings
            if f.check_type == "OVERLY_BROAD_ACTION" and f.severity == CheckSeverity.WARNING
        ]
        assert len(svc_wildcards) >= 1

    def test_partial_wildcard_detected_as_info(self, tmp_db):
        """Partial wildcard action flagged as INFO."""
        validator = SelfCheckValidator(database=tmp_db)
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
        findings = validator._check_overly_broad_permissions(policy)
        info = [
            f
            for f in findings
            if f.check_type == "OVERLY_BROAD_ACTION" and f.severity == CheckSeverity.INFO
        ]
        assert len(info) >= 1


# ---------------------------------------------------------------------------
# Test Tier 2 Exclusion
# ---------------------------------------------------------------------------


class TestTier2Exclusion:
    """Tests for _check_tier2_exclusion check."""

    def test_no_tier2_in_policy_passes(self, tmp_db):
        """No Tier 2 actions in rewritten policy produces no findings."""
        validator = SelfCheckValidator(database=tmp_db)
        policy = Policy(
            version="2012-10-17",
            statements=[
                Statement(
                    effect="Allow",
                    actions=["s3:GetObject"],
                    resources=["*"],
                )
            ],
        )
        validation_results = [
            ValidationResult(
                action="s3:GetObject",
                tier=ValidationTier.TIER_1_VALID,
                reason="Valid",
            ),
        ]
        findings = validator._check_tier2_exclusion(policy, validation_results)
        assert len(findings) == 0

    def test_tier2_action_in_policy_flagged(self, tmp_db):
        """Tier 2 action found in rewritten policy flagged as WARNING.

        Issue 2 (v0.8.0, Amendment 10): Tier-2 actions are now PRESERVED
        in the rewritten policy rather than removed, and the finding
        severity dropped from ERROR to WARNING. The verdict becomes
        WARNING instead of FAIL; under --strict the WARNING escalates
        back to FAIL preserving the old safety behavior.
        """
        validator = SelfCheckValidator(database=tmp_db)
        policy = Policy(
            version="2012-10-17",
            statements=[
                Statement(
                    effect="Allow",
                    actions=["s3:GetObject", "s3:NewUnknownAction"],
                    resources=["*"],
                )
            ],
        )
        validation_results = [
            ValidationResult(
                action="s3:GetObject",
                tier=ValidationTier.TIER_1_VALID,
                reason="Valid",
            ),
            ValidationResult(
                action="s3:NewUnknownAction",
                tier=ValidationTier.TIER_2_UNKNOWN,
                reason="Unknown",
            ),
        ]
        findings = validator._check_tier2_exclusion(policy, validation_results)
        tier2_findings = [f for f in findings if f.check_type == "TIER2_IN_POLICY"]
        assert len(tier2_findings) >= 1
        assert tier2_findings[0].severity == CheckSeverity.WARNING

    def test_mixed_tier_actions_handled(self, tmp_db):
        """Only Tier 2 actions in the rewritten policy are flagged."""
        validator = SelfCheckValidator(database=tmp_db)
        policy = Policy(
            version="2012-10-17",
            statements=[
                Statement(
                    effect="Allow",
                    actions=["s3:GetObject"],
                    resources=["*"],
                )
            ],
        )
        validation_results = [
            ValidationResult(
                action="s3:GetObject",
                tier=ValidationTier.TIER_1_VALID,
                reason="Valid",
            ),
            ValidationResult(
                action="s3:NewAction",
                tier=ValidationTier.TIER_2_UNKNOWN,
                reason="Unknown",
            ),
        ]
        findings = validator._check_tier2_exclusion(policy, validation_results)
        # s3:NewAction is Tier 2 but NOT in the rewritten policy
        assert len(findings) == 0

    def test_empty_policy_passes(self, tmp_db):
        """Empty rewritten policy produces no Tier 2 findings."""
        validator = SelfCheckValidator(database=tmp_db)
        policy = Policy(version="2012-10-17", statements=[])
        validation_results = [
            ValidationResult(
                action="s3:GetObject",
                tier=ValidationTier.TIER_2_UNKNOWN,
                reason="Unknown",
            ),
        ]
        findings = validator._check_tier2_exclusion(policy, validation_results)
        assert len(findings) == 0

    def test_tier2_preserved_actions_unions_both_check_types(self, tmp_db):
        """v0.8.1 (M1): tier2_preserved_actions must union TIER2_IN_POLICY
        and TIER2_ACTION_KEPT findings.

        Both surface paths populate the audit field — the field name
        implies complete audit coverage of Tier-2 actions preserved in
        the rewritten policy.

        - TIER2_IN_POLICY: surfaced by _check_tier2_exclusion (runs on
          original-policy validation; action was Tier-2 in original AND
          kept in rewritten).
        - TIER2_ACTION_KEPT: surfaced by _validate_actions (DB-lookup
          on rewritten policy; action not present in IAM corpus).

        Both paths can trigger for the same action, or for disjoint
        actions; the audit field must aggregate both or callers lose
        data. Regression test for the structurally incomplete
        implementation at v0.8.0.
        """
        validator = SelfCheckValidator(database=tmp_db)
        # Both actions are unknown (not in tmp_db); both will trigger
        # both TIER2_IN_POLICY (from _check_tier2_exclusion via
        # original-policy validation) AND TIER2_ACTION_KEPT (from
        # _validate_actions on the rewritten policy).
        original_policy = Policy(
            version="2012-10-17",
            statements=[
                Statement(
                    effect="Allow",
                    actions=["s3:NewUnknownAction"],
                    resources=["*"],
                )
            ],
        )
        rewritten_policy = Policy(
            version="2012-10-17",
            statements=[
                Statement(
                    effect="Allow",
                    actions=["s3:NewUnknownAction"],
                    resources=["arn:aws:s3:::bucket/*"],
                )
            ],
        )
        rewrite_result = _make_rewrite_result(
            original_policy=original_policy,
            rewritten_policy=rewritten_policy,
            assumptions=["Test."],
        )
        check_result = validator.run_self_check(rewrite_result)
        # The field must include the action.
        assert "s3:NewUnknownAction" in check_result.tier2_preserved_actions
        # Verify BOTH check_type paths fired for this action.
        in_policy_findings = [
            f
            for f in check_result.findings
            if f.check_type == "TIER2_IN_POLICY" and f.action == "s3:NewUnknownAction"
        ]
        kept_findings = [
            f
            for f in check_result.findings
            if f.check_type == "TIER2_ACTION_KEPT" and f.action == "s3:NewUnknownAction"
        ]
        assert len(in_policy_findings) >= 1, (
            "TIER2_IN_POLICY must fire for original-validated Tier-2 action preserved in rewrite"
        )
        assert len(kept_findings) >= 1, (
            "TIER2_ACTION_KEPT must fire for action missing from DB corpus in rewritten policy"
        )
        # Aggregation must be deduplicated (set-based).
        # Count the occurrences of the action in tier2_preserved_actions.
        assert check_result.tier2_preserved_actions.count("s3:NewUnknownAction") == 1, (
            "tier2_preserved_actions must deduplicate via set comprehension"
        )


# ---------------------------------------------------------------------------
# Test Assumption Validation
# ---------------------------------------------------------------------------


class TestAssumptionValidation:
    """Tests for _check_assumptions check."""

    def test_assumptions_present_passes(self, tmp_db):
        """Non-empty assumptions list produces no findings."""
        validator = SelfCheckValidator(database=tmp_db)
        result = _make_rewrite_result(assumptions=["No database available."])
        findings = validator._check_assumptions(result)
        assert len(findings) == 0

    def test_no_assumptions_flagged(self, tmp_db):
        """Empty assumptions list flagged as WARNING."""
        validator = SelfCheckValidator(database=tmp_db)
        result = _make_rewrite_result(assumptions=[])
        findings = validator._check_assumptions(result)
        warnings = [f for f in findings if f.severity == CheckSeverity.WARNING]
        assert len(warnings) >= 1
        assert warnings[0].check_type == "MISSING_ASSUMPTIONS"

    def test_empty_assumption_string_flagged(self, tmp_db):
        """Empty string in assumptions list flagged."""
        validator = SelfCheckValidator(database=tmp_db)
        result = _make_rewrite_result(assumptions=["Valid assumption", "", "  "])
        findings = validator._check_assumptions(result)
        empty_findings = [f for f in findings if f.check_type == "EMPTY_ASSUMPTION"]
        assert len(empty_findings) >= 1


# ---------------------------------------------------------------------------
# Test Self-Check Verdict
# ---------------------------------------------------------------------------


class TestSelfCheckVerdict:
    """Tests for verdict computation."""

    def test_all_pass_verdict(self, tmp_db):
        """No error/warning findings produce PASS verdict."""
        validator = SelfCheckValidator(database=tmp_db)
        # Use ec2:DescribeInstances which has no companion rules
        rewritten = Policy(
            version="2012-10-17",
            statements=[
                Statement(
                    effect="Allow",
                    actions=["ec2:DescribeInstances"],
                    resources=["arn:aws:ec2:us-east-1:123456789012:instance/i-abc"],
                )
            ],
        )
        original = Policy(
            version="2012-10-17",
            statements=[
                Statement(
                    effect="Allow",
                    actions=["ec2:DescribeInstances"],
                    resources=["*"],
                )
            ],
        )
        result = _make_rewrite_result(
            original_policy=original,
            rewritten_policy=rewritten,
            assumptions=["Database available."],
        )
        check_result = validator.run_self_check(result)
        assert check_result.verdict == CheckVerdict.PASS

    def test_error_finding_fail_verdict(self, tmp_db):
        """ERROR finding produces FAIL verdict."""
        validator = SelfCheckValidator(database=tmp_db)
        rewritten = Policy(
            version="2012-10-17",
            statements=[
                Statement(
                    effect="Allow",
                    actions=["s3:GetObject", "badformat"],
                    resources=["arn:aws:s3:::bucket/*"],
                )
            ],
        )
        result = _make_rewrite_result(
            rewritten_policy=rewritten,
            assumptions=["Test assumption."],
        )
        check_result = validator.run_self_check(result)
        assert check_result.verdict == CheckVerdict.FAIL

    def test_warning_normal_mode_verdict(self, tmp_db):
        """WARNING finding in normal mode produces WARNING verdict."""
        validator = SelfCheckValidator(database=tmp_db)
        rewritten = Policy(
            version="2012-10-17",
            statements=[
                Statement(
                    effect="Allow",
                    actions=["s3:GetObject"],
                    resources=["*"],
                )
            ],
        )
        result = _make_rewrite_result(
            rewritten_policy=rewritten,
            assumptions=["Test assumption."],
        )
        # Use allow_wildcard_resources to downgrade Resource:* from
        # ERROR to WARNING, so we can test the WARNING verdict path.
        config = PipelineConfig(
            strict_mode=False,
            allow_wildcard_resources=True,
        )
        check_result = validator.run_self_check(result, config)
        assert check_result.verdict == CheckVerdict.WARNING

    def test_warning_strict_mode_fail(self, tmp_db):
        """WARNING finding in strict mode produces FAIL verdict."""
        validator = SelfCheckValidator(database=tmp_db)
        rewritten = Policy(
            version="2012-10-17",
            statements=[
                Statement(
                    effect="Allow",
                    actions=["s3:GetObject"],
                    resources=["*"],
                )
            ],
        )
        result = _make_rewrite_result(
            rewritten_policy=rewritten,
            assumptions=["Test assumption."],
        )
        config = PipelineConfig(strict_mode=True)
        check_result = validator.run_self_check(result, config)
        assert check_result.verdict == CheckVerdict.FAIL

    def test_mixed_findings_highest_severity(self, tmp_db):
        """Mixed findings use highest severity for verdict."""
        validator = SelfCheckValidator(database=tmp_db)
        rewritten = Policy(
            version="2012-10-17",
            statements=[
                Statement(
                    effect="Allow",
                    actions=["s3:GetObject", "badformat"],
                    resources=["*"],
                )
            ],
        )
        result = _make_rewrite_result(
            rewritten_policy=rewritten,
            assumptions=["Test."],
        )
        check_result = validator.run_self_check(result)
        # Has both ERROR (badformat) and WARNING (*) -> FAIL wins
        assert check_result.verdict == CheckVerdict.FAIL


# ---------------------------------------------------------------------------
# Test Completeness Score
# ---------------------------------------------------------------------------


class TestSelfCheckCompleteness:
    """Tests for completeness score computation."""

    def test_score_within_range(self, tmp_db):
        """Completeness score is between 0.0 and 1.0."""
        validator = SelfCheckValidator(database=tmp_db)
        result = _make_rewrite_result(
            assumptions=["Test."],
        )
        check_result = validator.run_self_check(result)
        assert 0.0 <= check_result.completeness_score <= 1.0

    def test_perfect_policy_high_score(self, tmp_db):
        """Well-covered policy gets a high completeness score."""
        validator = SelfCheckValidator(database=tmp_db)
        original = Policy(
            version="2012-10-17",
            statements=[
                Statement(
                    effect="Allow",
                    actions=["s3:GetObject"],
                    resources=["*"],
                )
            ],
        )
        rewritten = Policy(
            version="2012-10-17",
            statements=[
                Statement(
                    effect="Allow",
                    actions=["s3:GetObject"],
                    resources=["arn:aws:s3:::bucket/*"],
                )
            ],
        )
        result = _make_rewrite_result(
            original_policy=original,
            rewritten_policy=rewritten,
            assumptions=["Database available."],
        )
        check_result = validator.run_self_check(result)
        assert check_result.completeness_score >= 0.8

    def test_missing_permissions_lower_score(self, tmp_db):
        """Missing companion permissions lower the completeness score."""
        validator = SelfCheckValidator(database=tmp_db)
        original = Policy(
            version="2012-10-17",
            statements=[
                Statement(
                    effect="Allow",
                    actions=["lambda:InvokeFunction"],
                    resources=["*"],
                )
            ],
        )
        rewritten = Policy(
            version="2012-10-17",
            statements=[
                Statement(
                    effect="Allow",
                    actions=["lambda:InvokeFunction"],
                    resources=["*"],
                )
            ],
        )
        result = _make_rewrite_result(
            original_policy=original,
            rewritten_policy=rewritten,
            assumptions=["Test."],
        )
        check_result = validator.run_self_check(result)
        assert check_result.completeness_score < 1.0

"""Unit tests for analyzer module."""

import pytest
import tempfile
from pathlib import Path

from src.sentinel.analyzer import (
    IntentMapper,
    RiskAnalyzer,
    DangerousPermissionChecker,
    CompanionPermissionDetector,
    HITLSystem,
    AccessLevel,
    RiskSeverity,
    IntentMapping,
    RiskFinding,
    CompanionPermission,
    HITLDecision,
)
from src.sentinel.database import Database, Service, Action


@pytest.fixture
def temp_db():
    """Create temporary database for testing."""
    with tempfile.NamedTemporaryFile(suffix='.db', delete=False) as f:
        db_path = Path(f.name)

    yield db_path

    if db_path.exists():
        db_path.unlink()


@pytest.fixture
def database(temp_db):
    """Create and initialize database with sample data."""
    db = Database(temp_db)
    db.create_schema()

    # Add sample services
    db.insert_service(Service(
        service_prefix='s3',
        service_name='Amazon S3'
    ))
    db.insert_service(Service(
        service_prefix='lambda',
        service_name='AWS Lambda'
    ))
    db.insert_service(Service(
        service_prefix='iam',
        service_name='AWS IAM'
    ))

    # Add sample actions
    db.insert_action(Action(
        action_id=None,
        service_prefix='s3',
        action_name='GetObject',
        full_action='s3:GetObject',
        description='Read S3 objects',
        access_level='Read',
        is_read=True
    ))
    db.insert_action(Action(
        action_id=None,
        service_prefix='s3',
        action_name='PutObject',
        full_action='s3:PutObject',
        description='Write S3 objects',
        access_level='Write',
        is_write=True
    ))
    db.insert_action(Action(
        action_id=None,
        service_prefix='s3',
        action_name='ListBucket',
        full_action='s3:ListBucket',
        description='List S3 buckets',
        access_level='List',
        is_list=True
    ))
    db.insert_action(Action(
        action_id=None,
        service_prefix='lambda',
        action_name='InvokeFunction',
        full_action='lambda:InvokeFunction',
        description='Invoke Lambda function',
        access_level='Write',
        is_write=True
    ))
    db.insert_action(Action(
        action_id=None,
        service_prefix='iam',
        action_name='PassRole',
        full_action='iam:PassRole',
        description='Pass role to AWS service',
        access_level='Write',
        is_write=True
    ))
    db.insert_action(Action(
        action_id=None,
        service_prefix='iam',
        action_name='CreatePolicyVersion',
        full_action='iam:CreatePolicyVersion',
        description='Create IAM policy version',
        access_level='Permissions management',
        is_permissions_management=True
    ))

    return db


class TestIntentMapper:
    """Test IntentMapper functionality."""

    def test_map_read_only_intent(self, database):
        """Test mapping read-only intent."""
        mapper = IntentMapper(database)
        result = mapper.map_intent("read-only access to S3")

        assert AccessLevel.READ in result.access_levels
        assert AccessLevel.LIST in result.access_levels
        assert AccessLevel.WRITE not in result.access_levels
        assert 's3' in result.services
        assert result.confidence > 0

    def test_map_read_write_intent(self, database):
        """Test mapping read-write intent."""
        mapper = IntentMapper(database)
        result = mapper.map_intent("read-write access to DynamoDB")

        assert AccessLevel.READ in result.access_levels
        assert AccessLevel.LIST in result.access_levels
        assert AccessLevel.WRITE in result.access_levels

    def test_map_write_only_intent(self, database):
        """Test mapping write-only intent."""
        mapper = IntentMapper(database)
        result = mapper.map_intent("write data to S3")

        assert AccessLevel.WRITE in result.access_levels

    def test_map_list_only_intent(self, database):
        """Test mapping list-only intent."""
        mapper = IntentMapper(database)
        result = mapper.map_intent("list S3 buckets")

        assert AccessLevel.LIST in result.access_levels
        assert 's3' in result.services

    def test_map_admin_intent(self, database):
        """Test mapping admin/full access intent."""
        mapper = IntentMapper(database)
        result = mapper.map_intent("admin access to Lambda")

        assert AccessLevel.READ in result.access_levels
        assert AccessLevel.WRITE in result.access_levels
        assert AccessLevel.PERMISSIONS_MANAGEMENT in result.access_levels
        assert AccessLevel.TAGGING in result.access_levels

    def test_map_deployment_intent(self, database):
        """Test mapping deployment intent."""
        mapper = IntentMapper(database)
        result = mapper.map_intent("deploy Lambda functions")

        assert AccessLevel.WRITE in result.access_levels
        assert AccessLevel.TAGGING in result.access_levels
        assert 'lambda' in result.services

    def test_map_with_database_actions(self, database):
        """Test intent mapping with database action lookup."""
        mapper = IntentMapper(database)
        result = mapper.map_intent("read S3 objects", service_filter=['s3'])

        assert len(result.actions) > 0
        assert any('s3:' in action for action in result.actions)

    def test_map_default_read_only(self, database):
        """Test default to read-only for unknown intent."""
        mapper = IntentMapper(database)
        result = mapper.map_intent("some random text")

        # Should default to read-only for safety
        assert AccessLevel.READ in result.access_levels
        assert AccessLevel.LIST in result.access_levels

    def test_map_multiple_services(self, database):
        """Test intent with multiple services."""
        mapper = IntentMapper(database)
        result = mapper.map_intent("read from S3 and Lambda")

        assert 's3' in result.services
        assert 'lambda' in result.services

    def test_explanation_generation(self, database):
        """Test explanation string generation."""
        mapper = IntentMapper(database)
        result = mapper.map_intent("read-only S3 access")

        assert result.explanation
        assert 'read-only' in result.explanation.lower()


class TestRiskAnalyzer:
    """Test RiskAnalyzer functionality."""

    def test_detect_full_wildcard(self, database):
        """Test detection of full wildcard."""
        analyzer = RiskAnalyzer(database)
        findings = analyzer.analyze_actions(['*'])

        assert len(findings) > 0
        assert any(f.risk_type == 'WILDCARD_ALL_ACTIONS' for f in findings)
        assert any(f.severity == RiskSeverity.CRITICAL for f in findings)

    def test_detect_service_wildcard(self, database):
        """Test detection of service-level wildcard."""
        analyzer = RiskAnalyzer(database)
        findings = analyzer.analyze_actions(['s3:*'])

        assert len(findings) > 0
        assert any(f.risk_type == 'WILDCARD_ACTION' for f in findings)

    def test_detect_iam_wildcard_critical(self, database):
        """Test IAM wildcard gets CRITICAL severity."""
        analyzer = RiskAnalyzer(database)
        findings = analyzer.analyze_actions(['iam:*'])

        wildcard_findings = [f for f in findings if f.risk_type == 'WILDCARD_ACTION']
        assert len(wildcard_findings) > 0
        assert wildcard_findings[0].severity == RiskSeverity.CRITICAL

    def test_detect_privilege_escalation(self, database):
        """Test detection of privilege escalation actions."""
        analyzer = RiskAnalyzer(database)
        findings = analyzer.analyze_actions(['iam:PassRole'])

        assert len(findings) > 0
        assert any(f.risk_type == 'PRIVILEGE_ESCALATION' for f in findings)
        assert any(f.severity == RiskSeverity.HIGH for f in findings)

    def test_detect_multiple_escalation_actions(self, database):
        """Test detection of multiple privilege escalation actions."""
        analyzer = RiskAnalyzer(database)
        actions = [
            'iam:PassRole',
            'iam:CreatePolicyVersion',
            'iam:AttachRolePolicy'
        ]
        findings = analyzer.analyze_actions(actions)

        escalation_findings = [f for f in findings if f.risk_type == 'PRIVILEGE_ESCALATION']
        assert len(escalation_findings) >= 3

    def test_detect_data_exfiltration(self, database):
        """Test detection of data exfiltration risks."""
        analyzer = RiskAnalyzer(database)
        findings = analyzer.analyze_actions(['s3:GetObject'])

        assert len(findings) > 0
        assert any(f.risk_type == 'DATA_EXFILTRATION_RISK' for f in findings)

    def test_detect_secrets_exfiltration(self, database):
        """Test detection of secrets access."""
        analyzer = RiskAnalyzer(database)
        findings = analyzer.analyze_actions(['secretsmanager:GetSecretValue'])

        assert len(findings) > 0
        assert any(f.risk_type == 'DATA_EXFILTRATION_RISK' for f in findings)

    def test_detect_destruction_capability(self, database):
        """Test detection of destruction capabilities."""
        analyzer = RiskAnalyzer(database)
        findings = analyzer.analyze_actions(['s3:DeleteBucket'])

        assert len(findings) > 0
        assert any(f.risk_type == 'DESTRUCTION_CAPABILITY' for f in findings)

    def test_detect_permissions_management(self, database):
        """Test detection of permissions management actions."""
        analyzer = RiskAnalyzer(database)
        findings = analyzer.analyze_actions(['iam:PutUserPolicy'])

        assert len(findings) > 0
        assert any(f.risk_type == 'PERMISSIONS_MANAGEMENT' for f in findings)

    def test_detect_dangerous_combination_lambda(self, database):
        """Test detection of PassRole + Lambda combination."""
        analyzer = RiskAnalyzer(database)
        actions = ['iam:PassRole', 'lambda:CreateFunction']
        findings = analyzer.analyze_actions(actions)

        dangerous_combos = [f for f in findings if f.risk_type == 'DANGEROUS_COMBINATION']
        assert len(dangerous_combos) > 0
        assert any('lambda' in f.description.lower() for f in dangerous_combos)

    def test_detect_dangerous_combination_ec2(self, database):
        """Test detection of PassRole + EC2 combination."""
        analyzer = RiskAnalyzer(database)
        actions = ['iam:PassRole', 'ec2:RunInstances']
        findings = analyzer.analyze_actions(actions)

        dangerous_combos = [f for f in findings if f.risk_type == 'DANGEROUS_COMBINATION']
        assert len(dangerous_combos) > 0
        assert any('ec2' in f.description.lower() for f in dangerous_combos)

    def test_detect_policy_takeover_combination(self, database):
        """Test detection of policy takeover combination."""
        analyzer = RiskAnalyzer(database)
        actions = ['iam:CreatePolicyVersion', 'iam:SetDefaultPolicyVersion']
        findings = analyzer.analyze_actions(actions)

        dangerous_combos = [f for f in findings if f.risk_type == 'DANGEROUS_COMBINATION']
        assert len(dangerous_combos) > 0
        assert any('policy' in f.description.lower() for f in dangerous_combos)

    def test_detect_redundancy_full_wildcard(self, database):
        """Test detection of redundancy with full wildcard."""
        analyzer = RiskAnalyzer(database)
        actions = ['*', 's3:GetObject', 'lambda:InvokeFunction']
        findings = analyzer.analyze_actions(actions)

        redundancy_findings = [f for f in findings if f.risk_type == 'REDUNDANCY']
        assert len(redundancy_findings) > 0

    def test_detect_redundancy_service_wildcard(self, database):
        """Test detection of redundancy with service wildcard."""
        analyzer = RiskAnalyzer(database)
        actions = ['s3:*', 's3:GetObject', 's3:PutObject']
        findings = analyzer.analyze_actions(actions)

        redundancy_findings = [f for f in findings if f.risk_type == 'REDUNDANCY']
        assert len(redundancy_findings) > 0
        assert any('s3' in f.description for f in redundancy_findings)

    def test_no_findings_for_safe_actions(self, database):
        """Test no critical findings for safe actions."""
        analyzer = RiskAnalyzer(database)
        findings = analyzer.analyze_actions(['s3:GetObject', 's3:ListBucket'])

        # Should have some findings but not CRITICAL
        critical_findings = [f for f in findings if f.severity == RiskSeverity.CRITICAL]
        assert len(critical_findings) == 0

    def test_wildcard_severity_assessment(self, database):
        """Test wildcard severity assessment."""
        analyzer = RiskAnalyzer(database)

        # Test different wildcard patterns
        assert analyzer._assess_wildcard_severity('s3:*') == RiskSeverity.HIGH
        assert analyzer._assess_wildcard_severity('s3:Get*') == RiskSeverity.MEDIUM
        assert analyzer._assess_wildcard_severity('iam:*') == RiskSeverity.CRITICAL


class TestDangerousPermissionChecker:
    """Test DangerousPermissionChecker functionality."""

    def test_check_action_with_wildcard_resource(self, database):
        """Test checking action with wildcard resource."""
        checker = DangerousPermissionChecker(database)
        findings = checker.check_action('iam:PassRole', resource='*')

        assert len(findings) > 0
        # Severity should be escalated for wildcard resource
        assert any('wildcard resource' in f.description for f in findings)

    def test_check_action_with_specific_resource(self, database):
        """Test checking action with specific resource."""
        checker = DangerousPermissionChecker(database)
        findings = checker.check_action(
            'iam:PassRole',
            resource='arn:aws:iam::123456789012:role/MyRole'
        )

        assert len(findings) > 0

    def test_severity_escalation(self, database):
        """Test severity escalation logic."""
        checker = DangerousPermissionChecker(database)

        assert checker._escalate_severity(RiskSeverity.INFO) == RiskSeverity.LOW
        assert checker._escalate_severity(RiskSeverity.LOW) == RiskSeverity.MEDIUM
        assert checker._escalate_severity(RiskSeverity.MEDIUM) == RiskSeverity.HIGH
        assert checker._escalate_severity(RiskSeverity.HIGH) == RiskSeverity.CRITICAL
        assert checker._escalate_severity(RiskSeverity.CRITICAL) == RiskSeverity.CRITICAL


class TestCompanionPermissionDetector:
    """Test CompanionPermissionDetector functionality."""

    def test_detect_lambda_logs_missing(self, database):
        """Test detection of missing Lambda CloudWatch Logs permissions."""
        detector = CompanionPermissionDetector(database)
        actions = ['lambda:InvokeFunction']
        missing = detector.detect_missing_companions(actions)

        assert len(missing) > 0
        assert any('logs:' in comp for m in missing for comp in m.companion_actions)

    def test_detect_lambda_logs_present(self, database):
        """Test no missing companions when logs permissions present."""
        detector = CompanionPermissionDetector(database)
        actions = [
            'lambda:InvokeFunction',
            'logs:CreateLogGroup',
            'logs:CreateLogStream',
            'logs:PutLogEvents'
        ]
        missing = detector.detect_missing_companions(actions)

        # Should not flag lambda logs as missing
        lambda_missing = [m for m in missing if m.primary_action == 'lambda:InvokeFunction']
        if lambda_missing:
            # If any companions still missing, they should be the VPC ones
            assert not any('logs:' in comp
                          for m in lambda_missing
                          for comp in m.companion_actions)

    def test_detect_sqs_consumer_missing(self, database):
        """Test detection of missing SQS consumer permissions."""
        detector = CompanionPermissionDetector(database)
        actions = ['sqs:ReceiveMessage']
        missing = detector.detect_missing_companions(actions)

        assert len(missing) > 0
        assert any(m.primary_action == 'sqs:ReceiveMessage' for m in missing)
        # Should include DeleteMessage and other lifecycle actions
        sqs_missing = [m for m in missing if m.primary_action == 'sqs:ReceiveMessage']
        assert any('sqs:DeleteMessage' in m.companion_actions for m in sqs_missing)

    def test_detect_kms_decrypt_missing(self, database):
        """Test detection of missing KMS decrypt permission."""
        detector = CompanionPermissionDetector(database)
        actions = ['s3:GetObject']
        missing = detector.detect_missing_companions(actions)

        assert len(missing) > 0
        # Should suggest kms:Decrypt for encrypted objects
        s3_missing = [m for m in missing if m.primary_action == 's3:GetObject']
        assert any('kms:Decrypt' in m.companion_actions for m in s3_missing)

    def test_suggest_companions_lambda(self, database):
        """Test suggesting companions for Lambda action."""
        detector = CompanionPermissionDetector(database)
        companion = detector.suggest_companions('lambda:InvokeFunction')

        assert companion is not None
        assert 'logs:CreateLogGroup' in companion.companion_actions
        assert companion.primary_action == 'lambda:InvokeFunction'

    def test_suggest_companions_unknown_action(self, database):
        """Test suggesting companions for unknown action."""
        detector = CompanionPermissionDetector(database)
        companion = detector.suggest_companions('unknown:Action')

        assert companion is None

    def test_detect_dynamodb_streams_missing(self, database):
        """Test detection of missing DynamoDB Streams permissions."""
        detector = CompanionPermissionDetector(database)
        actions = ['dynamodb:GetRecords']
        missing = detector.detect_missing_companions(actions)

        assert len(missing) > 0
        streams_missing = [m for m in missing if m.primary_action == 'dynamodb:GetRecords']
        assert len(streams_missing) > 0
        assert any('dynamodb:GetShardIterator' in m.companion_actions
                  for m in streams_missing)

    def test_no_missing_when_all_present(self, database):
        """Test no missing companions when all are present."""
        detector = CompanionPermissionDetector(database)
        actions = [
            'sqs:ReceiveMessage',
            'sqs:DeleteMessage',
            'sqs:GetQueueAttributes',
            'sqs:ChangeMessageVisibility'
        ]
        missing = detector.detect_missing_companions(actions)

        # No SQS companions should be missing
        sqs_missing = [m for m in missing if m.primary_action == 'sqs:ReceiveMessage']
        assert len(sqs_missing) == 0


class TestHITLSystem:
    """Test HITLSystem functionality."""

    def test_flag_tier2_action(self):
        """Test flagging Tier 2 action for review."""
        hitl = HITLSystem()
        assumptions = ["Action is for new AWS service", "Format looks correct"]

        result = hitl.flag_tier2_action('newservice:GetData', assumptions)

        assert result is True  # Default approval for testing
        assert len(hitl.decisions) == 1
        assert hitl.decisions[0].action == 'newservice:GetData'
        assert hitl.decisions[0].tier == 'TIER_2_UNKNOWN'

    def test_record_decision_approved(self):
        """Test recording approved decision."""
        hitl = HITLSystem()
        hitl.record_decision(
            action='unknown:Action',
            tier='TIER_2_UNKNOWN',
            approved=True,
            comment='Looks good to me',
            assumptions=['New service', 'Correct format']
        )

        assert len(hitl.decisions) == 1
        assert hitl.decisions[0].user_approved is True
        assert hitl.decisions[0].user_comment == 'Looks good to me'

    def test_record_decision_rejected(self):
        """Test recording rejected decision."""
        hitl = HITLSystem()
        hitl.record_decision(
            action='invalid:Action',
            tier='TIER_3_INVALID',
            approved=False,
            comment='Invalid format'
        )

        assert len(hitl.decisions) == 1
        assert hitl.decisions[0].user_approved is False

    def test_get_decision_history(self):
        """Test retrieving decision history."""
        hitl = HITLSystem()
        hitl.record_decision('action1', 'TIER_2', True)
        hitl.record_decision('action2', 'TIER_2', False)

        history = hitl.get_decision_history()

        assert len(history) == 2
        assert history[0].action == 'action1'
        assert history[1].action == 'action2'

    def test_get_approval_stats_empty(self):
        """Test approval statistics with no decisions."""
        hitl = HITLSystem()
        stats = hitl.get_approval_stats()

        assert stats['total_reviews'] == 0
        assert stats['approved'] == 0
        assert stats['rejected'] == 0
        assert stats['approval_rate'] == 0.0

    def test_get_approval_stats_with_decisions(self):
        """Test approval statistics with decisions."""
        hitl = HITLSystem()
        hitl.record_decision('action1', 'TIER_2', True)
        hitl.record_decision('action2', 'TIER_2', True)
        hitl.record_decision('action3', 'TIER_2', False)

        stats = hitl.get_approval_stats()

        assert stats['total_reviews'] == 3
        assert stats['approved'] == 2
        assert stats['rejected'] == 1
        assert stats['approval_rate'] == 2.0 / 3.0

    def test_clear_history(self):
        """Test clearing decision history."""
        hitl = HITLSystem()
        hitl.record_decision('action1', 'TIER_2', True)
        hitl.record_decision('action2', 'TIER_2', True)

        assert len(hitl.decisions) == 2

        hitl.clear_history()

        assert len(hitl.decisions) == 0
        stats = hitl.get_approval_stats()
        assert stats['total_reviews'] == 0

    def test_multiple_flag_calls(self):
        """Test multiple flag calls track separately."""
        hitl = HITLSystem()

        hitl.flag_tier2_action('action1', ['assumption1'])
        hitl.flag_tier2_action('action2', ['assumption2'])

        assert len(hitl.decisions) == 2
        assert hitl.decisions[0].action == 'action1'
        assert hitl.decisions[1].action == 'action2'


class TestIntegration:
    """Integration tests combining multiple analyzer components."""

    def test_full_analysis_pipeline(self, database):
        """Test complete analysis pipeline."""
        # Map intent
        mapper = IntentMapper(database)
        intent_result = mapper.map_intent("admin access to Lambda and S3")

        # Analyze risks
        analyzer = RiskAnalyzer(database)
        test_actions = ['lambda:*', 's3:*', 'iam:PassRole']
        risk_findings = analyzer.analyze_actions(test_actions)

        # Check dangerous permissions
        checker = DangerousPermissionChecker(database)
        dangerous_findings = checker.check_action('iam:PassRole', '*')

        # Check companion permissions
        detector = CompanionPermissionDetector(database)
        missing_companions = detector.detect_missing_companions(['lambda:InvokeFunction'])

        # Verify pipeline results
        assert AccessLevel.PERMISSIONS_MANAGEMENT in intent_result.access_levels
        assert len(risk_findings) > 0
        assert len(dangerous_findings) > 0
        assert len(missing_companions) > 0

    def test_intent_to_risk_analysis(self, database):
        """Test intent mapping followed by risk analysis."""
        mapper = IntentMapper(database)
        analyzer = RiskAnalyzer(database)

        # Map deployment intent
        intent = mapper.map_intent("deploy Lambda functions with full access")

        # Analyze suggested actions for risks
        if intent.actions:
            findings = analyzer.analyze_actions(intent.actions)
            # Deployment actions should have some risk findings
            assert isinstance(findings, list)

    def test_companion_detection_with_intent(self, database):
        """Test companion detection based on intent-derived actions."""
        mapper = IntentMapper(database)
        detector = CompanionPermissionDetector(database)

        # Map Lambda intent
        intent = mapper.map_intent("invoke Lambda functions")

        # Check for missing companions
        test_actions = ['lambda:InvokeFunction']
        missing = detector.detect_missing_companions(test_actions)

        # Should detect missing CloudWatch Logs permissions
        assert len(missing) > 0

    def test_hitl_with_risk_findings(self):
        """Test HITL system with risk findings."""
        analyzer = RiskAnalyzer()
        hitl = HITLSystem()

        # Analyze unknown action
        findings = analyzer.analyze_actions(['newservice:GetData'])

        # Flag for HITL review
        approved = hitl.flag_tier2_action(
            'newservice:GetData',
            ['New service', 'Plausible format']
        )

        assert approved is True
        assert len(hitl.decisions) == 1

    def test_comprehensive_policy_analysis(self, database):
        """Test comprehensive analysis of a complete policy."""
        # Simulate a policy with various actions
        policy_actions = [
            's3:*',
            'lambda:InvokeFunction',
            'iam:PassRole',
            'dynamodb:GetItem',
            'kms:Decrypt'
        ]

        # Risk analysis
        analyzer = RiskAnalyzer(database)
        risks = analyzer.analyze_actions(policy_actions)

        # Companion detection
        detector = CompanionPermissionDetector(database)
        missing = detector.detect_missing_companions(policy_actions)

        # Should find risks (wildcards, privilege escalation)
        assert len(risks) > 0
        wildcard_risks = [r for r in risks if r.risk_type == 'WILDCARD_ACTION']
        assert len(wildcard_risks) > 0

        escalation_risks = [r for r in risks if r.risk_type == 'PRIVILEGE_ESCALATION']
        assert len(escalation_risks) > 0

        # Should find missing companions (Lambda logs)
        lambda_missing = [m for m in missing
                         if m.primary_action == 'lambda:InvokeFunction']
        assert len(lambda_missing) > 0

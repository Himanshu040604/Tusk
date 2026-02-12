"""Unit tests for the Policy Rewriter module.

Tests cover wildcard replacement, resource scoping, companion permissions,
condition key injection, statement reorganization, and JSON serialization.
"""

import json
import pytest
import tempfile
from pathlib import Path

from src.sentinel.parser import Policy, Statement
from src.sentinel.rewriter import (
    PolicyRewriter,
    RewriteConfig,
    RewriteResult,
    RewriteChange,
)
from src.sentinel.database import Database, Service, Action
from src.sentinel.inventory import ResourceInventory, Resource


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def tmp_db(tmp_path):
    """Create a temporary IAM actions database with sample data."""
    db_path = tmp_path / "test_iam.db"
    db = Database(db_path)
    db.create_schema()

    # Insert services
    for svc in [
        Service(service_prefix='s3', service_name='Amazon S3'),
        Service(service_prefix='ec2', service_name='Amazon EC2'),
        Service(service_prefix='lambda', service_name='AWS Lambda'),
        Service(service_prefix='iam', service_name='AWS IAM'),
        Service(service_prefix='logs', service_name='CloudWatch Logs'),
        Service(service_prefix='kms', service_name='AWS KMS'),
    ]:
        db.insert_service(svc)

    # Insert S3 actions
    s3_actions = [
        ('GetObject', 'Read', True),
        ('PutObject', 'Write', False),
        ('DeleteObject', 'Write', False),
        ('ListBucket', 'List', True),
        ('GetBucketPolicy', 'Read', True),
        ('PutBucketPolicy', 'Permissions management', False),
        ('GetBucketLocation', 'Read', True),
        ('HeadObject', 'Read', True),
        ('CopyObject', 'Write', False),
        ('CreateMultipartUpload', 'Write', False),
    ]
    for name, level, is_read in s3_actions:
        db.insert_action(Action(
            action_id=None,
            service_prefix='s3',
            action_name=name,
            full_action=f's3:{name}',
            description=f'S3 {name}',
            access_level=level,
            is_list=(level == 'List'),
            is_read=(level == 'Read'),
            is_write=(level == 'Write'),
            is_permissions_management=(level == 'Permissions management'),
        ))

    # Insert EC2 actions
    ec2_actions = [
        ('DescribeInstances', 'List', True, False),
        ('RunInstances', 'Write', False, True),
        ('TerminateInstances', 'Write', False, True),
        ('StartInstances', 'Write', False, True),
        ('StopInstances', 'Write', False, True),
    ]
    for name, level, is_read, is_write in ec2_actions:
        db.insert_action(Action(
            action_id=None,
            service_prefix='ec2',
            action_name=name,
            full_action=f'ec2:{name}',
            description=f'EC2 {name}',
            access_level=level,
            is_list=(level == 'List'),
            is_read=is_read,
            is_write=is_write,
        ))

    # Insert Lambda actions
    for name in ['InvokeFunction', 'CreateFunction', 'UpdateFunctionCode']:
        db.insert_action(Action(
            action_id=None,
            service_prefix='lambda',
            action_name=name,
            full_action=f'lambda:{name}',
            description=f'Lambda {name}',
            access_level='Write',
            is_write=True,
        ))

    # Insert logs actions
    for name in ['CreateLogGroup', 'CreateLogStream', 'PutLogEvents']:
        db.insert_action(Action(
            action_id=None,
            service_prefix='logs',
            action_name=name,
            full_action=f'logs:{name}',
            description=f'Logs {name}',
            access_level='Write',
            is_write=True,
        ))

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
            service_prefix='s3',
            resource_type='bucket',
            resource_arn='arn:aws:s3:::my-app-data',
            resource_name='my-app-data',
            region=None,
            account_id='123456789012',
        ),
        Resource(
            resource_id=None,
            service_prefix='s3',
            resource_type='bucket',
            resource_arn='arn:aws:s3:::my-app-logs',
            resource_name='my-app-logs',
            region=None,
            account_id='123456789012',
        ),
        Resource(
            resource_id=None,
            service_prefix='ec2',
            resource_type='instance',
            resource_arn='arn:aws:ec2:us-east-1:123456789012:instance/i-0123456789abcdef0',
            resource_name='web-server',
            region='us-east-1',
            account_id='123456789012',
        ),
        Resource(
            resource_id=None,
            service_prefix='lambda',
            resource_type='function',
            resource_arn='arn:aws:lambda:us-east-1:123456789012:function:my-function',
            resource_name='my-function',
            region='us-east-1',
            account_id='123456789012',
        ),
    ]
    for r in resources:
        inv.insert_resource(r)

    return inv


@pytest.fixture
def simple_policy():
    """Create a simple test policy."""
    return Policy(
        version='2012-10-17',
        statements=[
            Statement(
                effect='Allow',
                actions=['s3:GetObject', 's3:PutObject'],
                resources=['*'],
            )
        ],
    )


@pytest.fixture
def wildcard_policy():
    """Create a policy with wildcard actions."""
    return Policy(
        version='2012-10-17',
        statements=[
            Statement(
                effect='Allow',
                actions=['s3:*'],
                resources=['*'],
            )
        ],
    )


@pytest.fixture
def full_wildcard_policy():
    """Create a policy with full wildcard."""
    return Policy(
        version='2012-10-17',
        statements=[
            Statement(
                effect='Allow',
                actions=['*'],
                resources=['*'],
            )
        ],
    )


@pytest.fixture
def deny_policy():
    """Create a policy with Deny statement."""
    return Policy(
        version='2012-10-17',
        statements=[
            Statement(
                effect='Allow',
                actions=['s3:GetObject'],
                resources=['*'],
            ),
            Statement(
                effect='Deny',
                actions=['s3:DeleteBucket'],
                resources=['*'],
            ),
        ],
    )


@pytest.fixture
def lambda_policy():
    """Create a Lambda policy (needs companion permissions)."""
    return Policy(
        version='2012-10-17',
        statements=[
            Statement(
                effect='Allow',
                actions=['lambda:InvokeFunction'],
                resources=['*'],
            )
        ],
    )


# ---------------------------------------------------------------------------
# Test PolicyRewriter Initialization
# ---------------------------------------------------------------------------

class TestPolicyRewriterInit:
    """Tests for PolicyRewriter initialization."""

    def test_init_no_args(self):
        """Rewriter can be initialized without database or inventory."""
        rewriter = PolicyRewriter()
        assert rewriter.database is None
        assert rewriter.inventory is None

    def test_init_with_database(self, tmp_db):
        """Rewriter accepts a Database instance."""
        rewriter = PolicyRewriter(database=tmp_db)
        assert rewriter.database is tmp_db

    def test_init_with_inventory(self, tmp_inventory):
        """Rewriter accepts a ResourceInventory instance."""
        rewriter = PolicyRewriter(inventory=tmp_inventory)
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
        assert 's3:GetObject' in actions
        assert 's3:PutObject' in actions

    def test_service_wildcard_expanded(self, tmp_db, wildcard_policy):
        """service:* is expanded to specific actions."""
        rewriter = PolicyRewriter(database=tmp_db)
        result = rewriter.rewrite_policy(wildcard_policy)
        actions = result.rewritten_policy.statements[0].actions
        assert len(actions) > 1
        assert 's3:GetObject' in actions
        assert 's3:PutObject' in actions
        assert 's3:ListBucket' in actions

    def test_wildcard_change_tracked(self, tmp_db, wildcard_policy):
        """Wildcard replacement creates a change record."""
        rewriter = PolicyRewriter(database=tmp_db)
        result = rewriter.rewrite_policy(wildcard_policy)
        wildcard_changes = [
            c for c in result.changes
            if c.change_type == 'WILDCARD_REPLACED'
        ]
        assert len(wildcard_changes) >= 1
        assert wildcard_changes[0].original_value == 's3:*'

    def test_prefix_wildcard_expanded(self, tmp_db):
        """service:Get* is expanded to matching actions."""
        policy = Policy(
            version='2012-10-17',
            statements=[
                Statement(
                    effect='Allow',
                    actions=['s3:Get*'],
                    resources=['*'],
                )
            ],
        )
        rewriter = PolicyRewriter(database=tmp_db)
        result = rewriter.rewrite_policy(policy)
        actions = result.rewritten_policy.statements[0].actions
        assert 's3:GetObject' in actions
        assert 's3:GetBucketPolicy' in actions
        assert 's3:GetBucketLocation' in actions
        assert 's3:PutObject' not in actions

    def test_full_wildcard_without_intent(self, tmp_db, full_wildcard_policy):
        """Full wildcard without intent is kept as-is."""
        rewriter = PolicyRewriter(database=tmp_db)
        result = rewriter.rewrite_policy(full_wildcard_policy)
        actions = result.rewritten_policy.statements[0].actions
        assert '*' in actions

    def test_full_wildcard_with_intent(self, tmp_db, full_wildcard_policy):
        """Full wildcard with intent is expanded based on intent."""
        rewriter = PolicyRewriter(database=tmp_db)
        config = RewriteConfig(intent='read-only s3')
        result = rewriter.rewrite_policy(full_wildcard_policy, config)
        actions = result.rewritten_policy.statements[0].actions
        assert 's3:GetObject' in actions
        assert 's3:ListBucket' in actions
        # Write actions should NOT be included for read-only intent
        assert 's3:PutObject' not in actions
        assert 's3:DeleteObject' not in actions

    def test_wildcard_no_database(self, wildcard_policy):
        """Wildcards kept when no database is available."""
        rewriter = PolicyRewriter()
        result = rewriter.rewrite_policy(wildcard_policy)
        actions = result.rewritten_policy.statements[0].actions
        assert 's3:*' in actions

    def test_no_database_assumption(self, wildcard_policy):
        """Assumption recorded when no database is available."""
        rewriter = PolicyRewriter()
        result = rewriter.rewrite_policy(wildcard_policy)
        assert any('database' in a.lower() for a in result.assumptions)


# ---------------------------------------------------------------------------
# Test Resource Scoping
# ---------------------------------------------------------------------------

class TestResourceScoping:
    """Tests for resource ARN scoping."""

    def test_wildcard_resource_replaced_with_real_arns(
        self, tmp_db, tmp_inventory, simple_policy
    ):
        """Wildcard resource replaced with real ARNs from inventory."""
        rewriter = PolicyRewriter(
            database=tmp_db, inventory=tmp_inventory
        )
        result = rewriter.rewrite_policy(simple_policy)
        resources = result.rewritten_policy.statements[0].resources
        assert '*' not in resources
        assert any('my-app-data' in r for r in resources)

    def test_wildcard_resource_placeholder_no_inventory(
        self, tmp_db, simple_policy
    ):
        """Placeholder ARN generated when no inventory available."""
        rewriter = PolicyRewriter(database=tmp_db)
        config = RewriteConfig(
            account_id='111222333444', region='eu-west-1'
        )
        result = rewriter.rewrite_policy(simple_policy, config)
        resources = result.rewritten_policy.statements[0].resources
        assert '*' not in resources
        assert any('PLACEHOLDER' in r for r in resources)

    def test_non_wildcard_resource_preserved(self, tmp_db):
        """Non-wildcard resources are not modified."""
        policy = Policy(
            version='2012-10-17',
            statements=[
                Statement(
                    effect='Allow',
                    actions=['s3:GetObject'],
                    resources=['arn:aws:s3:::my-bucket/*'],
                )
            ],
        )
        rewriter = PolicyRewriter(database=tmp_db)
        result = rewriter.rewrite_policy(policy)
        resources = result.rewritten_policy.statements[0].resources
        assert 'arn:aws:s3:::my-bucket/*' in resources

    def test_arn_scoped_change_tracked(
        self, tmp_db, tmp_inventory, simple_policy
    ):
        """Resource scoping creates a change record."""
        rewriter = PolicyRewriter(
            database=tmp_db, inventory=tmp_inventory
        )
        result = rewriter.rewrite_policy(simple_policy)
        arn_changes = [
            c for c in result.changes if c.change_type == 'ARN_SCOPED'
        ]
        assert len(arn_changes) >= 1

    def test_no_inventory_assumption(self, simple_policy):
        """Assumption recorded when no inventory is available."""
        rewriter = PolicyRewriter()
        result = rewriter.rewrite_policy(simple_policy)
        assert any('inventory' in a.lower() for a in result.assumptions)


# ---------------------------------------------------------------------------
# Test Deny Statement Preservation
# ---------------------------------------------------------------------------

class TestDenyPreservation:
    """Tests for Deny statement preservation."""

    def test_deny_preserved(self, tmp_db, deny_policy):
        """Deny statements are preserved unchanged."""
        rewriter = PolicyRewriter(database=tmp_db)
        result = rewriter.rewrite_policy(deny_policy)
        deny_stmts = [
            s for s in result.rewritten_policy.statements
            if s.effect == 'Deny'
        ]
        assert len(deny_stmts) == 1
        assert deny_stmts[0].actions == ['s3:DeleteBucket']
        assert deny_stmts[0].resources == ['*']

    def test_deny_not_preserved_when_disabled(self, tmp_db, deny_policy):
        """Deny statements processed when preservation disabled."""
        rewriter = PolicyRewriter(database=tmp_db)
        config = RewriteConfig(preserve_deny_statements=False)
        result = rewriter.rewrite_policy(deny_policy, config)
        deny_stmts = [
            s for s in result.rewritten_policy.statements
            if s.effect == 'Deny'
        ]
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
        assert 'logs:CreateLogGroup' in all_actions
        assert 'logs:CreateLogStream' in all_actions
        assert 'logs:PutLogEvents' in all_actions

    def test_companion_change_tracked(self, tmp_db, lambda_policy):
        """Companion addition creates a change record."""
        rewriter = PolicyRewriter(database=tmp_db)
        result = rewriter.rewrite_policy(lambda_policy)
        companion_changes = [
            c for c in result.changes
            if c.change_type == 'COMPANION_ADDED'
        ]
        assert len(companion_changes) >= 1

    def test_companions_not_added_when_disabled(self, tmp_db, lambda_policy):
        """Companions not added when config disables them."""
        rewriter = PolicyRewriter(database=tmp_db)
        config = RewriteConfig(add_companions=False)
        result = rewriter.rewrite_policy(lambda_policy, config)
        all_actions = []
        for stmt in result.rewritten_policy.statements:
            all_actions.extend(stmt.actions)
        assert 'logs:CreateLogGroup' not in all_actions

    def test_companions_recorded_in_result(self, tmp_db, lambda_policy):
        """Companion permissions appear in result.companion_permissions_added."""
        rewriter = PolicyRewriter(database=tmp_db)
        result = rewriter.rewrite_policy(lambda_policy)
        assert len(result.companion_permissions_added) >= 1
        assert result.companion_permissions_added[0].primary_action == (
            'lambda:InvokeFunction'
        )

    def test_existing_companions_not_duplicated(self, tmp_db):
        """Already-present companion actions are not added again."""
        policy = Policy(
            version='2012-10-17',
            statements=[
                Statement(
                    effect='Allow',
                    actions=[
                        'lambda:InvokeFunction',
                        'logs:CreateLogGroup',
                        'logs:CreateLogStream',
                        'logs:PutLogEvents',
                    ],
                    resources=['*'],
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
        config = RewriteConfig(region='us-east-1')
        result = rewriter.rewrite_policy(simple_policy, config)
        stmt = result.rewritten_policy.statements[0]
        assert stmt.conditions is not None
        assert stmt.conditions['StringEquals']['aws:RequestedRegion'] == (
            'us-east-1'
        )

    def test_s3_encryption_condition_added(self, tmp_db):
        """S3 encryption condition added for PutObject."""
        policy = Policy(
            version='2012-10-17',
            statements=[
                Statement(
                    effect='Allow',
                    actions=['s3:PutObject'],
                    resources=['arn:aws:s3:::my-bucket/*'],
                )
            ],
        )
        rewriter = PolicyRewriter(database=tmp_db)
        config = RewriteConfig(add_conditions=True)
        result = rewriter.rewrite_policy(policy, config)
        stmt = result.rewritten_policy.statements[0]
        assert stmt.conditions is not None
        assert 's3:x-amz-server-side-encryption' in (
            stmt.conditions.get('StringEquals', {})
        )

    def test_source_account_condition_added(self, tmp_db):
        """Source account condition added for cross-service actions."""
        policy = Policy(
            version='2012-10-17',
            statements=[
                Statement(
                    effect='Allow',
                    actions=['lambda:InvokeFunction'],
                    resources=['*'],
                )
            ],
        )
        rewriter = PolicyRewriter(database=tmp_db)
        config = RewriteConfig(account_id='123456789012')
        result = rewriter.rewrite_policy(policy, config)
        # Find the statement with lambda:InvokeFunction
        for stmt in result.rewritten_policy.statements:
            if 'lambda:InvokeFunction' in stmt.actions:
                assert stmt.conditions is not None
                assert stmt.conditions['StringEquals'][
                    'aws:SourceAccount'
                ] == '123456789012'
                break

    def test_conditions_not_added_when_disabled(self, tmp_db, simple_policy):
        """Conditions not added when disabled in config."""
        rewriter = PolicyRewriter(database=tmp_db)
        config = RewriteConfig(
            add_conditions=False, region='us-east-1'
        )
        result = rewriter.rewrite_policy(simple_policy, config)
        stmt = result.rewritten_policy.statements[0]
        assert stmt.conditions is None

    def test_existing_conditions_preserved(self, tmp_db):
        """Existing conditions are preserved and merged."""
        policy = Policy(
            version='2012-10-17',
            statements=[
                Statement(
                    effect='Allow',
                    actions=['s3:GetObject'],
                    resources=['*'],
                    conditions={
                        'StringEquals': {
                            'aws:PrincipalOrgID': 'o-123456'
                        }
                    },
                )
            ],
        )
        rewriter = PolicyRewriter(database=tmp_db)
        config = RewriteConfig(region='us-east-1')
        result = rewriter.rewrite_policy(policy, config)
        stmt = result.rewritten_policy.statements[0]
        assert stmt.conditions['StringEquals']['aws:PrincipalOrgID'] == (
            'o-123456'
        )
        assert 'aws:RequestedRegion' in stmt.conditions['StringEquals']

    def test_condition_change_tracked(self, tmp_db, simple_policy):
        """Condition injection creates a change record."""
        rewriter = PolicyRewriter(database=tmp_db)
        config = RewriteConfig(region='us-east-1')
        result = rewriter.rewrite_policy(simple_policy, config)
        condition_changes = [
            c for c in result.changes
            if c.change_type == 'CONDITION_ADDED'
        ]
        assert len(condition_changes) >= 1

    def test_global_service_no_region_condition(self, tmp_db):
        """Global services (IAM) do not get region restriction."""
        policy = Policy(
            version='2012-10-17',
            statements=[
                Statement(
                    effect='Allow',
                    actions=['iam:GetUser'],
                    resources=['*'],
                )
            ],
        )
        rewriter = PolicyRewriter(database=tmp_db)
        config = RewriteConfig(region='us-east-1')
        result = rewriter.rewrite_policy(policy, config)
        stmt = result.rewritten_policy.statements[0]
        # IAM is global, should not have region restriction
        if stmt.conditions:
            assert 'aws:RequestedRegion' not in (
                stmt.conditions.get('StringEquals', {})
            )


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
        actions = [f's3:{name}' for name in [
            'GetObject', 'PutObject', 'DeleteObject', 'ListBucket',
            'GetBucketPolicy', 'PutBucketPolicy', 'GetBucketLocation',
            'HeadObject', 'CopyObject', 'CreateMultipartUpload',
        ]]
        # Add more to exceed max_actions_per_statement
        actions.extend([
            'ec2:DescribeInstances', 'ec2:RunInstances',
            'ec2:TerminateInstances', 'ec2:StartInstances',
            'ec2:StopInstances', 'lambda:InvokeFunction',
        ])
        policy = Policy(
            version='2012-10-17',
            statements=[
                Statement(
                    effect='Allow',
                    actions=actions,
                    resources=['*'],
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
                assert re.match(r'^[A-Za-z0-9]+$', stmt.sid), (
                    f"Invalid Sid: {stmt.sid}"
                )


# ---------------------------------------------------------------------------
# Test NotAction / NotResource Handling
# ---------------------------------------------------------------------------

class TestNotActionNotResource:
    """Tests for NotAction and NotResource handling."""

    def test_not_action_preserved(self, tmp_db):
        """NotAction statements preserved with warning."""
        policy = Policy(
            version='2012-10-17',
            statements=[
                Statement(
                    effect='Allow',
                    actions=[],
                    resources=['*'],
                    not_actions=['iam:*'],
                )
            ],
        )
        rewriter = PolicyRewriter(database=tmp_db)
        result = rewriter.rewrite_policy(policy)
        assert result.rewritten_policy.statements[0].not_actions == ['iam:*']
        assert any('NotAction' in w for w in result.warnings)

    def test_not_resource_preserved(self, tmp_db):
        """NotResource statements preserved with warning."""
        policy = Policy(
            version='2012-10-17',
            statements=[
                Statement(
                    effect='Allow',
                    actions=['s3:*'],
                    resources=[],
                    not_resources=['arn:aws:s3:::sensitive-bucket'],
                )
            ],
        )
        rewriter = PolicyRewriter(database=tmp_db)
        result = rewriter.rewrite_policy(policy)
        assert result.rewritten_policy.statements[0].not_resources == [
            'arn:aws:s3:::sensitive-bucket'
        ]
        assert any('NotResource' in w for w in result.warnings)


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
        assert json_output['Version'] == '2012-10-17'
        assert 'Statement' in json_output
        assert len(json_output['Statement']) >= 1

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
            version='2012-10-17',
            statements=[
                Statement(
                    effect='Allow',
                    actions=['s3:GetObject'],
                    resources=['arn:aws:s3:::my-bucket/*'],
                )
            ],
        )
        rewriter = PolicyRewriter(database=tmp_db)
        config = RewriteConfig(add_conditions=False, add_companions=False)
        result = rewriter.rewrite_policy(policy, config)
        json_output = rewriter.to_policy_json(result.rewritten_policy)
        stmt = json_output['Statement'][0]
        assert isinstance(stmt['Action'], str)
        assert isinstance(stmt['Resource'], str)

    def test_to_policy_json_conditions_included(self, tmp_db):
        """Conditions included in JSON output."""
        policy = Policy(
            version='2012-10-17',
            statements=[
                Statement(
                    effect='Allow',
                    actions=['s3:GetObject'],
                    resources=['*'],
                    conditions={
                        'StringEquals': {'aws:PrincipalOrgID': 'o-123'}
                    },
                )
            ],
        )
        rewriter = PolicyRewriter(database=tmp_db)
        config = RewriteConfig(add_conditions=False)
        result = rewriter.rewrite_policy(policy, config)
        json_output = rewriter.to_policy_json(result.rewritten_policy)
        stmt = json_output['Statement'][0]
        assert 'Condition' in stmt
        assert stmt['Condition']['StringEquals']['aws:PrincipalOrgID'] == (
            'o-123'
        )

    def test_to_policy_json_sid_included(self, tmp_db, simple_policy):
        """Sid included in JSON output."""
        rewriter = PolicyRewriter(database=tmp_db)
        result = rewriter.rewrite_policy(simple_policy)
        json_output = rewriter.to_policy_json(result.rewritten_policy)
        stmt = json_output['Statement'][0]
        assert 'Sid' in stmt

    def test_to_policy_json_with_not_action(self, tmp_db):
        """NotAction serialized correctly."""
        policy = Policy(
            version='2012-10-17',
            statements=[
                Statement(
                    effect='Allow',
                    actions=[],
                    resources=['*'],
                    not_actions=['iam:*'],
                )
            ],
        )
        rewriter = PolicyRewriter(database=tmp_db)
        result = rewriter.rewrite_policy(policy)
        json_output = rewriter.to_policy_json(result.rewritten_policy)
        stmt = json_output['Statement'][0]
        assert 'NotAction' in stmt
        assert 'Action' not in stmt


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

    def test_result_has_assumptions(self):
        """Result contains assumptions when database missing."""
        rewriter = PolicyRewriter()
        policy = Policy(
            version='2012-10-17',
            statements=[
                Statement(
                    effect='Allow', actions=['s3:*'], resources=['*']
                )
            ],
        )
        result = rewriter.rewrite_policy(policy)
        assert len(result.assumptions) > 0

    def test_intent_assumption_recorded(self, tmp_db, simple_policy):
        """Intent recorded in assumptions."""
        rewriter = PolicyRewriter(database=tmp_db)
        config = RewriteConfig(intent='read-only s3 access')
        result = rewriter.rewrite_policy(simple_policy, config)
        assert any('read-only s3 access' in a for a in result.assumptions)


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
        assert config.placeholder_format == 'PLACEHOLDER'

    def test_config_no_mutation(self, tmp_db, simple_policy):
        """Rewriting with default config works without error."""
        rewriter = PolicyRewriter(database=tmp_db)
        result = rewriter.rewrite_policy(simple_policy)
        assert result.rewritten_policy is not None

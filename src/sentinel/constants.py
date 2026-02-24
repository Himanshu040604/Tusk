"""Shared constants for IAM Policy Sentinel.

Single source of truth for values used across parser, analyzer, rewriter,
inventory, database, and self_check modules.  This module has zero imports
from other sentinel modules to prevent circular dependencies.
"""

import json
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple

# ---------------------------------------------------------------------------
# CLI exit codes
# ---------------------------------------------------------------------------

EXIT_SUCCESS: int = 0
EXIT_ISSUES_FOUND: int = 1
EXIT_INVALID_ARGS: int = 2
EXIT_IO_ERROR: int = 3

# ---------------------------------------------------------------------------
# Default file paths
# ---------------------------------------------------------------------------

DEFAULT_DB_PATH: str = "data/iam_actions.db"
DEFAULT_INVENTORY_PATH: str = "data/resource_inventory.db"

# ---------------------------------------------------------------------------
# Schema & default placeholders
# ---------------------------------------------------------------------------

SCHEMA_VERSION: str = "1.0"
DEFAULT_ACCOUNT_ID: str = "123456789012"
DEFAULT_REGION: str = "us-east-1"

# ---------------------------------------------------------------------------
# Action classification prefixes
# ---------------------------------------------------------------------------

READ_PREFIXES: Tuple[str, ...] = (
    'Get', 'Describe', 'List', 'Head', 'Batch',
)

WRITE_PREFIXES: Tuple[str, ...] = (
    'Put', 'Create', 'Update', 'Delete', 'Remove',
    'Terminate', 'Run', 'Start', 'Stop', 'Send',
    'Publish', 'Invoke', 'Execute',
)

ADMIN_PREFIXES: Tuple[str, ...] = (
    'Attach', 'Detach', 'SetDefault', 'UpdateAssumeRole',
)

# ---------------------------------------------------------------------------
# Intent keywords
# ---------------------------------------------------------------------------

READ_INTENT_KEYWORDS: Tuple[str, ...] = (
    'read-only', 'read only', 'readonly', 'view', 'get',
)

WRITE_INTENT_KEYWORDS: Tuple[str, ...] = (
    'write', 'modify', 'update', 'create', 'manage',
)

# ---------------------------------------------------------------------------
# Service categorization
# ---------------------------------------------------------------------------

SECURITY_CRITICAL_SERVICES: Set[str] = {
    'iam', 'sts', 'organizations', 'kms',
}

REGION_LESS_GLOBAL_SERVICES: Set[str] = {
    'iam', 'sts', 'organizations', 'cloudfront', 'route53',
}

# ---------------------------------------------------------------------------
# Service name mappings  (keyword -> service prefix)
#
# Merged from analyzer.py (22 entries) and rewriter.py (9 entries).
# ---------------------------------------------------------------------------

SERVICE_NAME_MAPPINGS: Dict[str, str] = {
    's3': 's3',
    'bucket': 's3',
    'object storage': 's3',
    'ec2': 'ec2',
    'instance': 'ec2',
    'compute': 'ec2',
    'lambda': 'lambda',
    'function': 'lambda',
    'dynamodb': 'dynamodb',
    'dynamo': 'dynamodb',
    'table': 'dynamodb',
    'rds': 'rds',
    'database': 'rds',
    'iam': 'iam',
    'role': 'iam',
    'user': 'iam',
    'sqs': 'sqs',
    'queue': 'sqs',
    'sns': 'sns',
    'topic': 'sns',
    'kms': 'kms',
    'key': 'kms',
    'secrets': 'secretsmanager',
    'secret': 'secretsmanager',
    'cloudwatch': 'logs',
    'logs': 'logs',
}

# ---------------------------------------------------------------------------
# Known AWS service prefixes  (expanded from 56 -> ~150)
#
# Organised by category for readability.
# ---------------------------------------------------------------------------

_HARDCODED_SERVICES: Set[str] = {
    # -- Compute --
    's3', 'ec2', 'lambda', 'ecs', 'ecr', 'eks', 'fargate',
    'elasticbeanstalk', 'batch', 'lightsail', 'autoscaling',
    'autoscaling-plans', 'imagebuilder', 'compute-optimizer',
    'elasticloadbalancing', 'app-mesh', 'apprunner',

    # -- Storage --
    'ebs', 'efs', 's3-outposts', 'fsx', 'storagegateway',
    'backup', 'dlm',

    # -- Database --
    'dynamodb', 'rds', 'redshift', 'elasticache', 'neptune',
    'docdb-elastic', 'dax', 'memorydb', 'timestream',
    'qldb', 'keyspaces', 'dms',

    # -- Networking --
    'vpc', 'route53', 'route53resolver', 'cloudfront',
    'apigateway', 'execute-api', 'appsync', 'directconnect',
    'globalaccelerator', 'networkmanager', 'network-firewall',
    'servicediscovery', 'transitgateway',

    # -- Security, Identity, Compliance --
    'iam', 'sts', 'organizations', 'kms', 'secretsmanager',
    'acm', 'acm-pca', 'waf', 'wafv2', 'shield',
    'guardduty', 'inspector', 'inspector2', 'macie', 'macie2',
    'cognito-idp', 'cognito-identity', 'sso', 'sso-admin',
    'ram', 'securityhub', 'access-analyzer', 'detective',
    'fms', 'artifact', 'auditmanager', 'identitystore',
    'verifiedpermissions',

    # -- Management & Governance --
    'cloudformation', 'cloudwatch', 'logs', 'events',
    'ssm', 'config', 'cloudtrail', 'servicecatalog',
    'health', 'trustedadvisor', 'resource-groups',
    'tag', 'license-manager', 'account', 'controltower',
    'wellarchitected', 'chatbot', 'support', 'ce',
    'budgets', 'cur',

    # -- Messaging & Integration --
    'sqs', 'sns', 'ses', 'sesv2', 'pinpoint',
    'connect', 'chime', 'mq', 'kafka',
    'states', 'swf', 'scheduler',

    # -- Analytics --
    'kinesis', 'firehose', 'athena', 'emr', 'emr-serverless',
    'glue', 'databrew', 'lakeformation', 'quicksight',
    'opensearch', 'opensearchserverless', 'datapipeline',
    'msk',

    # -- Application Integration --
    'stepfunctions', 'eventbridge', 'pipes',
    'appflow', 'mwaa',

    # -- Developer Tools --
    'codebuild', 'codedeploy', 'codepipeline', 'codecommit',
    'codestar', 'codestar-connections', 'codeartifact',
    'codeguru-reviewer', 'codeguru-profiler', 'xray',
    'cloud9', 'proton',

    # -- Machine Learning --
    'sagemaker', 'comprehend', 'rekognition', 'transcribe',
    'translate', 'polly', 'lex', 'personalize', 'forecast',
    'textract', 'bedrock', 'lookoutmetrics',

    # -- IoT --
    'iot', 'iot-data', 'iotanalytics', 'iotevents',
    'iotsitewise', 'greengrass',

    # -- Media Services --
    'mediaconvert', 'mediapackage', 'medialive',
    'mediastore', 'elastictranscoder',

    # -- Migration --
    'mgn', 'datasync', 'transfer',

    # -- Business Applications --
    'workspaces', 'workmail', 'workdocs',
    'appstream',
}

# Path to JSON data file (project root / data / known_services.json)
_JSON_PATH: Path = (
    Path(__file__).resolve().parent.parent.parent / "data" / "known_services.json"
)


def load_known_services(json_path: Optional[Path] = None) -> Set[str]:
    """Load known AWS service prefixes from JSON file with hardcoded fallback.

    Args:
        json_path: Override path to JSON file (for testing). Defaults to
            ``data/known_services.json`` relative to project root.

    Returns:
        Set of service prefix strings.
    """
    path = json_path or _JSON_PATH
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        services = data.get("services", [])
        if not isinstance(services, list) or not services:
            return set(_HARDCODED_SERVICES)
        return set(services)
    except (FileNotFoundError, json.JSONDecodeError, OSError, KeyError, TypeError):
        return set(_HARDCODED_SERVICES)


KNOWN_SERVICES: Set[str] = load_known_services()

# ---------------------------------------------------------------------------
# Companion permission rules  (expanded from 7 -> 22)
#
# Format: action -> (companion_actions, reason, severity_string)
# Plain tuples so this module has zero sentinel imports.
# analyzer.py converts to CompanionPermission objects at class-definition time.
# ---------------------------------------------------------------------------

COMPANION_PERMISSION_RULES: Dict[str, Tuple[List[str], str, str]] = {
    # -- Original 7 rules (preserved exactly) --

    'lambda:InvokeFunction': (
        [
            'logs:CreateLogGroup',
            'logs:CreateLogStream',
            'logs:PutLogEvents',
        ],
        'Lambda functions require CloudWatch Logs permissions to write execution logs',
        'MEDIUM',
    ),
    'lambda:CreateFunction': (
        [
            'logs:CreateLogGroup',
            'logs:CreateLogStream',
            'logs:PutLogEvents',
            'ec2:CreateNetworkInterface',
            'ec2:DescribeNetworkInterfaces',
            'ec2:DeleteNetworkInterface',
        ],
        'Lambda functions require CloudWatch Logs permissions to write execution logs. '
        'Lambda functions in VPC require EC2 network interface permissions.',
        'HIGH',
    ),
    's3:GetObject': (
        ['kms:Decrypt'],
        'Reading KMS-encrypted S3 objects requires kms:Decrypt permission',
        'MEDIUM',
    ),
    's3:PutObject': (
        ['kms:GenerateDataKey', 'kms:Decrypt'],
        'Writing KMS-encrypted S3 objects requires KMS key generation',
        'MEDIUM',
    ),
    'sqs:ReceiveMessage': (
        [
            'sqs:DeleteMessage',
            'sqs:GetQueueAttributes',
            'sqs:ChangeMessageVisibility',
        ],
        'SQS consumers need permissions for complete message processing lifecycle',
        'MEDIUM',
    ),
    'dynamodb:GetRecords': (
        [
            'dynamodb:GetShardIterator',
            'dynamodb:DescribeStream',
            'dynamodb:ListStreams',
        ],
        'DynamoDB Streams processing requires stream discovery and iteration',
        'MEDIUM',
    ),
    'ec2:TerminateInstances': (
        ['ec2:DeleteVolume', 'ec2:DetachVolume'],
        'Instance termination may require volume cleanup permissions',
        'LOW',
    ),

    # -- 15 new rules --

    'ecs:RunTask': (
        [
            'iam:PassRole',
            'logs:CreateLogGroup',
            'logs:CreateLogStream',
            'logs:PutLogEvents',
        ],
        'ECS tasks require IAM PassRole for task/execution roles and CloudWatch Logs for logging',
        'HIGH',
    ),
    'glue:StartJobRun': (
        [
            'iam:PassRole',
            'logs:CreateLogGroup',
            'logs:CreateLogStream',
            'logs:PutLogEvents',
        ],
        'Glue jobs require IAM PassRole for the job role and CloudWatch Logs for output',
        'HIGH',
    ),
    'states:StartExecution': (
        ['iam:PassRole'],
        'Step Functions executions require IAM PassRole for the state machine role',
        'MEDIUM',
    ),
    'cloudformation:CreateStack': (
        ['iam:PassRole', 'cloudformation:DescribeStacks'],
        'CloudFormation stack creation requires IAM PassRole for the stack role '
        'and DescribeStacks to monitor progress',
        'HIGH',
    ),
    'cloudformation:UpdateStack': (
        ['iam:PassRole', 'cloudformation:DescribeStacks'],
        'CloudFormation stack updates require IAM PassRole and DescribeStacks',
        'HIGH',
    ),
    'sns:Publish': (
        ['kms:GenerateDataKey', 'kms:Decrypt'],
        'Publishing to KMS-encrypted SNS topics requires KMS permissions',
        'MEDIUM',
    ),
    'firehose:PutRecord': (
        ['firehose:PutRecordBatch'],
        'Firehose producers typically need both PutRecord and PutRecordBatch',
        'LOW',
    ),
    'rds:CreateDBSnapshot': (
        ['rds:DescribeDBInstances'],
        'Creating DB snapshots requires DescribeDBInstances to identify the target',
        'LOW',
    ),
    'secretsmanager:GetSecretValue': (
        ['kms:Decrypt'],
        'Retrieving KMS-encrypted secrets requires kms:Decrypt',
        'MEDIUM',
    ),
    'ssm:GetParameter': (
        ['kms:Decrypt'],
        'Retrieving encrypted SSM parameters requires kms:Decrypt',
        'MEDIUM',
    ),
    'ssm:GetParameters': (
        ['kms:Decrypt'],
        'Retrieving encrypted SSM parameters requires kms:Decrypt',
        'MEDIUM',
    ),
    'events:PutRule': (
        ['iam:PassRole', 'events:PutTargets'],
        'EventBridge rules require IAM PassRole for target invocation and PutTargets',
        'MEDIUM',
    ),
    'batch:SubmitJob': (
        ['iam:PassRole', 'logs:CreateLogGroup', 'logs:CreateLogStream', 'logs:PutLogEvents'],
        'AWS Batch jobs require IAM PassRole for job role and CloudWatch Logs',
        'HIGH',
    ),
    'emr:RunJobFlow': (
        ['iam:PassRole', 'ec2:AuthorizeSecurityGroupIngress'],
        'EMR clusters require IAM PassRole for service/instance roles and EC2 security group access',
        'HIGH',
    ),
    'athena:StartQueryExecution': (
        ['s3:GetBucketLocation', 's3:GetObject', 's3:ListBucket', 's3:PutObject'],
        'Athena queries require S3 permissions for reading data and writing results',
        'MEDIUM',
    ),
}

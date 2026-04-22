"""Seed classification tables from shipped baseline constants (Task 4).

Populates the tables introduced in migrations 0002–0008 from the Python
constants that previously lived in ``analyzer.py`` / ``rewriter.py`` /
``constants.py``.  Invoked in two contexts:

1. **First run of a newly-migrated DB** — bootstrap so ``RiskAnalyzer``
   finds rows to bulk-load at ``__init__`` time.
2. **``sentinel refresh --source shipped``** — re-seeds baseline rows
   (source-partitioned truncate-and-reload per § 6.4).

All rows are HMAC-signed via ``hmac_keys.sign_row()`` with the K_db
sub-key.  All writes happen inside a ``BEGIN IMMEDIATE`` transaction —
safe because WAL mode is already active by Task 5.

``source`` column values must match the CHECK constraints in § 6.1:
``'policy_sentry' | 'aws-docs' | 'shipped' | 'managed-policies' |
'cloudsplaining'``.  This module uses ``'shipped'`` for the baseline
content that ships with the source tree.
"""

from __future__ import annotations

import re
import sqlite3
from datetime import datetime, timezone
from pathlib import Path

from .hmac_keys import sign_row

SOURCE_SHIPPED = "shipped"

# ---------------------------------------------------------------------------
# Shipped baseline content (§ 12 Phase 2 Task 4 / Task 8).
#
# These live here — not in analyzer.py — because the seeder is the designated
# "shipped" source (source column = 'shipped' per § 6.1 CHECK constraint).
# Task 8 bans value-bearing constants from the HOT-PATH modules (analyzer,
# rewriter, inventory, constants).  seed_data.py is the seeding module and
# explicitly exempt — its whole role is to materialise this data into DB rows.
# ---------------------------------------------------------------------------

_BASELINE_PRIVILEGE_ESCALATION_ACTIONS: tuple[str, ...] = (
    "iam:PassRole",
    "iam:CreatePolicyVersion",
    "iam:SetDefaultPolicyVersion",
    "iam:AttachUserPolicy",
    "iam:AttachGroupPolicy",
    "iam:AttachRolePolicy",
    "iam:PutUserPolicy",
    "iam:PutGroupPolicy",
    "iam:PutRolePolicy",
    "iam:AddUserToGroup",
    "iam:UpdateAssumeRolePolicy",
    "iam:CreateAccessKey",
    "iam:CreateLoginProfile",
    "sts:AssumeRole",
    "lambda:UpdateFunctionCode",
    "lambda:CreateFunction",
    "lambda:InvokeFunction",
    "glue:CreateDevEndpoint",
    "glue:UpdateDevEndpoint",
    "cloudformation:CreateStack",
    "cloudformation:UpdateStack",
    "datapipeline:CreatePipeline",
    "datapipeline:PutPipelineDefinition",
)

_BASELINE_DATA_EXFILTRATION_PATTERNS: tuple[tuple[str, str], ...] = (
    (r"^s3:GetObject[A-Za-z]*$", "S3 object read access"),
    (r"^secretsmanager:GetSecretValue$", "Secrets Manager access"),
    (r"^ssm:GetParameter[A-Za-z]*$", "SSM Parameter Store access"),
    (r"^rds:CopyDBSnapshot$", "RDS snapshot copy"),
    (r"^rds:CreateDBSnapshot$", "RDS snapshot creation"),
    (r"^ec2:CreateSnapshot$", "EC2 snapshot creation"),
    (r"^dynamodb:GetItem$", "DynamoDB item read"),
    (r"^kms:Decrypt$", "KMS decryption"),
)

_BASELINE_DESTRUCTION_PATTERNS: tuple[tuple[str, str], ...] = (
    (r"^[a-z0-9\-]+:Delete[A-Z][A-Za-z]*$", "Deletion capability"),
    (r"^[a-z0-9\-]+:Terminate[A-Z][A-Za-z]*$", "Termination capability"),
    (r"^[a-z0-9\-]+:Drop[A-Z][A-Za-z]*$", "Drop capability"),
    (r"^[a-z0-9\-]+:Destroy[A-Z][A-Za-z]*$", "Destruction capability"),
    (r"^s3:DeleteBucket$", "S3 bucket deletion"),
    (r"^dynamodb:DeleteTable$", "DynamoDB table deletion"),
    (r"^rds:DeleteDB[A-Za-z]*$", "RDS database deletion"),
    (r"^ec2:TerminateInstances$", "EC2 instance termination"),
)

_BASELINE_PERMISSIONS_MGMT_PATTERNS: tuple[tuple[str, str], ...] = (
    (r"^[a-z0-9\-]+:Put[A-Za-z]*Policy[A-Za-z]*$", "Policy modification"),
    (r"^[a-z0-9\-]+:Attach[A-Za-z]*Policy[A-Za-z]*$", "Policy attachment"),
    (r"^[a-z0-9\-]+:UpdateAssumeRolePolicy$", "Trust policy modification"),
    (r"^[a-z0-9\-]+:CreatePolicy[A-Za-z]*$", "Policy creation"),
    (r"^[a-z0-9\-]+:SetDefaultPolicyVersion$", "Policy version modification"),
)

# Companion permission rules (22 entries).  Format:
#   primary_action -> (companion_actions, reason, severity_string)
# Migrated from constants.py in Task 8 — this is the shipped-baseline
# source written into the `companion_rules` DB table with source='shipped'.
_BASELINE_COMPANION_RULES: dict[str, tuple[list[str], str, str]] = {
    "lambda:InvokeFunction": (
        ["logs:CreateLogGroup", "logs:CreateLogStream", "logs:PutLogEvents"],
        "Lambda functions require CloudWatch Logs permissions to write execution logs",
        "MEDIUM",
    ),
    "lambda:CreateFunction": (
        [
            "logs:CreateLogGroup",
            "logs:CreateLogStream",
            "logs:PutLogEvents",
            "ec2:CreateNetworkInterface",
            "ec2:DescribeNetworkInterfaces",
            "ec2:DeleteNetworkInterface",
        ],
        "Lambda functions require CloudWatch Logs permissions to write execution logs. "
        "Lambda functions in VPC require EC2 network interface permissions.",
        "HIGH",
    ),
    "s3:GetObject": (
        ["kms:Decrypt"],
        "Reading KMS-encrypted S3 objects requires kms:Decrypt permission",
        "MEDIUM",
    ),
    "s3:PutObject": (
        ["kms:GenerateDataKey", "kms:Decrypt"],
        "Writing KMS-encrypted S3 objects requires KMS key generation",
        "MEDIUM",
    ),
    "sqs:ReceiveMessage": (
        ["sqs:DeleteMessage", "sqs:GetQueueAttributes", "sqs:ChangeMessageVisibility"],
        "SQS consumers need permissions for complete message processing lifecycle",
        "MEDIUM",
    ),
    "dynamodb:GetRecords": (
        ["dynamodb:GetShardIterator", "dynamodb:DescribeStream", "dynamodb:ListStreams"],
        "DynamoDB Streams processing requires stream discovery and iteration",
        "MEDIUM",
    ),
    "ec2:TerminateInstances": (
        ["ec2:DeleteVolume", "ec2:DetachVolume"],
        "Instance termination may require volume cleanup permissions",
        "LOW",
    ),
    "ecs:RunTask": (
        ["iam:PassRole", "logs:CreateLogGroup", "logs:CreateLogStream", "logs:PutLogEvents"],
        "ECS tasks require IAM PassRole for task/execution roles and CloudWatch Logs for logging",
        "HIGH",
    ),
    "glue:StartJobRun": (
        ["iam:PassRole", "logs:CreateLogGroup", "logs:CreateLogStream", "logs:PutLogEvents"],
        "Glue jobs require IAM PassRole for the job role and CloudWatch Logs for output",
        "HIGH",
    ),
    "states:StartExecution": (
        ["iam:PassRole"],
        "Step Functions executions require IAM PassRole for the state machine role",
        "MEDIUM",
    ),
    "cloudformation:CreateStack": (
        ["iam:PassRole", "cloudformation:DescribeStacks"],
        "CloudFormation stack creation requires IAM PassRole for the stack role "
        "and DescribeStacks to monitor progress",
        "HIGH",
    ),
    "cloudformation:UpdateStack": (
        ["iam:PassRole", "cloudformation:DescribeStacks"],
        "CloudFormation stack updates require IAM PassRole and DescribeStacks",
        "HIGH",
    ),
    "sns:Publish": (
        ["kms:GenerateDataKey", "kms:Decrypt"],
        "Publishing to KMS-encrypted SNS topics requires KMS permissions",
        "MEDIUM",
    ),
    "firehose:PutRecord": (
        ["firehose:PutRecordBatch"],
        "Firehose producers typically need both PutRecord and PutRecordBatch",
        "LOW",
    ),
    "rds:CreateDBSnapshot": (
        ["rds:DescribeDBInstances"],
        "Creating DB snapshots requires DescribeDBInstances to identify the target",
        "LOW",
    ),
    "secretsmanager:GetSecretValue": (
        ["kms:Decrypt"],
        "Retrieving KMS-encrypted secrets requires kms:Decrypt",
        "MEDIUM",
    ),
    "ssm:GetParameter": (
        ["kms:Decrypt"],
        "Retrieving encrypted SSM parameters requires kms:Decrypt",
        "MEDIUM",
    ),
    "ssm:GetParameters": (
        ["kms:Decrypt"],
        "Retrieving encrypted SSM parameters requires kms:Decrypt",
        "MEDIUM",
    ),
    "events:PutRule": (
        ["iam:PassRole", "events:PutTargets"],
        "EventBridge rules require IAM PassRole for target invocation and PutTargets",
        "MEDIUM",
    ),
    "batch:SubmitJob": (
        ["iam:PassRole", "logs:CreateLogGroup", "logs:CreateLogStream", "logs:PutLogEvents"],
        "AWS Batch jobs require IAM PassRole for job role and CloudWatch Logs",
        "HIGH",
    ),
    "emr:RunJobFlow": (
        ["iam:PassRole", "ec2:AuthorizeSecurityGroupIngress"],
        "EMR clusters require IAM PassRole for service/instance roles and EC2 security group access",
        "HIGH",
    ),
    "athena:StartQueryExecution": (
        ["s3:GetBucketLocation", "s3:GetObject", "s3:ListBucket", "s3:PutObject"],
        "Athena queries require S3 permissions for reading data and writing results",
        "MEDIUM",
    ),
}

# Action -> resource-type mapping (27 entries).  Migrated from
# inventory.ACTION_RESOURCE_MAP in Task 8.  Written into the
# `action_resource_map` DB table with source='shipped'.
_BASELINE_ACTION_RESOURCE_MAP: dict[str, str] = {
    "s3:GetObject": "object",
    "s3:PutObject": "object",
    "s3:DeleteObject": "object",
    "s3:ListBucket": "bucket",
    "s3:GetBucketPolicy": "bucket",
    "s3:PutBucketPolicy": "bucket",
    "ec2:RunInstances": "instance",
    "ec2:TerminateInstances": "instance",
    "ec2:DescribeInstances": "instance",
    "lambda:InvokeFunction": "function",
    "lambda:CreateFunction": "function",
    "lambda:UpdateFunctionCode": "function",
    "dynamodb:GetItem": "table",
    "dynamodb:PutItem": "table",
    "dynamodb:DeleteItem": "table",
    "dynamodb:Query": "table",
    "dynamodb:Scan": "table",
    "sqs:SendMessage": "queue",
    "sqs:ReceiveMessage": "queue",
    "sqs:DeleteMessage": "queue",
    "sns:Publish": "topic",
    "sns:Subscribe": "topic",
    "kms:Decrypt": "key",
    "kms:Encrypt": "key",
    "kms:GenerateDataKey": "key",
    "rds:DescribeDBInstances": "db",
    "secretsmanager:GetSecretValue": "secret",
}

# Service-prefix -> ARN template (10 entries).  Migrated from
# inventory.ARN_TEMPLATES in Task 8.  Templates use named placeholders:
# {region}, {account_id}, {resource_type}, {resource_name}, {resource_id}.
_BASELINE_ARN_TEMPLATES: dict[str, str] = {
    "s3": "arn:aws:s3:::{resource_name}",
    "ec2": "arn:aws:ec2:{region}:{account_id}:{resource_type}/{resource_id}",
    "lambda": "arn:aws:lambda:{region}:{account_id}:function:{resource_name}",
    "dynamodb": "arn:aws:dynamodb:{region}:{account_id}:table/{resource_name}",
    "sqs": "arn:aws:sqs:{region}:{account_id}:{resource_name}",
    "sns": "arn:aws:sns:{region}:{account_id}:{resource_name}",
    "kms": "arn:aws:kms:{region}:{account_id}:key/{resource_id}",
    "iam": "arn:aws:iam::{account_id}:{resource_type}/{resource_name}",
    "rds": "arn:aws:rds:{region}:{account_id}:db:{resource_name}",
    "secretsmanager": "arn:aws:secretsmanager:{region}:{account_id}:secret:{resource_name}",
}


def _now_iso() -> str:
    """Return a CURRENT_TIMESTAMP-comparable ISO-8601 UTC string."""
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")


def _validate_regex(pattern: str, where: str) -> None:
    """Fail-fast regex validation (H1 ReDoS mitigation for DB-stored patterns)."""
    try:
        re.compile(pattern)
    except re.error as e:
        raise ValueError(f"Invalid regex at {where}: {pattern!r}: {e}") from e


def seed_dangerous_actions(conn: sqlite3.Connection) -> int:
    """Truncate-and-reload ``dangerous_actions`` from shipped baseline.

    Source rows derive from the ``_BASELINE_*`` module-level tuples in
    this file (moved here from analyzer.py in Task 8).  Four categories:
    privilege_escalation (literal action list), exfiltration,
    destruction, permissions_mgmt (regex -> description tuples).

    Returns:
        Number of rows inserted.
    """
    now = _now_iso()
    rows: list[tuple] = []

    # Category 1: privilege_escalation (literal action list)
    for action in _BASELINE_PRIVILEGE_ESCALATION_ACTIONS:
        data = {
            "severity": "HIGH",
            "description": "Known privilege escalation vector",
            "source": SOURCE_SHIPPED,
            "refreshed_at": now,
        }
        row_hmac = sign_row(
            "dangerous_actions",
            (action, "privilege_escalation"),
            data,
        )
        rows.append(
            (
                action,
                "privilege_escalation",
                data["severity"],
                data["description"],
                data["source"],
                now,
                row_hmac,
            )
        )

    # Categories 2–4: regex patterns stored as the action_name key
    # (bulk-load pattern: RiskAnalyzer.__init__ compiles + matches).
    pattern_groups = (
        ("exfiltration", _BASELINE_DATA_EXFILTRATION_PATTERNS),
        ("destruction", _BASELINE_DESTRUCTION_PATTERNS),
        ("permissions_mgmt", _BASELINE_PERMISSIONS_MGMT_PATTERNS),
    )
    for category, patterns in pattern_groups:
        for pattern, description in patterns:
            _validate_regex(pattern, f"dangerous_actions[{category}]")
            severity = "HIGH" if category != "destruction" else "MEDIUM"
            data = {
                "severity": severity,
                "description": description,
                "source": SOURCE_SHIPPED,
                "refreshed_at": now,
            }
            row_hmac = sign_row(
                "dangerous_actions", (pattern, category), data
            )
            rows.append(
                (pattern, category, severity, description, SOURCE_SHIPPED, now, row_hmac)
            )

    conn.execute(
        "DELETE FROM dangerous_actions WHERE source = ?",
        (SOURCE_SHIPPED,),
    )
    conn.executemany(
        "INSERT OR IGNORE INTO dangerous_actions "
        "(action_name, category, severity, description, source, refreshed_at, row_hmac) "
        "VALUES (?, ?, ?, ?, ?, ?, ?)",
        rows,
    )
    return len(rows)


def seed_companion_rules(conn: sqlite3.Connection) -> int:
    """Truncate-and-reload ``companion_rules`` from the shipped baseline."""
    now = _now_iso()
    rows: list[tuple] = []
    for primary, (companions, reason, severity) in _BASELINE_COMPANION_RULES.items():
        for companion in companions:
            data = {
                "reason": reason,
                "severity": severity,
                "source": SOURCE_SHIPPED,
                "refreshed_at": now,
            }
            row_hmac = sign_row(
                "companion_rules", (primary, companion), data
            )
            rows.append(
                (primary, companion, reason, severity, SOURCE_SHIPPED, now, row_hmac)
            )

    conn.execute(
        "DELETE FROM companion_rules WHERE source = ?", (SOURCE_SHIPPED,)
    )
    conn.executemany(
        "INSERT OR IGNORE INTO companion_rules "
        "(primary_action, companion_action, reason, severity, source, refreshed_at, row_hmac) "
        "VALUES (?, ?, ?, ?, ?, ?, ?)",
        rows,
    )
    return len(rows)


def seed_action_resource_map(conn: sqlite3.Connection) -> int:
    """Seed ``action_resource_map`` from the shipped baseline dict.

    NOT HMAC-signed (Theme G1 — simple membership lookup).
    """
    rows = list(_BASELINE_ACTION_RESOURCE_MAP.items())
    conn.executemany(
        "INSERT OR IGNORE INTO action_resource_map (action_name, resource_type) "
        "VALUES (?, ?)",
        rows,
    )
    return len(rows)


def seed_arn_templates(conn: sqlite3.Connection) -> int:
    """Seed ``arn_templates`` from the shipped baseline dict.

    NOT HMAC-signed.  Templates are keyed by service_prefix only in the
    shipped data; the DB schema's (service_prefix, resource_type)
    composite PK uses an empty resource_type for these service-wide
    templates — PolicyRewriter's bulk-load prefers the {svc}:{rt}
    composite when present and falls back to the bare-service entry.
    """
    rows = [(svc, "", template) for svc, template in _BASELINE_ARN_TEMPLATES.items()]
    conn.executemany(
        "INSERT OR IGNORE INTO arn_templates "
        "(service_prefix, resource_type, arn_template) VALUES (?, ?, ?)",
        rows,
    )
    return len(rows)


def seed_all_baseline(db_path: Path) -> dict[str, int]:
    """Seed every baseline table from shipped constants.

    Executes inside a single ``BEGIN IMMEDIATE`` transaction (M16 — safe
    because WAL mode is active by Task 5).  On failure, the transaction
    rolls back and no partial state is visible.

    Returns:
        Dict mapping table name to row count inserted.
    """
    conn = sqlite3.connect(str(db_path))
    try:
        conn.execute("BEGIN IMMEDIATE")
        counts = {
            "dangerous_actions": seed_dangerous_actions(conn),
            "companion_rules": seed_companion_rules(conn),
            "action_resource_map": seed_action_resource_map(conn),
            "arn_templates": seed_arn_templates(conn),
        }
        conn.commit()
        return counts
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


__all__ = [
    "SOURCE_SHIPPED",
    "seed_all_baseline",
    "seed_dangerous_actions",
    "seed_companion_rules",
    "seed_action_resource_map",
    "seed_arn_templates",
]

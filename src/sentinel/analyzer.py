"""Risk analysis engine for IAM Policy Sentinel.

This module provides intent mapping, risk detection, dangerous permission checking,
companion permission detection, and human-in-the-loop validation system.
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import List, Dict, Set, Optional, Tuple, Any
import re


class AccessLevel(Enum):
    """IAM access level categories."""
    LIST = "List"
    READ = "Read"
    WRITE = "Write"
    PERMISSIONS_MANAGEMENT = "Permissions management"
    TAGGING = "Tagging"


class RiskSeverity(Enum):
    """Risk severity levels."""
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


@dataclass
class IntentMapping:
    """Result of intent-to-access-level mapping.

    Attributes:
        original_intent: Original developer intent string
        access_levels: Set of mapped access levels
        services: Set of service prefixes to filter (empty = all services)
        actions: List of specific action names matching intent
        confidence: Mapping confidence score (0.0-1.0)
        explanation: Human-readable explanation of mapping
    """
    original_intent: str
    access_levels: Set[AccessLevel]
    services: Set[str] = field(default_factory=set)
    actions: List[str] = field(default_factory=list)
    confidence: float = 1.0
    explanation: str = ""


@dataclass
class RiskFinding:
    """Risk analysis finding.

    Attributes:
        risk_type: Type of risk detected
        severity: Risk severity level
        action: Action causing the risk
        description: Human-readable description
        remediation: Suggested remediation steps
        additional_context: Additional context information
    """
    risk_type: str
    severity: RiskSeverity
    action: str
    description: str
    remediation: str
    additional_context: Dict[str, Any] = field(default_factory=dict)


@dataclass
class CompanionPermission:
    """Companion permission requirement.

    Attributes:
        primary_action: Primary action requiring companion permissions
        companion_actions: List of required companion actions
        reason: Why these companions are needed
        severity: Severity if companions are missing
    """
    primary_action: str
    companion_actions: List[str]
    reason: str
    severity: RiskSeverity = RiskSeverity.MEDIUM


@dataclass
class HITLDecision:
    """Human-in-the-loop decision record.

    Attributes:
        action: Action flagged for review
        tier: Validation tier (typically TIER_2)
        user_approved: Whether user approved the action
        user_comment: Optional user comment
        assumptions_validated: List of assumptions user validated
    """
    action: str
    tier: str
    user_approved: bool
    user_comment: Optional[str] = None
    assumptions_validated: List[str] = field(default_factory=list)


class IntentMapper:
    """Maps developer intent to IAM access levels and actions.

    Translates natural language intent descriptions into specific
    access levels and action sets for policy generation.
    """

    # Intent keyword mappings
    INTENT_KEYWORDS = {
        # Read-only patterns
        "read-only": {AccessLevel.LIST, AccessLevel.READ},
        "read": {AccessLevel.LIST, AccessLevel.READ},
        "get": {AccessLevel.LIST, AccessLevel.READ},
        "describe": {AccessLevel.LIST, AccessLevel.READ},
        "view": {AccessLevel.LIST, AccessLevel.READ},
        "fetch": {AccessLevel.LIST, AccessLevel.READ},
        "retrieve": {AccessLevel.LIST, AccessLevel.READ},

        # Read-write patterns
        "read-write": {AccessLevel.LIST, AccessLevel.READ, AccessLevel.WRITE},
        "modify": {AccessLevel.LIST, AccessLevel.READ, AccessLevel.WRITE},
        "update": {AccessLevel.LIST, AccessLevel.READ, AccessLevel.WRITE},
        "manage": {AccessLevel.LIST, AccessLevel.READ, AccessLevel.WRITE},

        # Write-only patterns
        "write-only": {AccessLevel.WRITE},
        "write": {AccessLevel.WRITE},
        "create": {AccessLevel.WRITE},
        "put": {AccessLevel.WRITE},
        "upload": {AccessLevel.WRITE},
        "insert": {AccessLevel.WRITE},

        # List-only patterns
        "list-only": {AccessLevel.LIST},
        "list": {AccessLevel.LIST},
        "enumerate": {AccessLevel.LIST},

        # Admin/Full access patterns
        "admin": {AccessLevel.LIST, AccessLevel.READ, AccessLevel.WRITE,
                  AccessLevel.PERMISSIONS_MANAGEMENT, AccessLevel.TAGGING},
        "full": {AccessLevel.LIST, AccessLevel.READ, AccessLevel.WRITE,
                 AccessLevel.PERMISSIONS_MANAGEMENT, AccessLevel.TAGGING},
        "full-access": {AccessLevel.LIST, AccessLevel.READ, AccessLevel.WRITE,
                        AccessLevel.PERMISSIONS_MANAGEMENT, AccessLevel.TAGGING},

        # Deployment patterns
        "deploy": {AccessLevel.WRITE, AccessLevel.TAGGING},
        "ci/cd": {AccessLevel.WRITE, AccessLevel.TAGGING},
        "deployment": {AccessLevel.WRITE, AccessLevel.TAGGING},

        # Tagging patterns
        "tag": {AccessLevel.TAGGING},
        "tagging": {AccessLevel.TAGGING},

        # Permissions management patterns
        "permissions": {AccessLevel.PERMISSIONS_MANAGEMENT},
        "policy": {AccessLevel.PERMISSIONS_MANAGEMENT},
        "policy-management": {AccessLevel.PERMISSIONS_MANAGEMENT},
    }

    def __init__(self, database=None):
        """Initialize intent mapper.

        Args:
            database: Optional Database instance for querying actions
        """
        self.database = database

    def map_intent(self, intent: str, service_filter: Optional[List[str]] = None) -> IntentMapping:
        """Map developer intent to access levels and actions.

        Args:
            intent: Natural language intent description
            service_filter: Optional list of service prefixes to filter

        Returns:
            IntentMapping with access levels and matching actions
        """
        intent_lower = intent.lower().strip()

        # Extract access levels from intent
        access_levels = self._extract_access_levels(intent_lower)

        # Extract service hints from intent
        services = self._extract_services(intent_lower)
        if service_filter:
            services.update(service_filter)

        # Query database for matching actions if available
        actions = []
        confidence = 1.0

        if self.database and access_levels:
            actions = self._query_actions_by_access_levels(access_levels, services)
            # Lower confidence if no actions found
            if not actions:
                confidence = 0.7

        explanation = self._generate_explanation(intent, access_levels, services, actions)

        return IntentMapping(
            original_intent=intent,
            access_levels=access_levels,
            services=services,
            actions=actions,
            confidence=confidence,
            explanation=explanation
        )

    def _extract_access_levels(self, intent_lower: str) -> Set[AccessLevel]:
        """Extract access levels from intent string.

        Args:
            intent_lower: Lowercase intent string

        Returns:
            Set of AccessLevel enums
        """
        access_levels = set()

        # Check each keyword pattern
        for keyword, levels in self.INTENT_KEYWORDS.items():
            if keyword in intent_lower:
                access_levels.update(levels)

        # If no keywords matched, default to read-only for safety
        if not access_levels:
            access_levels = {AccessLevel.LIST, AccessLevel.READ}

        return access_levels

    def _extract_services(self, intent_lower: str) -> Set[str]:
        """Extract AWS service hints from intent string.

        Args:
            intent_lower: Lowercase intent string

        Returns:
            Set of service prefix strings
        """
        services = set()

        # Common service name mappings
        service_mappings = {
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

        for keyword, service in service_mappings.items():
            if keyword in intent_lower:
                services.add(service)

        return services

    def _query_actions_by_access_levels(
        self,
        access_levels: Set[AccessLevel],
        services: Set[str]
    ) -> List[str]:
        """Query database for actions matching access levels.

        Args:
            access_levels: Set of access levels to match
            services: Set of service prefixes to filter (empty = all)

        Returns:
            List of action names (service:action format)
        """
        if not self.database:
            return []

        actions = []

        # Build filter conditions based on access levels
        filters = []
        if AccessLevel.LIST in access_levels:
            filters.append("is_list = 1")
        if AccessLevel.READ in access_levels:
            filters.append("is_read = 1")
        if AccessLevel.WRITE in access_levels:
            filters.append("is_write = 1")
        if AccessLevel.PERMISSIONS_MANAGEMENT in access_levels:
            filters.append("is_permissions_management = 1")
        if AccessLevel.TAGGING in access_levels:
            filters.append("is_tagging_only = 1")

        if not filters:
            return []

        # Query database using parameterized queries to prevent SQL injection
        with self.database.get_connection() as conn:
            cursor = conn.cursor()

            where_clause = f"({' OR '.join(filters)})"
            params = []
            if services:
                placeholders = ','.join('?' for _ in services)
                where_clause += f" AND service_prefix IN ({placeholders})"
                params.extend(sorted(services))

            query = f"""
                SELECT service_prefix, action_name
                FROM actions
                WHERE {where_clause}
                ORDER BY service_prefix, action_name
            """

            cursor.execute(query, params)
            actions = [f"{row['service_prefix']}:{row['action_name']}"
                      for row in cursor.fetchall()]

        return actions

    def _generate_explanation(
        self,
        intent: str,
        access_levels: Set[AccessLevel],
        services: Set[str],
        actions: List[str]
    ) -> str:
        """Generate human-readable explanation of mapping.

        Args:
            intent: Original intent
            access_levels: Mapped access levels
            services: Detected services
            actions: Matched actions

        Returns:
            Explanation string
        """
        parts = [f"Intent '{intent}' mapped to:"]

        level_names = sorted([level.value for level in access_levels])
        parts.append(f"Access levels: {', '.join(level_names)}")

        if services:
            parts.append(f"Services: {', '.join(sorted(services))}")

        if actions:
            parts.append(f"Found {len(actions)} matching actions")

        return " | ".join(parts)


class RiskAnalyzer:
    """Analyzes IAM policies for security risks.

    Detects wildcards, privilege escalation paths, dangerous permissions,
    and other security issues in IAM policies.
    """

    # Privilege escalation actions
    PRIVILEGE_ESCALATION_ACTIONS = {
        'iam:PassRole',
        'iam:CreatePolicyVersion',
        'iam:SetDefaultPolicyVersion',
        'iam:AttachUserPolicy',
        'iam:AttachGroupPolicy',
        'iam:AttachRolePolicy',
        'iam:PutUserPolicy',
        'iam:PutGroupPolicy',
        'iam:PutRolePolicy',
        'iam:AddUserToGroup',
        'iam:UpdateAssumeRolePolicy',
        'iam:CreateAccessKey',
        'iam:CreateLoginProfile',
        'sts:AssumeRole',
        'lambda:UpdateFunctionCode',
        'lambda:CreateFunction',
        'lambda:InvokeFunction',
        'glue:CreateDevEndpoint',
        'glue:UpdateDevEndpoint',
        'cloudformation:CreateStack',
        'cloudformation:UpdateStack',
        'datapipeline:CreatePipeline',
        'datapipeline:PutPipelineDefinition',
    }

    # Data exfiltration patterns
    DATA_EXFILTRATION_PATTERNS = [
        (r's3:GetObject.*', 'S3 object read access'),
        (r'secretsmanager:GetSecretValue.*', 'Secrets Manager access'),
        (r'ssm:GetParameter.*', 'SSM Parameter Store access'),
        (r'rds:CopyDBSnapshot', 'RDS snapshot copy'),
        (r'rds:CreateDBSnapshot', 'RDS snapshot creation'),
        (r'ec2:CreateSnapshot', 'EC2 snapshot creation'),
        (r'dynamodb:GetItem', 'DynamoDB item read'),
        (r'kms:Decrypt', 'KMS decryption'),
    ]

    # Infrastructure destruction patterns
    DESTRUCTION_PATTERNS = [
        (r'.*:Delete.*', 'Deletion capability'),
        (r'.*:Terminate.*', 'Termination capability'),
        (r'.*:Drop.*', 'Drop capability'),
        (r'.*:Destroy.*', 'Destruction capability'),
        (r's3:DeleteBucket', 'S3 bucket deletion'),
        (r'dynamodb:DeleteTable', 'DynamoDB table deletion'),
        (r'rds:DeleteDB.*', 'RDS database deletion'),
        (r'ec2:TerminateInstances', 'EC2 instance termination'),
    ]

    # Permissions management patterns
    PERMISSIONS_MGMT_PATTERNS = [
        (r'.*:Put.*Policy.*', 'Policy modification'),
        (r'.*:Attach.*Policy.*', 'Policy attachment'),
        (r'.*:UpdateAssumeRolePolicy', 'Trust policy modification'),
        (r'.*:CreatePolicy.*', 'Policy creation'),
        (r'.*:SetDefaultPolicyVersion', 'Policy version modification'),
    ]

    def __init__(self, database=None):
        """Initialize risk analyzer.

        Args:
            database: Optional Database instance for action validation
        """
        self.database = database

    def analyze_actions(self, actions: List[str]) -> List[RiskFinding]:
        """Analyze list of actions for security risks.

        Args:
            actions: List of IAM action names

        Returns:
            List of RiskFinding objects
        """
        findings = []

        for action in actions:
            # Check wildcards
            findings.extend(self._check_wildcards(action))

            # Check privilege escalation
            findings.extend(self._check_privilege_escalation(action))

            # Check data exfiltration
            findings.extend(self._check_data_exfiltration(action))

            # Check destruction capability
            findings.extend(self._check_destruction(action))

            # Check permissions management
            findings.extend(self._check_permissions_management(action))

        # Check for dangerous combinations
        findings.extend(self._check_dangerous_combinations(actions))

        # Check for cross-statement redundancy
        findings.extend(self._check_redundancy(actions))

        return findings

    def _check_wildcards(self, action: str) -> List[RiskFinding]:
        """Check for wildcard usage and assess severity.

        Args:
            action: IAM action name

        Returns:
            List of RiskFinding objects
        """
        findings = []

        if action == '*' or action == '*:*':
            findings.append(RiskFinding(
                risk_type="WILDCARD_ALL_ACTIONS",
                severity=RiskSeverity.CRITICAL,
                action=action,
                description="Full wildcard grants ALL AWS permissions across ALL services",
                remediation="Replace with specific actions or service-level wildcards (e.g., s3:*)",
                additional_context={'wildcard_type': 'full'}
            ))
        elif '*' in action:
            severity = self._assess_wildcard_severity(action)
            findings.append(RiskFinding(
                risk_type="WILDCARD_ACTION",
                severity=severity,
                action=action,
                description=f"Wildcard action grants multiple permissions: {action}",
                remediation="Replace with specific actions to follow least privilege",
                additional_context={'wildcard_type': 'partial', 'pattern': action}
            ))

        return findings

    def _assess_wildcard_severity(self, action: str) -> RiskSeverity:
        """Assess severity of wildcard action.

        Args:
            action: Wildcard action pattern

        Returns:
            RiskSeverity level
        """
        # service:* is HIGH severity
        if action.endswith(':*'):
            service = action.split(':')[0]
            # Critical services get CRITICAL severity
            if service in ['iam', 'sts', 'organizations', 'kms']:
                return RiskSeverity.CRITICAL
            return RiskSeverity.HIGH

        # Prefix/suffix wildcards are MEDIUM severity
        if action.endswith('*') or action.startswith('*'):
            return RiskSeverity.MEDIUM

        return RiskSeverity.LOW

    def _check_privilege_escalation(self, action: str) -> List[RiskFinding]:
        """Check for privilege escalation actions.

        Args:
            action: IAM action name

        Returns:
            List of RiskFinding objects
        """
        findings = []

        if action in self.PRIVILEGE_ESCALATION_ACTIONS:
            findings.append(RiskFinding(
                risk_type="PRIVILEGE_ESCALATION",
                severity=RiskSeverity.HIGH,
                action=action,
                description=f"Action {action} can be used for privilege escalation",
                remediation="Add strict conditions (e.g., resource ARNs, tags) to limit scope",
                additional_context={'escalation_action': action}
            ))

        return findings

    def _check_data_exfiltration(self, action: str) -> List[RiskFinding]:
        """Check for data exfiltration risks.

        Args:
            action: IAM action name

        Returns:
            List of RiskFinding objects
        """
        findings = []

        for pattern, description in self.DATA_EXFILTRATION_PATTERNS:
            if re.match(pattern, action):
                # Check if it's a wildcard on sensitive action
                severity = RiskSeverity.MEDIUM
                if '*' in action and ('Secret' in action or 's3:GetObject' in action):
                    severity = RiskSeverity.HIGH

                findings.append(RiskFinding(
                    risk_type="DATA_EXFILTRATION_RISK",
                    severity=severity,
                    action=action,
                    description=f"{description}: {action}",
                    remediation="Add resource-level constraints and conditions to limit data access",
                    additional_context={'pattern': description}
                ))
                break

        return findings

    def _check_destruction(self, action: str) -> List[RiskFinding]:
        """Check for infrastructure destruction capabilities.

        Args:
            action: IAM action name

        Returns:
            List of RiskFinding objects
        """
        findings = []

        for pattern, description in self.DESTRUCTION_PATTERNS:
            if re.match(pattern, action):
                severity = RiskSeverity.MEDIUM
                # Critical resources get higher severity
                if any(svc in action for svc in ['rds:DeleteDB', 's3:DeleteBucket',
                                                   'dynamodb:DeleteTable']):
                    severity = RiskSeverity.HIGH

                findings.append(RiskFinding(
                    risk_type="DESTRUCTION_CAPABILITY",
                    severity=severity,
                    action=action,
                    description=f"{description}: {action}",
                    remediation="Add MFA condition or restrict to specific resources",
                    additional_context={'pattern': description}
                ))
                break

        return findings

    def _check_permissions_management(self, action: str) -> List[RiskFinding]:
        """Check for permissions management actions.

        Args:
            action: IAM action name

        Returns:
            List of RiskFinding objects
        """
        findings = []

        for pattern, description in self.PERMISSIONS_MGMT_PATTERNS:
            if re.match(pattern, action):
                findings.append(RiskFinding(
                    risk_type="PERMISSIONS_MANAGEMENT",
                    severity=RiskSeverity.HIGH,
                    action=action,
                    description=f"{description}: {action}",
                    remediation="Restrict to specific resources and add approval workflow",
                    additional_context={'pattern': description}
                ))
                break

        return findings

    def _check_dangerous_combinations(self, actions: List[str]) -> List[RiskFinding]:
        """Check for dangerous permission combinations.

        Args:
            actions: List of IAM action names

        Returns:
            List of RiskFinding objects
        """
        findings = []
        action_set = set(actions)

        # iam:PassRole + lambda:CreateFunction = privilege escalation
        if 'iam:PassRole' in action_set and 'lambda:CreateFunction' in action_set:
            findings.append(RiskFinding(
                risk_type="DANGEROUS_COMBINATION",
                severity=RiskSeverity.CRITICAL,
                action="iam:PassRole + lambda:CreateFunction",
                description="Combination allows privilege escalation via Lambda execution role",
                remediation="Separate these permissions or add strict resource constraints",
                additional_context={
                    'combination': ['iam:PassRole', 'lambda:CreateFunction'],
                    'escalation_path': 'Lambda role assumption'
                }
            ))

        # iam:PassRole + ec2:RunInstances = privilege escalation
        if 'iam:PassRole' in action_set and 'ec2:RunInstances' in action_set:
            findings.append(RiskFinding(
                risk_type="DANGEROUS_COMBINATION",
                severity=RiskSeverity.CRITICAL,
                action="iam:PassRole + ec2:RunInstances",
                description="Combination allows privilege escalation via EC2 instance profile",
                remediation="Add conditions to restrict role ARNs and instance types",
                additional_context={
                    'combination': ['iam:PassRole', 'ec2:RunInstances'],
                    'escalation_path': 'EC2 instance profile'
                }
            ))

        # iam:CreatePolicyVersion + iam:SetDefaultPolicyVersion = policy takeover
        if 'iam:CreatePolicyVersion' in action_set and 'iam:SetDefaultPolicyVersion' in action_set:
            findings.append(RiskFinding(
                risk_type="DANGEROUS_COMBINATION",
                severity=RiskSeverity.CRITICAL,
                action="iam:CreatePolicyVersion + iam:SetDefaultPolicyVersion",
                description="Combination allows complete policy takeover",
                remediation="Separate permissions or add strict resource ARN constraints",
                additional_context={
                    'combination': ['iam:CreatePolicyVersion', 'iam:SetDefaultPolicyVersion'],
                    'escalation_path': 'Policy version manipulation'
                }
            ))

        return findings

    def _check_redundancy(self, actions: List[str]) -> List[RiskFinding]:
        """Check for redundant or overlapping actions.

        Args:
            actions: List of IAM action names

        Returns:
            List of RiskFinding objects
        """
        findings = []

        # Check if wildcard makes specific actions redundant
        wildcards = [a for a in actions if '*' in a]
        specific = [a for a in actions if '*' not in a]

        for wildcard in wildcards:
            if wildcard == '*' or wildcard == '*:*':
                if specific:
                    findings.append(RiskFinding(
                        risk_type="REDUNDANCY",
                        severity=RiskSeverity.INFO,
                        action=wildcard,
                        description=f"Wildcard {wildcard} makes {len(specific)} specific actions redundant",
                        remediation="Remove specific actions as wildcard already grants them",
                        additional_context={'redundant_count': len(specific)}
                    ))
            elif wildcard.endswith(':*'):
                service = wildcard.split(':')[0]
                redundant = [a for a in specific if a.startswith(f"{service}:")]
                if redundant:
                    findings.append(RiskFinding(
                        risk_type="REDUNDANCY",
                        severity=RiskSeverity.INFO,
                        action=wildcard,
                        description=f"Service wildcard {wildcard} makes {len(redundant)} actions redundant",
                        remediation=f"Remove redundant {service} actions",
                        additional_context={'redundant_actions': redundant}
                    ))

        return findings


class DangerousPermissionChecker:
    """Specialized checker for dangerous permission patterns.

    Provides detailed analysis of high-risk permissions and their context.
    """

    def __init__(self, database=None):
        """Initialize dangerous permission checker.

        Args:
            database: Optional Database instance
        """
        self.database = database
        self.risk_analyzer = RiskAnalyzer(database)

    def check_action(self, action: str, resource: str = "*") -> List[RiskFinding]:
        """Check single action for dangerous patterns.

        Args:
            action: IAM action name
            resource: Resource ARN (default: wildcard)

        Returns:
            List of RiskFinding objects
        """
        findings = self.risk_analyzer.analyze_actions([action])

        # Add resource context to findings
        for finding in findings:
            if resource == "*":
                finding.severity = self._escalate_severity(finding.severity)
                finding.additional_context['resource'] = resource
                finding.description += " (applied to wildcard resource)"

        return findings

    def _escalate_severity(self, severity: RiskSeverity) -> RiskSeverity:
        """Escalate severity when applied to wildcard resources.

        Args:
            severity: Original severity

        Returns:
            Escalated severity
        """
        escalation = {
            RiskSeverity.INFO: RiskSeverity.LOW,
            RiskSeverity.LOW: RiskSeverity.MEDIUM,
            RiskSeverity.MEDIUM: RiskSeverity.HIGH,
            RiskSeverity.HIGH: RiskSeverity.CRITICAL,
            RiskSeverity.CRITICAL: RiskSeverity.CRITICAL,
        }
        return escalation.get(severity, severity)


class CompanionPermissionDetector:
    """Detects missing companion permissions for IAM actions.

    Identifies when actions require additional supporting permissions
    to function correctly (e.g., Lambda needs CloudWatch Logs permissions).
    """

    # Companion permission rules
    COMPANION_RULES = {
        # Lambda execution requires CloudWatch Logs
        'lambda:InvokeFunction': CompanionPermission(
            primary_action='lambda:InvokeFunction',
            companion_actions=[
                'logs:CreateLogGroup',
                'logs:CreateLogStream',
                'logs:PutLogEvents'
            ],
            reason='Lambda functions require CloudWatch Logs permissions to write execution logs',
            severity=RiskSeverity.MEDIUM
        ),
        'lambda:CreateFunction': CompanionPermission(
            primary_action='lambda:CreateFunction',
            companion_actions=[
                'logs:CreateLogGroup',
                'logs:CreateLogStream',
                'logs:PutLogEvents',
                'ec2:CreateNetworkInterface',
                'ec2:DescribeNetworkInterfaces',
                'ec2:DeleteNetworkInterface'
            ],
            reason='Lambda functions require CloudWatch Logs permissions to write execution logs. '
                   'Lambda functions in VPC require EC2 network interface permissions.',
            severity=RiskSeverity.HIGH
        ),

        # KMS encrypted resources need decrypt permission
        's3:GetObject': CompanionPermission(
            primary_action='s3:GetObject',
            companion_actions=['kms:Decrypt'],
            reason='Reading KMS-encrypted S3 objects requires kms:Decrypt permission',
            severity=RiskSeverity.MEDIUM
        ),
        's3:PutObject': CompanionPermission(
            primary_action='s3:PutObject',
            companion_actions=['kms:GenerateDataKey', 'kms:Decrypt'],
            reason='Writing KMS-encrypted S3 objects requires KMS key generation',
            severity=RiskSeverity.MEDIUM
        ),

        # SQS consumer needs full message lifecycle
        'sqs:ReceiveMessage': CompanionPermission(
            primary_action='sqs:ReceiveMessage',
            companion_actions=[
                'sqs:DeleteMessage',
                'sqs:GetQueueAttributes',
                'sqs:ChangeMessageVisibility'
            ],
            reason='SQS consumers need permissions for complete message processing lifecycle',
            severity=RiskSeverity.MEDIUM
        ),

        # DynamoDB streams processing
        'dynamodb:GetRecords': CompanionPermission(
            primary_action='dynamodb:GetRecords',
            companion_actions=[
                'dynamodb:GetShardIterator',
                'dynamodb:DescribeStream',
                'dynamodb:ListStreams'
            ],
            reason='DynamoDB Streams processing requires stream discovery and iteration',
            severity=RiskSeverity.MEDIUM
        ),

        # EC2 instance termination with volume cleanup
        'ec2:TerminateInstances': CompanionPermission(
            primary_action='ec2:TerminateInstances',
            companion_actions=[
                'ec2:DeleteVolume',
                'ec2:DetachVolume'
            ],
            reason='Instance termination may require volume cleanup permissions',
            severity=RiskSeverity.LOW
        ),
    }

    def __init__(self, database=None):
        """Initialize companion permission detector.

        Args:
            database: Optional Database instance
        """
        self.database = database

    def detect_missing_companions(
        self,
        actions: List[str],
        context: Optional[Dict[str, Any]] = None
    ) -> List[CompanionPermission]:
        """Detect missing companion permissions.

        Args:
            actions: List of IAM action names in policy
            context: Optional context (e.g., VPC config, encryption settings)

        Returns:
            List of CompanionPermission objects for missing companions
        """
        missing = []
        action_set = set(actions)

        for action in actions:
            if action in self.COMPANION_RULES:
                companion = self.COMPANION_RULES[action]

                # Check if any companion actions are missing
                missing_companions = [
                    comp for comp in companion.companion_actions
                    if comp not in action_set
                ]

                if missing_companions:
                    missing.append(CompanionPermission(
                        primary_action=companion.primary_action,
                        companion_actions=missing_companions,
                        reason=companion.reason,
                        severity=companion.severity
                    ))

        return missing

    def suggest_companions(self, action: str) -> Optional[CompanionPermission]:
        """Suggest companion permissions for a single action.

        Args:
            action: IAM action name

        Returns:
            CompanionPermission if companions exist, None otherwise
        """
        return self.COMPANION_RULES.get(action)


class HITLSystem:
    """Human-in-the-Loop validation system.

    Flags Tier 2 (unknown) actions for user review and tracks
    user decisions and assumptions.
    """

    def __init__(self):
        """Initialize HITL system."""
        self.decisions: List[HITLDecision] = []

    def flag_tier2_action(
        self,
        action: str,
        assumptions: List[str]
    ) -> bool:
        """Flag Tier 2 action for human review.

        Args:
            action: Action name to flag
            assumptions: List of assumptions to validate

        Returns:
            True to proceed with action, False to reject

        Note:
            This is a synchronous method. In production, this would
            integrate with an interactive prompt system.
        """
        # In a real implementation, this would show an interactive prompt
        # For testing, we'll return True and track the decision

        decision = HITLDecision(
            action=action,
            tier='TIER_2_UNKNOWN',
            user_approved=True,  # Default for automated testing
            assumptions_validated=assumptions
        )

        self.decisions.append(decision)
        return True

    def record_decision(
        self,
        action: str,
        tier: str,
        approved: bool,
        comment: Optional[str] = None,
        assumptions: Optional[List[str]] = None
    ) -> None:
        """Record a user decision.

        Args:
            action: Action that was reviewed
            tier: Validation tier
            approved: Whether user approved the action
            comment: Optional user comment
            assumptions: Validated assumptions
        """
        decision = HITLDecision(
            action=action,
            tier=tier,
            user_approved=approved,
            user_comment=comment,
            assumptions_validated=assumptions or []
        )

        self.decisions.append(decision)

    def get_decision_history(self) -> List[HITLDecision]:
        """Get all recorded decisions.

        Returns:
            List of HITLDecision objects
        """
        return self.decisions.copy()

    def get_approval_stats(self) -> Dict[str, int]:
        """Get approval statistics.

        Returns:
            Dictionary with approval counts
        """
        total = len(self.decisions)
        approved = sum(1 for d in self.decisions if d.user_approved)
        rejected = total - approved

        return {
            'total_reviews': total,
            'approved': approved,
            'rejected': rejected,
            'approval_rate': approved / total if total > 0 else 0.0
        }

    def clear_history(self) -> None:
        """Clear decision history."""
        self.decisions.clear()

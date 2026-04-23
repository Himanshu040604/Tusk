"""Risk analysis engine for IAM Policy Sentinel.

This module provides intent mapping, risk detection, dangerous permission checking,
companion permission detection, and human-in-the-loop validation system.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import TYPE_CHECKING, Any
import re

# P0-3 α — constants imports deferred to function scope to break the
# cold-start chain: module-level `from .constants import ...` pulls the
# pydantic-settings stack at import time (~635ms).  Moving into the
# specific functions that need SERVICE_NAME_MAPPINGS /
# SECURITY_CRITICAL_SERVICES means `sentinel --version` doesn't load
# constants or pydantic-settings at all.

if TYPE_CHECKING:
    from .database import Database


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
    access_levels: set[AccessLevel]
    services: set[str] = field(default_factory=set)
    actions: list[str] = field(default_factory=list)
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
    additional_context: dict[str, Any] = field(default_factory=dict)


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
    companion_actions: list[str]
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
    user_comment: str | None = None
    assumptions_validated: list[str] = field(default_factory=list)


class IntentMapper:
    """Maps developer intent to IAM access levels and actions.

    Translates natural language intent descriptions into specific
    access levels and action sets for policy generation.

    Task 8 / M1: keyword -> access-level map is now loaded at
    __init__ time from the ``[intent.keywords.*]`` TOML tables via
    :func:`sentinel.config.get_settings`.  No class-level constant —
    changing a bucket's synonyms or level set is a pure config edit
    (reload with ``SENTINEL_CONFIG_RELOAD=1``) rather than a code
    redeploy.
    """

    def __init__(self, database: Database | None = None):
        """Initialize intent mapper.

        Args:
            database: Optional Database instance for querying actions.
        """
        self.database = database
        self._intent_keywords: dict[str, set[AccessLevel]] = self._load_intent_keywords()
        # P2-15 α — precompile the word-boundary keyword patterns once
        # at __init__ so hot-path methods (``map_intent``,
        # ``_extract_access_levels``) don't re-compile them per call.
        # Mirrors the precompile-in-__init__ precedent in ``RiskAnalyzer``.
        self._compiled_keyword_patterns: list[tuple[re.Pattern[str], set[AccessLevel]]] = [
            (re.compile(r"\b" + re.escape(kw) + r"\b"), levels)
            for kw, levels in self._intent_keywords.items()
        ]

    @staticmethod
    def _load_intent_keywords() -> dict[str, set[AccessLevel]]:
        """Flatten the 8-bucket TOML schema into a keyword -> AccessLevel set.

        Each bucket in ``Settings.intent.keywords`` declares a list of
        synonym ``values`` and a list of ``levels`` (AccessLevel enum
        member names).  Flattened shape matches the old class-level
        dict so downstream callers stay unchanged.
        """
        from .config import get_settings

        settings = get_settings()
        out: dict[str, set[AccessLevel]] = {}
        for bucket in settings.intent.keywords.values():
            levels: set[AccessLevel] = set()
            for lvl_name in bucket.levels:
                try:
                    levels.add(AccessLevel[lvl_name])
                except KeyError:
                    # Unknown level name in TOML — skip quietly;
                    # config validation catches this at load time.
                    continue
            for keyword in bucket.values:
                if keyword in out:
                    out[keyword].update(levels)
                else:
                    out[keyword] = set(levels)
        return out

    @property
    def INTENT_KEYWORDS(self) -> dict[str, set[AccessLevel]]:
        """Backwards-compat shim — callers inside this class still read this."""
        return self._intent_keywords

    def map_intent(self, intent: str, service_filter: list[str] | None = None) -> IntentMapping:
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

        if self.database and access_levels:
            actions = self._query_actions_by_access_levels(access_levels, services)

        # Graduate confidence based on keyword match count and DB results.
        # P2-15 α — iterate precompiled patterns instead of per-call
        # re.search with string construction.
        keyword_hits = sum(
            1 for pattern, _ in self._compiled_keyword_patterns if pattern.search(intent_lower)
        )
        if keyword_hits >= 3:
            confidence = 1.0
        elif keyword_hits == 2:
            confidence = 0.8
        elif keyword_hits == 1:
            confidence = 0.6
        else:
            confidence = 0.4
        # Lower if DB available but returned no matching actions
        if self.database and not actions and confidence > 0.5:
            confidence -= 0.3

        explanation = self._generate_explanation(intent, access_levels, services, actions)

        return IntentMapping(
            original_intent=intent,
            access_levels=access_levels,
            services=services,
            actions=actions,
            confidence=round(confidence, 2),
            explanation=explanation,
        )

    def _extract_access_levels(self, intent_lower: str) -> set[AccessLevel]:
        """Extract access levels from intent string.

        Args:
            intent_lower: Lowercase intent string

        Returns:
            Set of AccessLevel enums
        """
        access_levels = set()

        # P2-15 α — check each PRECOMPILED pattern (word boundaries) to
        # avoid false positives (e.g. "target" matching "get",
        # "blacklist" matching "list") without rebuilding regex strings
        # on every call.
        for pattern, levels in self._compiled_keyword_patterns:
            if pattern.search(intent_lower):
                access_levels.update(levels)

        # If no keywords matched, default to read-only for safety
        if not access_levels:
            access_levels = {AccessLevel.LIST, AccessLevel.READ}

        return access_levels

    def _extract_services(self, intent_lower: str) -> set[str]:
        """Extract AWS service hints from intent string.

        Args:
            intent_lower: Lowercase intent string

        Returns:
            Set of service prefix strings
        """
        from .constants import SERVICE_NAME_MAPPINGS  # P0-3 α deferred

        services = set()

        for keyword, service in SERVICE_NAME_MAPPINGS.items():
            # Use word boundary matching to avoid substring false positives
            if re.search(r"\b" + re.escape(keyword) + r"\b", intent_lower):
                services.add(service)

        return services

    def _query_actions_by_access_levels(
        self, access_levels: set[AccessLevel], services: set[str]
    ) -> list[str]:
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
                placeholders = ",".join("?" for _ in services)
                where_clause += f" AND service_prefix IN ({placeholders})"
                params.extend(sorted(services))

            query = f"""
                SELECT service_prefix, action_name
                FROM actions
                WHERE {where_clause}
                ORDER BY service_prefix, action_name
            """

            cursor.execute(query, params)
            actions = [f"{row['service_prefix']}:{row['action_name']}" for row in cursor.fetchall()]

        return actions

    def _generate_explanation(
        self, intent: str, access_levels: set[AccessLevel], services: set[str], actions: list[str]
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

    def __init__(self, database: "Database" | None = None):
        """Initialize risk analyzer with bulk-loaded classification tables.

        Task 6 bulk-load pattern: reads ``dangerous_actions`` from the DB
        once at construction time, verifies the HMAC signature on each
        row (Task 6a), and builds instance-level frozensets / pre-compiled
        regex tuples for O(1) / O(n_patterns) hot-path lookups.  No per-
        action SQL — matches § 12 Phase 2 Task 6 "no N+1" mandate.

        Task 8b D3 HARD-FAIL: ``database`` must be non-None.  Without a
        DB we have no classification source (Task 8 deleted the
        class-level fallbacks) and silently returning empty sets would
        mask every risk finding — a worse security posture than just
        failing loudly.  The CLI maps :class:`DatabaseError` from this
        constructor to exit code 3 (EXIT_IO_ERROR) with the remediation
        hint "no IAM DB found; run `sentinel refresh --source shipped`".

        Args:
            database: Database instance for action validation and
                classification-row bulk-load.  Accepting ``None`` is
                kept in the signature only so existing callsites that
                passed ``None`` raise at construction time rather than
                at argument-bind time — the error message is clearer.

        Raises:
            DatabaseError: If ``database`` is None, OR if any loaded
                row has a mismatched HMAC signature (on-disk tampering
                — Task 6a K_db verification).
        """
        if database is None:
            from .database import DatabaseError

            raise DatabaseError(
                "RiskAnalyzer requires a non-None Database (Task 8b D3 "
                "HARD-FAIL).  Construct via `Database(iam_db_path)` — or "
                "run `sentinel refresh --source shipped` to create a "
                "baseline IAM DB if none exists yet."
            )
        self.database = database

        # Instance-level bulk-loaded classification.  Immutable after
        # __init__; hot-path methods read self._priv_escalation etc.
        self._priv_escalation: frozenset[str] = frozenset()
        self._exfil_patterns: tuple[tuple["re.Pattern[str]", str], ...] = ()
        self._destruction_patterns: tuple[tuple["re.Pattern[str]", str], ...] = ()
        self._perms_mgmt_patterns: tuple[tuple["re.Pattern[str]", str], ...] = ()

        # Propagate HMAC/DatabaseError failures — do NOT silently
        # swallow, that would defeat the tamper defense.
        self._bulk_load_classifications(database)

    def _bulk_load_classifications(self, database: Database) -> bool:
        """Load + HMAC-verify rows from ``dangerous_actions``.

        Returns:
            True if the table exists and at least one row was loaded.
            False if the table is absent or empty (caller falls back to
            class-level constants).

        Raises:
            DatabaseError: On HMAC signature mismatch — includes the
                offending row's primary key for forensic replay.
        """
        from .hmac_keys import verify_row

        # P0-1 α — no outer `except Exception`.  Let DatabaseError (raised
        # by get_connection() on sqlite I/O failures) and row-level
        # HMAC-mismatch DatabaseError propagate to the caller.  The probe
        # branch below remains the only silent path (pre-migration DB).
        with database.get_connection() as conn:
            # Probe for table existence first (pre-migration DBs).
            probe = conn.execute(
                "SELECT name FROM sqlite_master WHERE type='table' AND name='dangerous_actions'"
            ).fetchone()
            if not probe:
                return False
            rows = conn.execute(
                "SELECT action_name, category, severity, description, "
                "source, refreshed_at, row_hmac FROM dangerous_actions"
            ).fetchall()

        if not rows:
            return False

        priv: set[str] = set()
        exfil: list[tuple["re.Pattern[str]", str]] = []
        destruction: list[tuple["re.Pattern[str]", str]] = []
        perms_mgmt: list[tuple["re.Pattern[str]", str]] = []

        for action_name, category, severity, description, source, refreshed_at, row_hmac in rows:
            # Task 6a: HMAC verify each row before trusting its content.
            payload = {
                "severity": severity,
                "description": description,
                "source": source,
                "refreshed_at": refreshed_at,
            }
            ok = verify_row(
                "dangerous_actions",
                (action_name, category),
                payload,
                row_hmac,
            )
            if not ok:
                from .database import DatabaseError

                raise DatabaseError(
                    f"HMAC verification failed for dangerous_actions row "
                    f"({action_name!r}, {category!r}).  On-disk tampering "
                    f"suspected — wipe and rerun `sentinel refresh --source shipped`."
                )

            if category == "privilege_escalation":
                priv.add(action_name)
            elif category in ("exfiltration", "destruction", "permissions_mgmt"):
                # Security #1 (v0.6.2): wrap re.compile so a malformed
                # DB-sourced regex surfaces as DatabaseError (naming the
                # offending row) rather than crashing RiskAnalyzer.__init__
                # with an uninformative re.error.
                try:
                    compiled = re.compile(action_name)
                except re.error as exc:
                    from .database import DatabaseError

                    raise DatabaseError(
                        f"Invalid regex in dangerous_actions "
                        f"({action_name!r}, {category!r}): {exc}"
                    ) from exc
                if category == "exfiltration":
                    exfil.append((compiled, description))
                elif category == "destruction":
                    destruction.append((compiled, description))
                else:  # permissions_mgmt
                    perms_mgmt.append((compiled, description))

        self._priv_escalation = frozenset(priv)
        self._exfil_patterns = tuple(exfil)
        self._destruction_patterns = tuple(destruction)
        self._perms_mgmt_patterns = tuple(perms_mgmt)
        return True

    def analyze_actions(self, actions: list[str]) -> list[RiskFinding]:
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

    def _check_wildcards(self, action: str) -> list[RiskFinding]:
        """Check for wildcard usage and assess severity.

        Args:
            action: IAM action name

        Returns:
            List of RiskFinding objects
        """
        findings = []

        if action == "*" or action == "*:*":
            findings.append(
                RiskFinding(
                    risk_type="WILDCARD_ALL_ACTIONS",
                    severity=RiskSeverity.CRITICAL,
                    action=action,
                    description="Full wildcard grants ALL AWS permissions across ALL services",
                    remediation="Replace with specific actions or service-level wildcards (e.g., s3:*)",
                    additional_context={"wildcard_type": "full"},
                )
            )
        elif "*" in action:
            severity = self._assess_wildcard_severity(action)
            findings.append(
                RiskFinding(
                    risk_type="WILDCARD_ACTION",
                    severity=severity,
                    action=action,
                    description=f"Wildcard action grants multiple permissions: {action}",
                    remediation="Replace with specific actions to follow least privilege",
                    additional_context={"wildcard_type": "partial", "pattern": action},
                )
            )

        return findings

    def _assess_wildcard_severity(self, action: str) -> RiskSeverity:
        """Assess severity of wildcard action.

        Args:
            action: Wildcard action pattern

        Returns:
            RiskSeverity level
        """
        from .constants import SECURITY_CRITICAL_SERVICES  # P0-3 α deferred

        # service:* is HIGH severity
        if action.endswith(":*"):
            service = action.split(":")[0]
            # Critical services get CRITICAL severity
            if service in SECURITY_CRITICAL_SERVICES:
                return RiskSeverity.CRITICAL
            return RiskSeverity.HIGH

        # Prefix/suffix wildcards are MEDIUM severity
        if action.endswith("*") or action.startswith("*"):
            return RiskSeverity.MEDIUM

        return RiskSeverity.LOW

    def _check_privilege_escalation(self, action: str) -> list[RiskFinding]:
        """Check for privilege escalation actions.

        Args:
            action: IAM action name

        Returns:
            List of RiskFinding objects
        """
        findings = []

        if action in self._priv_escalation:
            findings.append(
                RiskFinding(
                    risk_type="PRIVILEGE_ESCALATION",
                    severity=RiskSeverity.HIGH,
                    action=action,
                    description=f"Action {action} can be used for privilege escalation",
                    remediation="Add strict conditions (e.g., resource ARNs, tags) to limit scope",
                    additional_context={"escalation_action": action},
                )
            )

        return findings

    def _check_data_exfiltration(self, action: str) -> list[RiskFinding]:
        """Check for data exfiltration risks.

        Args:
            action: IAM action name

        Returns:
            List of RiskFinding objects
        """
        findings = []

        for compiled, description in self._exfil_patterns:
            if compiled.match(action):
                # Check if it's a wildcard on sensitive action
                severity = RiskSeverity.MEDIUM
                if "*" in action and ("Secret" in action or "s3:GetObject" in action):
                    severity = RiskSeverity.HIGH

                findings.append(
                    RiskFinding(
                        risk_type="DATA_EXFILTRATION_RISK",
                        severity=severity,
                        action=action,
                        description=f"{description}: {action}",
                        remediation="Add resource-level constraints and conditions to limit data access",
                        additional_context={"pattern": description},
                    )
                )
                break

        return findings

    def _check_destruction(self, action: str) -> list[RiskFinding]:
        """Check for infrastructure destruction capabilities.

        Args:
            action: IAM action name

        Returns:
            List of RiskFinding objects
        """
        findings = []

        for compiled, description in self._destruction_patterns:
            if compiled.match(action):
                severity = RiskSeverity.MEDIUM
                # Critical resources get higher severity
                if any(
                    svc in action
                    for svc in ["rds:DeleteDB", "s3:DeleteBucket", "dynamodb:DeleteTable"]
                ):
                    severity = RiskSeverity.HIGH

                findings.append(
                    RiskFinding(
                        risk_type="DESTRUCTION_CAPABILITY",
                        severity=severity,
                        action=action,
                        description=f"{description}: {action}",
                        remediation="Add MFA condition or restrict to specific resources",
                        additional_context={"pattern": description},
                    )
                )
                break

        return findings

    def _check_permissions_management(self, action: str) -> list[RiskFinding]:
        """Check for permissions management actions.

        Args:
            action: IAM action name

        Returns:
            List of RiskFinding objects
        """
        findings = []

        for compiled, description in self._perms_mgmt_patterns:
            if compiled.match(action):
                findings.append(
                    RiskFinding(
                        risk_type="PERMISSIONS_MANAGEMENT",
                        severity=RiskSeverity.HIGH,
                        action=action,
                        description=f"{description}: {action}",
                        remediation="Restrict to specific resources and add approval workflow",
                        additional_context={"pattern": description},
                    )
                )
                break

        return findings

    def _check_dangerous_combinations(self, actions: list[str]) -> list[RiskFinding]:
        """Check for dangerous permission combinations.

        Args:
            actions: List of IAM action names

        Returns:
            List of RiskFinding objects
        """
        findings = []
        action_set = set(actions)

        # iam:PassRole + lambda:CreateFunction = privilege escalation
        if "iam:PassRole" in action_set and "lambda:CreateFunction" in action_set:
            findings.append(
                RiskFinding(
                    risk_type="DANGEROUS_COMBINATION",
                    severity=RiskSeverity.CRITICAL,
                    action="iam:PassRole + lambda:CreateFunction",
                    description="Combination allows privilege escalation via Lambda execution role",
                    remediation="Separate these permissions or add strict resource constraints",
                    additional_context={
                        "combination": ["iam:PassRole", "lambda:CreateFunction"],
                        "escalation_path": "Lambda role assumption",
                    },
                )
            )

        # iam:PassRole + ec2:RunInstances = privilege escalation
        if "iam:PassRole" in action_set and "ec2:RunInstances" in action_set:
            findings.append(
                RiskFinding(
                    risk_type="DANGEROUS_COMBINATION",
                    severity=RiskSeverity.CRITICAL,
                    action="iam:PassRole + ec2:RunInstances",
                    description="Combination allows privilege escalation via EC2 instance profile",
                    remediation="Add conditions to restrict role ARNs and instance types",
                    additional_context={
                        "combination": ["iam:PassRole", "ec2:RunInstances"],
                        "escalation_path": "EC2 instance profile",
                    },
                )
            )

        # iam:CreatePolicyVersion + iam:SetDefaultPolicyVersion = policy takeover
        if "iam:CreatePolicyVersion" in action_set and "iam:SetDefaultPolicyVersion" in action_set:
            findings.append(
                RiskFinding(
                    risk_type="DANGEROUS_COMBINATION",
                    severity=RiskSeverity.CRITICAL,
                    action="iam:CreatePolicyVersion + iam:SetDefaultPolicyVersion",
                    description="Combination allows complete policy takeover",
                    remediation="Separate permissions or add strict resource ARN constraints",
                    additional_context={
                        "combination": ["iam:CreatePolicyVersion", "iam:SetDefaultPolicyVersion"],
                        "escalation_path": "Policy version manipulation",
                    },
                )
            )

        return findings

    def _check_redundancy(self, actions: list[str]) -> list[RiskFinding]:
        """Check for redundant or overlapping actions.

        Args:
            actions: List of IAM action names

        Returns:
            List of RiskFinding objects
        """
        findings = []

        # Check if wildcard makes specific actions redundant
        wildcards = [a for a in actions if "*" in a]
        specific = [a for a in actions if "*" not in a]

        for wildcard in wildcards:
            if wildcard == "*" or wildcard == "*:*":
                if specific:
                    findings.append(
                        RiskFinding(
                            risk_type="REDUNDANCY",
                            severity=RiskSeverity.INFO,
                            action=wildcard,
                            description=f"Wildcard {wildcard} makes {len(specific)} specific actions redundant",
                            remediation="Remove specific actions as wildcard already grants them",
                            additional_context={"redundant_count": len(specific)},
                        )
                    )
            elif wildcard.endswith(":*"):
                service = wildcard.split(":")[0]
                redundant = [a for a in specific if a.startswith(f"{service}:")]
                if redundant:
                    findings.append(
                        RiskFinding(
                            risk_type="REDUNDANCY",
                            severity=RiskSeverity.INFO,
                            action=wildcard,
                            description=f"Service wildcard {wildcard} makes {len(redundant)} actions redundant",
                            remediation=f"Remove redundant {service} actions",
                            additional_context={"redundant_actions": redundant},
                        )
                    )

        return findings


class DangerousPermissionChecker:
    """Specialized checker for dangerous permission patterns.

    Provides detailed analysis of high-risk permissions and their context.
    """

    def __init__(self, database: Database | None = None):
        """Initialize dangerous permission checker.

        Args:
            database: Optional Database instance
        """
        self.database = database
        self.risk_analyzer = RiskAnalyzer(database)

    def check_action(self, action: str, resource: str = "*") -> list[RiskFinding]:
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
                finding.additional_context["resource"] = resource
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

    # Task 8: class-level COMPANION_PERMISSION_RULES import and
    # fallback-reconstruction block deleted.  Rules live exclusively in
    # the `companion_rules` DB table (migration 0004 + seed_all_baseline).

    def __init__(self, database: "Database" | None = None):
        """Initialize companion permission detector.

        Task 6 bulk-load: reads ``companion_rules`` once at construction
        time, HMAC-verifies each row (Task 6a K_db), and builds the
        instance-level lookup dict.  Hot path is O(1) dict access.

        Task 8b D3 HARD-FAIL: ``database`` must be non-None.  The
        ``companion_rules`` table is the sole ruleset source after Task
        8 deleted the ``COMPANION_PERMISSION_RULES`` constant; a None DB
        would leave the detector silently incapable of finding any
        missing companions.

        Args:
            database: Database instance.  ``None`` raises
                :class:`DatabaseError` with the same remediation hint
                as :class:`RiskAnalyzer`.

        Raises:
            DatabaseError: If ``database`` is None or on HMAC row
                signature mismatch.
        """
        if database is None:
            from .database import DatabaseError

            raise DatabaseError(
                "CompanionPermissionDetector requires a non-None Database "
                "(Task 8b D3 HARD-FAIL).  Run `sentinel refresh --source "
                "shipped` if no baseline IAM DB exists yet."
            )
        self.database = database
        self._companion_rules: dict[str, CompanionPermission] = {}
        self._bulk_load_companion_rules(database)

    def _bulk_load_companion_rules(self, database: Database) -> bool:
        """Load + HMAC-verify rows from ``companion_rules``.

        Multiple rows per primary_action are grouped into one
        CompanionPermission.companion_actions list (matching the old
        class-dict shape where each key mapped to a flat companion list).
        """
        from .hmac_keys import verify_row

        # P0-1 α — no outer `except Exception`.  Let DatabaseError propagate.
        with database.get_connection() as conn:
            probe = conn.execute(
                "SELECT name FROM sqlite_master WHERE type='table' AND name='companion_rules'"
            ).fetchone()
            if not probe:
                return False
            rows = conn.execute(
                "SELECT primary_action, companion_action, reason, "
                "severity, source, refreshed_at, row_hmac "
                "FROM companion_rules ORDER BY primary_action, companion_action"
            ).fetchall()

        if not rows:
            return False

        # Group by primary_action.  HMAC-verify each row as we go.
        grouped: dict[str, dict] = {}
        for primary, companion, reason, severity, source, refreshed_at, row_hmac in rows:
            payload = {
                "reason": reason,
                "severity": severity,
                "source": source,
                "refreshed_at": refreshed_at,
            }
            if not verify_row("companion_rules", (primary, companion), payload, row_hmac):
                from .database import DatabaseError

                raise DatabaseError(
                    f"HMAC verification failed for companion_rules row "
                    f"({primary!r}, {companion!r})."
                )
            if primary not in grouped:
                grouped[primary] = {
                    "companions": [],
                    "reason": reason,
                    "severity": severity,
                }
            grouped[primary]["companions"].append(companion)

        self._companion_rules = {
            primary: CompanionPermission(
                primary_action=primary,
                companion_actions=data["companions"],
                reason=data["reason"],
                severity=RiskSeverity[data["severity"]],
            )
            for primary, data in grouped.items()
        }
        return True

    def detect_missing_companions(
        self, actions: list[str], context: dict[str, Any] | None = None
    ) -> list[CompanionPermission]:
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
            if action in self._companion_rules:
                companion = self._companion_rules[action]

                # Check if any companion actions are missing
                missing_companions = [
                    comp for comp in companion.companion_actions if comp not in action_set
                ]

                if missing_companions:
                    missing.append(
                        CompanionPermission(
                            primary_action=companion.primary_action,
                            companion_actions=missing_companions,
                            reason=companion.reason,
                            severity=companion.severity,
                        )
                    )

        return missing

    def suggest_companions(self, action: str) -> CompanionPermission | None:
        """Suggest companion permissions for a single action.

        Args:
            action: IAM action name

        Returns:
            CompanionPermission if companions exist, None otherwise
        """
        return self._companion_rules.get(action)


class HITLSystem:
    """Human-in-the-Loop validation system.

    Flags Tier 2 (unknown) actions for user review and tracks
    user decisions and assumptions.
    """

    def __init__(self, interactive: bool = False):
        """Initialize HITL system.

        Args:
            interactive: If True, prompt user via stdin for each
                Tier 2 action. If False, auto-approve all actions
                (safe for CI/CD and testing).
        """
        self.interactive = interactive
        self.decisions: list[HITLDecision] = []
        self._skip_remaining = False

    def flag_tier2_action(self, action: str, assumptions: list[str]) -> bool:
        """Flag Tier 2 action for human review.

        When interactive mode is enabled, prompts the user via stdin
        to approve, reject, or skip remaining actions. In non-interactive
        mode, auto-approves all actions.

        Args:
            action: Action name to flag
            assumptions: List of assumptions to validate

        Returns:
            True to proceed with action, False to reject
        """
        if not self.interactive or self._skip_remaining:
            decision = HITLDecision(
                action=action,
                tier="TIER_2_UNKNOWN",
                user_approved=True,
                assumptions_validated=assumptions,
            )
            self.decisions.append(decision)
            return True

        return self._prompt_user(action, assumptions)

    def _prompt_user(self, action: str, assumptions: list[str]) -> bool:
        """Prompt user via stdin for a Tier 2 action decision.

        Displays action details and reads user input. Accepts:
        - 'a' to approve
        - 'r' to reject
        - 's' to skip remaining (auto-approve all subsequent)

        Args:
            action: Action name to review.
            assumptions: Assumptions about the action.

        Returns:
            True if approved, False if rejected.
        """
        reason = "; ".join(assumptions) if assumptions else "No details available"
        print(f"\n[HITL] Tier 2 action: {action}")
        print(f"  Reason: {reason}")

        while True:
            try:
                answer = (
                    input(
                        "  Approve this action? "
                        "[A]pprove / [R]eject / [S]kip remaining (auto-approve) > "
                    )
                    .strip()
                    .lower()
                )
            except EOFError:
                answer = "r"

            if answer in ("a", "approve"):
                decision = HITLDecision(
                    action=action,
                    tier="TIER_2_UNKNOWN",
                    user_approved=True,
                    assumptions_validated=assumptions,
                )
                self.decisions.append(decision)
                return True
            elif answer in ("r", "reject"):
                decision = HITLDecision(
                    action=action,
                    tier="TIER_2_UNKNOWN",
                    user_approved=False,
                    assumptions_validated=assumptions,
                )
                self.decisions.append(decision)
                return False
            elif answer in ("s", "skip"):
                self._skip_remaining = True
                decision = HITLDecision(
                    action=action,
                    tier="TIER_2_UNKNOWN",
                    user_approved=True,
                    user_comment="Auto-approved (skip remaining)",
                    assumptions_validated=assumptions,
                )
                self.decisions.append(decision)
                return True
            else:
                print("  Invalid input. Please enter 'a', 'r', or 's'.")

    def record_decision(
        self,
        action: str,
        tier: str,
        approved: bool,
        comment: str | None = None,
        assumptions: list[str] | None = None,
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
            assumptions_validated=assumptions or [],
        )

        self.decisions.append(decision)

    def get_decision_history(self) -> list[HITLDecision]:
        """Get all recorded decisions.

        Returns:
            List of HITLDecision objects
        """
        return self.decisions.copy()

    def get_approval_stats(self) -> dict[str, float]:
        """Get approval statistics.

        Returns:
            Dictionary with approval counts
        """
        total = len(self.decisions)
        approved = sum(1 for d in self.decisions if d.user_approved)
        rejected = total - approved

        return {
            "total_reviews": total,
            "approved": approved,
            "rejected": rejected,
            "approval_rate": approved / total if total > 0 else 0.0,
        }

    def clear_history(self) -> None:
        """Clear decision history."""
        self.decisions.clear()

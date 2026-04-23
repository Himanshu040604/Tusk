"""Policy rewriter for IAM Policy Sentinel.

This module provides least-privilege policy generation by replacing wildcards
with specific actions, scoping resources to real or placeholder ARNs, adding
companion permissions, injecting condition keys, and reorganizing statements.
"""

from __future__ import annotations

import copy
import re
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

# P0-3 α — constants imports deferred to function scope to break the
# cold-start chain.  Module-level `from .constants import X` triggers
# constants.__getattr__ which calls get_settings() which loads
# pydantic-settings (~635ms).  By moving into the hot-path functions
# that actually read these values, `sentinel --version` avoids the
# pydantic load entirely.  DEFAULT_ACCOUNT_ID and DEFAULT_REGION are
# pure constants (not __getattr__-backed) so safe to import eagerly.
from .constants import (
    DEFAULT_ACCOUNT_ID,
    DEFAULT_REGION,
)
from .parser import Policy, Statement
from .analyzer import (
    CompanionPermission,
    CompanionPermissionDetector,
    AccessLevel,
    RiskSeverity,
)

if TYPE_CHECKING:
    from .database import Database
    from .inventory import ResourceInventory


@dataclass
class RewriteConfig:
    """Configuration for policy rewriting.

    Attributes:
        intent: Developer intent description (e.g., 'read-only s3')
        account_id: AWS account ID for ARN generation
        region: AWS region for ARN generation
        add_companions: Whether to add companion permissions
        add_conditions: Whether to inject condition keys
        placeholder_format: Marker text for placeholder ARNs
        preserve_deny_statements: Keep Deny statements unchanged
        max_actions_per_statement: Max actions per statement for readability
        policy_type: Policy type hint (identity/resource/scp/boundary/None for auto-detect)
        condition_profile: Condition injection profile (strict/moderate/none)
    """

    intent: str | None = None
    account_id: str | None = None
    region: str | None = None
    add_companions: bool = True
    add_conditions: bool = True
    placeholder_format: str = "PLACEHOLDER"
    preserve_deny_statements: bool = True
    max_actions_per_statement: int = 15
    policy_type: str | None = None
    condition_profile: str = "moderate"


@dataclass
class RewriteChange:
    """Individual change record for audit trail.

    Attributes:
        change_type: Type of change made
        description: Human-readable description of the change
        original_value: What was changed from
        new_value: What was changed to
        statement_index: Which statement was affected
        confidence: How confident the rewrite decision is (1.0=DB-backed, 0.7=intent, 0.5=placeholder)
        rationale: Explanation of why this specific rewrite choice was made
    """

    change_type: str
    description: str
    original_value: str
    new_value: str
    statement_index: int = 0
    confidence: float = 1.0
    rationale: str | None = None


@dataclass
class RewriteResult:
    """Result of policy rewriting.

    Attributes:
        original_policy: The original input policy
        rewritten_policy: The rewritten least-privilege policy
        changes: List of changes made during rewriting
        assumptions: Assumptions made during rewriting
        warnings: Warnings generated during rewriting
        companion_permissions_added: Companion permissions that were added
    """

    original_policy: Policy
    rewritten_policy: Policy
    changes: list[RewriteChange] = field(default_factory=list)
    assumptions: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    companion_permissions_added: list[CompanionPermission] = field(default_factory=list)


class PolicyRewriter:
    """Least-privilege policy rewriter.

    Takes an IAM policy and generates a least-privilege version by:
    - Replacing wildcard actions with specific actions from the database
    - Scoping wildcard resources to real ARNs or placeholders
    - Adding missing companion permissions
    - Injecting security-hardening condition keys
    - Reorganizing statements with descriptive Sids
    """

    # P0-3 α — lazy properties avoid triggering constants.__getattr__
    # (and the pydantic-settings chain) at class-definition time.  These
    # read from ``constants`` each access; the constants layer caches
    # the underlying Settings so repeated access is cheap.
    @property
    def READ_PREFIXES(self) -> tuple[str, ...]:
        from .constants import READ_PREFIXES

        return READ_PREFIXES

    @property
    def WRITE_PREFIXES(self) -> tuple[str, ...]:
        from .constants import WRITE_PREFIXES

        return WRITE_PREFIXES

    @property
    def ADMIN_PREFIXES(self) -> tuple[str, ...]:
        from .constants import ADMIN_PREFIXES

        return ADMIN_PREFIXES

    def __init__(
        self,
        database: Database | None = None,
        inventory: ResourceInventory | None = None,
    ):
        """Initialize policy rewriter with bulk-loaded lookup tables.

        Task 7: action->resource-type and service->ARN-template lookups
        are bulk-loaded from the IAM DB at construction time (the
        ``action_resource_map`` and ``arn_templates`` tables — populated
        by migrations 0006/0007 and ``seed_all_baseline``).  The cached
        dicts replace the module-level ``ACTION_RESOURCE_MAP`` /
        ``ARN_TEMPLATES`` constants that Task 8 deletes from
        ``inventory.py``.

        When ``database`` is None or the tables are empty the instance
        dicts stay empty and callers fall back to their built-in
        defaults (``_infer_resource_type`` per-service defaults,
        ``generate_placeholder_arn`` generic fallback).  Task 8b flips
        ``database=None`` to a hard-fail.

        Args:
            database: Optional Database instance for action lookups +
                bulk-load source for action_resource_map / arn_templates.
            inventory: Optional ResourceInventory for ARN resolution.
        """
        self.database = database
        self.inventory = inventory
        self.companion_detector = CompanionPermissionDetector(database)

        # Task 7 bulk-load — cached dicts read once at __init__ time.
        self._action_resource_map: dict[str, str] = {}
        self._arn_templates: dict[str, str] = {}
        if database is not None:
            self._bulk_load_action_resource_map(database)
            self._bulk_load_arn_templates(database)

    def _bulk_load_action_resource_map(self, database: Database) -> None:
        """Populate ``self._action_resource_map`` from the IAM DB.

        Reads ``action_resource_map`` (migration 0006).  First row per
        action wins — shipped baseline only emits one row per action so
        this is deterministic.  Missing table / empty rowset leaves the
        instance dict empty; callers hit their per-service default path.
        """
        # P0-1 α — no outer `except Exception`.  Let DatabaseError propagate.
        with database.get_connection() as conn:
            probe = conn.execute(
                "SELECT name FROM sqlite_master WHERE type='table' "
                "AND name='action_resource_map'"
            ).fetchone()
            if not probe:
                return
            rows = conn.execute(
                "SELECT action_name, resource_type FROM action_resource_map"
            ).fetchall()
        # dict constructor collapses duplicates; first-wins via reversed().
        self._action_resource_map = {
            action_name: resource_type for action_name, resource_type in reversed(rows)
        }

    def _bulk_load_arn_templates(self, database: Database) -> None:
        """Populate ``self._arn_templates`` from the IAM DB.

        Reads ``arn_templates`` (migration 0007) keyed by service_prefix
        alone — matches the shape of the old ``ARN_TEMPLATES`` dict in
        ``inventory.py`` where keys were bare service prefixes.  Future
        (service, resource_type) composite rows remain addressable via
        ``"{svc}:{rt}"`` lookup keys.
        """
        # P0-1 α — no outer `except Exception`.  Let DatabaseError propagate.
        with database.get_connection() as conn:
            probe = conn.execute(
                "SELECT name FROM sqlite_master WHERE type='table' AND name='arn_templates'"
            ).fetchone()
            if not probe:
                return
            rows = conn.execute(
                "SELECT service_prefix, resource_type, arn_template FROM arn_templates"
            ).fetchall()
        out: dict[str, str] = {}
        for svc, rt, template in rows:
            key = svc if not rt else f"{svc}:{rt}"
            out[key] = template
        self._arn_templates = out

    @staticmethod
    def detect_policy_type(policy: Policy) -> str:
        """Auto-detect policy type from policy structure.

        Heuristic:
          - Any statement with Principal field -> 'resource'
          - All statements are Deny with no resource constraints -> 'scp'
          - Otherwise -> 'identity'

        Args:
            policy: Parsed policy object.

        Returns:
            One of 'identity', 'resource', 'scp'.
        """
        has_principal = any(stmt.principals is not None for stmt in policy.statements)
        if has_principal:
            return "resource"

        all_deny = policy.statements and all(stmt.effect == "Deny" for stmt in policy.statements)
        if all_deny:
            return "scp"

        return "identity"

    def rewrite_policy(self, policy: Policy, config: RewriteConfig | None = None) -> RewriteResult:
        """Rewrite an IAM policy to enforce least privilege.

        Orchestrates all rewriting steps: wildcard replacement, resource
        scoping, companion permission injection, condition key addition,
        and statement reorganization.

        Args:
            policy: Input IAM policy to rewrite
            config: Rewriting configuration (defaults applied if None)

        Returns:
            RewriteResult with rewritten policy and change audit trail
        """
        if config is None:
            config = RewriteConfig()

        # Auto-detect policy type if not explicitly set
        self._current_policy_type = config.policy_type or self.detect_policy_type(policy)

        all_changes: list[RewriteChange] = []
        assumptions: list[str] = []
        warnings: list[str] = []
        companions_added: list[CompanionPermission] = []

        # Deep copy to avoid mutating the original
        new_statements: list[Statement] = []

        for idx, stmt in enumerate(policy.statements):
            # Preserve Deny statements as-is
            if config.preserve_deny_statements and stmt.effect == "Deny":
                new_statements.append(copy.deepcopy(stmt))
                continue

            # Warn about NotAction / NotResource
            if stmt.not_actions:
                warnings.append(
                    f"Statement {idx}: NotAction preserved as-is. Manual review recommended."
                )
                new_statements.append(copy.deepcopy(stmt))
                continue

            if stmt.not_resources:
                warnings.append(
                    f"Statement {idx}: NotResource preserved as-is. Manual review recommended."
                )
                new_statements.append(copy.deepcopy(stmt))
                continue

            working = copy.deepcopy(stmt)

            # Step 1: Replace wildcard actions
            working, changes = self._replace_wildcards(working, config, idx)
            all_changes.extend(changes)

            # Step 2: Scope resources
            working, changes = self._scope_resources(working, config, idx)
            all_changes.extend(changes)

            # Step 3: Add condition keys
            if config.add_conditions:
                working, changes = self._add_condition_keys(working, config, idx)
                all_changes.extend(changes)

            new_statements.append(working)

        # Step 4: Add companion permissions
        if config.add_companions:
            new_statements, changes, companions = self._add_companion_permissions(
                new_statements, config
            )
            all_changes.extend(changes)
            companions_added.extend(companions)

        # Step 5: Reorganize statements
        new_statements = self._reorganize_statements(
            new_statements, config.max_actions_per_statement
        )

        # Build assumptions list
        if not self.database:
            assumptions.append(
                "No IAM action database available. "
                "Wildcards could not be expanded to specific actions."
            )
        if not self.inventory:
            assumptions.append(
                "No resource inventory available. "
                "Placeholder ARNs used instead of real resource ARNs."
            )
        if config.intent:
            assumptions.append(f"Developer intent interpreted as: '{config.intent}'")

        rewritten = Policy(
            version=policy.version,
            statements=new_statements,
            id=policy.id,
        )

        return RewriteResult(
            original_policy=policy,
            rewritten_policy=rewritten,
            changes=all_changes,
            assumptions=assumptions,
            warnings=warnings,
            companion_permissions_added=companions_added,
        )

    def _replace_wildcards(
        self,
        statement: Statement,
        config: RewriteConfig,
        stmt_index: int = 0,
    ) -> tuple[Statement, list[RewriteChange]]:
        """Replace wildcard actions with specific actions from the database.

        Handles patterns: '*', '*:*', 'service:*', 'service:Get*'.

        Args:
            statement: Statement to process
            config: Rewrite configuration
            stmt_index: Index of the statement for change tracking

        Returns:
            Tuple of (modified statement, list of changes)
        """
        changes: list[RewriteChange] = []
        new_actions: list[str] = []

        for action in statement.actions:
            if "*" not in action:
                new_actions.append(action)
                continue

            expanded = self._expand_wildcard_action(action, config)

            if expanded and expanded != [action]:
                changes.append(
                    RewriteChange(
                        change_type="WILDCARD_REPLACED",
                        description=(
                            f"Replaced wildcard '{action}' with {len(expanded)} specific actions"
                        ),
                        original_value=action,
                        new_value=", ".join(expanded[:5]) + ("..." if len(expanded) > 5 else ""),
                        statement_index=stmt_index,
                    )
                )
                new_actions.extend(expanded)
            else:
                # Keep original wildcard if no expansion possible
                new_actions.append(action)

        statement.actions = new_actions
        return statement, changes

    def _expand_wildcard_action(
        self,
        action: str,
        config: RewriteConfig,
    ) -> list[str]:
        """Expand a wildcard action pattern to specific actions.

        Args:
            action: Wildcard action (e.g., 's3:*', 's3:Get*')
            config: Rewrite configuration

        Returns:
            List of specific action names, or original action if no expansion
        """
        if not self.database:
            return [action]

        # Full wildcard: expand based on intent or return as-is
        if action in ("*", "*:*"):
            if config.intent:
                return self._intent_based_expansion(config.intent)
            return [action]

        parts = action.split(":", 1)
        if len(parts) != 2:
            return [action]

        service_prefix, action_pattern = parts

        # service:* -> all actions for service
        if action_pattern == "*":
            db_actions = self.database.get_actions_by_service(service_prefix)
            if db_actions:
                return [f"{service_prefix}:{a.action_name}" for a in db_actions]
            return [action]

        # service:Get* or service:*Object -> prefix/suffix matching
        if action_pattern.endswith("*"):
            prefix = action_pattern[:-1]
            db_actions = self.database.get_actions_by_service(service_prefix)
            matches = [
                f"{service_prefix}:{a.action_name}"
                for a in db_actions
                if a.action_name.startswith(prefix)
            ]
            return matches if matches else [action]

        if action_pattern.startswith("*"):
            suffix = action_pattern[1:]
            db_actions = self.database.get_actions_by_service(service_prefix)
            matches = [
                f"{service_prefix}:{a.action_name}"
                for a in db_actions
                if a.action_name.endswith(suffix)
            ]
            return matches if matches else [action]

        return [action]

    def _intent_based_expansion(self, intent: str) -> list[str]:
        """Expand full wildcard based on developer intent.

        Args:
            intent: Developer intent string (e.g., 'read-only s3')

        Returns:
            List of specific action names matching the intent
        """
        if not self.database:
            return ["*"]

        # P0-3 α — deferred imports; see module docstring.
        from .constants import (
            SERVICE_NAME_MAPPINGS,
            READ_INTENT_KEYWORDS,
            WRITE_INTENT_KEYWORDS,
        )

        intent_lower = intent.lower()
        actions: list[str] = []

        # Extract service hints (word boundary to avoid e.g. "turkey" matching "key")
        target_services: list[str] = []
        for keyword, service in SERVICE_NAME_MAPPINGS.items():
            if re.search(r"\b" + re.escape(keyword) + r"\b", intent_lower):
                if service not in target_services:
                    target_services.append(service)

        # Determine access level from intent (word boundary matching)
        is_read_only = any(
            re.search(r"\b" + re.escape(kw) + r"\b", intent_lower) for kw in READ_INTENT_KEYWORDS
        )
        is_write = any(
            re.search(r"\b" + re.escape(kw) + r"\b", intent_lower) for kw in WRITE_INTENT_KEYWORDS
        )

        for svc in target_services:
            db_actions = self.database.get_actions_by_service(svc)
            for a in db_actions:
                if is_read_only and (a.is_list or a.is_read):
                    actions.append(f"{svc}:{a.action_name}")
                elif is_write and (a.is_list or a.is_read or a.is_write):
                    actions.append(f"{svc}:{a.action_name}")
                elif not is_read_only and not is_write:
                    actions.append(f"{svc}:{a.action_name}")

        return actions if actions else ["*"]

    def _scope_resources(
        self,
        statement: Statement,
        config: RewriteConfig,
        stmt_index: int = 0,
    ) -> tuple[Statement, list[RewriteChange]]:
        """Replace wildcard resources with specific or placeholder ARNs.

        Args:
            statement: Statement to process
            config: Rewrite configuration
            stmt_index: Index of the statement for change tracking

        Returns:
            Tuple of (modified statement, list of changes)
        """
        changes: list[RewriteChange] = []

        if not any(r == "*" for r in statement.resources):
            return statement, changes

        # Determine which services are needed from the actions
        services_needed: set[str] = set()
        for action in statement.actions:
            parts = action.split(":", 1)
            if len(parts) == 2:
                services_needed.add(parts[0])

        new_resources: list[str] = []

        for resource in statement.resources:
            if resource != "*":
                new_resources.append(resource)
                continue

            # Try to resolve real ARNs for each service
            resolved_any = False
            for service in sorted(services_needed):
                arns = self._resolve_resource_arns_for_service(service, statement.actions, config)
                if arns:
                    new_resources.extend(arns)
                    resolved_any = True
                    changes.append(
                        RewriteChange(
                            change_type="ARN_SCOPED",
                            description=(
                                f"Replaced wildcard resource with {len(arns)} ARN(s) for {service}"
                            ),
                            original_value="*",
                            new_value=", ".join(arns[:3]) + ("..." if len(arns) > 3 else ""),
                            statement_index=stmt_index,
                        )
                    )

            if not resolved_any:
                # Generate placeholder ARNs
                for service in sorted(services_needed):
                    placeholder = self._generate_placeholder_arn(service, statement.actions, config)
                    new_resources.append(placeholder)
                    changes.append(
                        RewriteChange(
                            change_type="ARN_SCOPED",
                            description=(
                                f"Generated placeholder ARN for {service} (replace with real ARN)"
                            ),
                            original_value="*",
                            new_value=placeholder,
                            statement_index=stmt_index,
                        )
                    )

        # Deduplicate while preserving order
        seen: set[str] = set()
        deduped: list[str] = []
        for r in new_resources:
            if r not in seen:
                seen.add(r)
                deduped.append(r)

        statement.resources = deduped if deduped else ["*"]
        return statement, changes

    def _resolve_resource_arns_for_service(
        self,
        service_prefix: str,
        actions: list[str],
        config: RewriteConfig,
    ) -> list[str]:
        """Resolve real ARNs from inventory for a service.

        Args:
            service_prefix: AWS service prefix
            actions: Actions in the statement (for resource type mapping)
            config: Rewrite configuration

        Returns:
            List of real resource ARN strings
        """
        if not self.inventory:
            return []

        if not self.inventory.has_resources_for_service(service_prefix):
            return []

        # Try action-specific resolution first
        arns: set[str] = set()
        for action in actions:
            if action.startswith(f"{service_prefix}:"):
                action_arns = self.inventory.get_arns_for_action(action)
                arns.update(action_arns)

        # Fall back to all resources for the service
        if not arns:
            all_arns = self.inventory.resolve_wildcard_resource(service_prefix)
            arns.update(all_arns)

        return sorted(arns)

    def _generate_placeholder_arn(
        self,
        service_prefix: str,
        actions: list[str],
        config: RewriteConfig,
    ) -> str:
        """Generate a placeholder ARN for a service.

        Args:
            service_prefix: AWS service prefix
            actions: Actions to determine resource type
            config: Rewrite configuration

        Returns:
            Placeholder ARN string
        """
        # Determine resource type from actions
        resource_type = self._infer_resource_type(service_prefix, actions)

        account_id = config.account_id or DEFAULT_ACCOUNT_ID
        region = config.region or DEFAULT_REGION

        # Task 7: prefer the bulk-loaded arn_templates lookup — resolves
        # without touching the inventory DB.  Composite key (svc:rt) is
        # tried first so future scoped templates override the base one.
        placeholder_name = f"PLACEHOLDER-{resource_type}-name"
        placeholder_id = f"PLACEHOLDER-{resource_type}-id"
        template = self._arn_templates.get(
            f"{service_prefix}:{resource_type}"
        ) or self._arn_templates.get(service_prefix)
        if template:
            return template.format(
                region=region,
                account_id=account_id,
                resource_type=resource_type,
                resource_name=placeholder_name,
                resource_id=placeholder_id,
            )

        if self.inventory:
            return self.inventory.generate_placeholder_arn(
                service_prefix, resource_type, account_id, region
            )

        # Fallback without inventory or a template match.
        return (
            f"arn:aws:{service_prefix}:{region}:{account_id}:"
            f"{resource_type}/{config.placeholder_format}-{resource_type}-name"
        )

    def _infer_resource_type(
        self,
        service_prefix: str,
        actions: list[str],
    ) -> str:
        """Infer resource type from service and actions.

        Args:
            service_prefix: AWS service prefix
            actions: List of IAM action names

        Returns:
            Inferred resource type string
        """
        # Task 7/8: single source of truth is the bulk-loaded
        # action_resource_map (from the IAM DB).  The former
        # inventory.ACTION_RESOURCE_MAP fallback was deleted in Task 8.
        if self._action_resource_map:
            for action in actions:
                if action in self._action_resource_map:
                    return self._action_resource_map[action]

        # Default resource types by service
        defaults: dict[str, str] = {
            "s3": "bucket",
            "ec2": "instance",
            "lambda": "function",
            "dynamodb": "table",
            "sqs": "queue",
            "sns": "topic",
            "kms": "key",
            "iam": "role",
            "rds": "db",
            "secretsmanager": "secret",
        }
        return defaults.get(service_prefix, "resource")

    def _add_companion_permissions(
        self,
        statements: list[Statement],
        config: RewriteConfig,
    ) -> tuple[list[Statement], list[RewriteChange], list[CompanionPermission]]:
        """Add missing companion permissions.

        Uses CompanionPermissionDetector to identify missing companions
        and creates new statements for them.

        Args:
            statements: Current list of statements
            config: Rewrite configuration

        Returns:
            Tuple of (updated statements, changes, companions added)
        """
        changes: list[RewriteChange] = []
        companions_added: list[CompanionPermission] = []

        # Work on a copy to avoid mutating the input list
        statements = list(statements)

        # Collect all Allow actions across all statements
        all_allow_actions: list[str] = []
        for stmt in statements:
            if stmt.effect == "Allow":
                all_allow_actions.extend(stmt.actions)

        # Detect missing companions
        missing = self.companion_detector.detect_missing_companions(all_allow_actions)

        if not missing:
            return statements, changes, companions_added

        # Group companion actions by creating new statements
        for companion in missing:
            companion_stmt = Statement(
                effect="Allow",
                actions=companion.companion_actions,
                resources=["*"],
                sid=self._generate_sid(companion.companion_actions, "Allow"),
            )

            # Always attempt to scope companion resources
            companion_stmt, _ = self._scope_resources(companion_stmt, config, len(statements))

            statements.append(companion_stmt)
            companions_added.append(companion)

            changes.append(
                RewriteChange(
                    change_type="COMPANION_ADDED",
                    description=(
                        f"Added companion permissions for "
                        f"{companion.primary_action}: "
                        f"{', '.join(companion.companion_actions)}"
                    ),
                    original_value="(missing)",
                    new_value=", ".join(companion.companion_actions),
                    statement_index=len(statements) - 1,
                )
            )

        return statements, changes, companions_added

    def _add_condition_keys(
        self,
        statement: Statement,
        config: RewriteConfig,
        stmt_index: int = 0,
    ) -> tuple[Statement, list[RewriteChange]]:
        """Add security-hardening condition keys to a statement.

        Adds conditions like aws:RequestedRegion and encryption requirements.
        Preserves existing conditions and merges new ones.

        Args:
            statement: Statement to add conditions to
            config: Rewrite configuration
            stmt_index: Index of the statement for change tracking

        Returns:
            Tuple of (modified statement, list of changes)
        """
        changes: list[RewriteChange] = []

        if statement.effect != "Allow":
            return statement, changes

        # Respect condition_profile: 'none' skips all injection
        if config.condition_profile == "none":
            return statement, changes

        # Resolve policy type (explicit or auto-detect)
        policy_type = config.policy_type
        if policy_type is None and hasattr(self, "_current_policy_type"):
            policy_type = self._current_policy_type

        conditions = copy.deepcopy(statement.conditions) if statement.conditions else {}
        added_any = False

        # Add region restriction if region is specified
        if config.region:
            from .constants import REGION_LESS_GLOBAL_SERVICES  # P0-3 α deferred

            services_in_stmt = {a.split(":")[0] for a in statement.actions if ":" in a}
            # Only add for regional services (not IAM, S3 buckets, etc.)
            regional_services = services_in_stmt - REGION_LESS_GLOBAL_SERVICES

            if regional_services:
                if "StringEquals" not in conditions:
                    conditions["StringEquals"] = {}
                if "aws:RequestedRegion" not in conditions.get("StringEquals", {}):
                    conditions["StringEquals"]["aws:RequestedRegion"] = config.region
                    added_any = True
                    changes.append(
                        RewriteChange(
                            change_type="CONDITION_ADDED",
                            description=(f"Added region restriction to {config.region}"),
                            original_value="(none)",
                            new_value=(f"aws:RequestedRegion = {config.region}"),
                            statement_index=stmt_index,
                        )
                    )

        # Add encryption requirement for S3 writes
        s3_write_actions = {
            "s3:PutObject",
            "s3:CopyObject",
            "s3:CreateMultipartUpload",
        }
        if any(a in s3_write_actions for a in statement.actions):
            if "StringEquals" not in conditions:
                conditions["StringEquals"] = {}
            if "s3:x-amz-server-side-encryption" not in conditions.get("StringEquals", {}):
                conditions["StringEquals"]["s3:x-amz-server-side-encryption"] = "aws:kms"
                added_any = True
                changes.append(
                    RewriteChange(
                        change_type="CONDITION_ADDED",
                        description="Added S3 server-side encryption requirement",
                        original_value="(none)",
                        new_value="s3:x-amz-server-side-encryption = aws:kms",
                        statement_index=stmt_index,
                    )
                )

        # Add source account condition for cross-service actions
        # aws:SourceAccount is meaningful in resource-based policies only,
        # not in identity policies where the caller IS the account.
        skip_source_account = policy_type == "identity"
        if config.account_id and not skip_source_account:
            cross_service_actions = {
                "lambda:InvokeFunction",
                "sns:Publish",
                "sqs:SendMessage",
            }
            if any(a in cross_service_actions for a in statement.actions):
                if "StringEquals" not in conditions:
                    conditions["StringEquals"] = {}
                if "aws:SourceAccount" not in conditions.get("StringEquals", {}):
                    conditions["StringEquals"]["aws:SourceAccount"] = config.account_id
                    added_any = True
                    changes.append(
                        RewriteChange(
                            change_type="CONDITION_ADDED",
                            description=(
                                "Added source account restriction for cross-service access"
                            ),
                            original_value="(none)",
                            new_value=(f"aws:SourceAccount = {config.account_id}"),
                            statement_index=stmt_index,
                        )
                    )

        if added_any:
            statement.conditions = conditions

        return statement, changes

    def _reorganize_statements(
        self,
        statements: list[Statement],
        max_actions: int = 15,
    ) -> list[Statement]:
        """Reorganize statements for clarity and readability.

        Groups related actions, splits large statements, and generates
        unique descriptive Sid values.

        Args:
            statements: List of statements to reorganize
            max_actions: Maximum actions per statement before splitting

        Returns:
            Reorganized list of statements
        """
        result: list[Statement] = []
        used_sids: set[str] = set()

        for stmt in statements:
            # Skip empty statements (no actions and no not_actions)
            if not stmt.actions and not stmt.not_actions:
                continue

            # Preserve Deny and non-standard statements as-is
            if stmt.effect == "Deny" or stmt.not_actions or stmt.not_resources:
                if not stmt.sid:
                    stmt.sid = self._generate_unique_sid(
                        stmt.actions or stmt.not_actions or [],
                        stmt.effect,
                        used_sids,
                    )
                used_sids.add(stmt.sid)
                result.append(stmt)
                continue

            # Split large statements
            if len(stmt.actions) > max_actions:
                split_stmts = self._split_statement(stmt, max_actions)
                for s in split_stmts:
                    s.sid = self._generate_unique_sid(s.actions, s.effect, used_sids)
                    used_sids.add(s.sid)
                result.extend(split_stmts)
            else:
                if not stmt.sid:
                    stmt.sid = self._generate_unique_sid(stmt.actions, stmt.effect, used_sids)
                used_sids.add(stmt.sid)
                result.append(stmt)

        return result

    def _split_statement(
        self,
        statement: Statement,
        max_actions: int,
    ) -> list[Statement]:
        """Split a large statement into smaller ones by access level.

        Groups actions into read, write, and admin categories, then
        further splits if any group exceeds max_actions.

        Args:
            statement: Statement to split
            max_actions: Maximum actions per split statement

        Returns:
            List of split statements
        """
        read_actions: list[str] = []
        write_actions: list[str] = []
        admin_actions: list[str] = []
        other_actions: list[str] = []

        for action in statement.actions:
            action_name = action.split(":")[-1] if ":" in action else action

            if any(action_name.startswith(p) for p in self.READ_PREFIXES):
                read_actions.append(action)
            elif any(action_name.startswith(p) for p in self.WRITE_PREFIXES):
                write_actions.append(action)
            elif any(action_name.startswith(p) for p in self.ADMIN_PREFIXES):
                admin_actions.append(action)
            else:
                other_actions.append(action)

        result: list[Statement] = []

        for group_actions, label in [
            (read_actions, "Read"),
            (write_actions, "Write"),
            (admin_actions, "Admin"),
            (other_actions, "Other"),
        ]:
            if not group_actions:
                continue

            # Further split if still too large
            for i in range(0, len(group_actions), max_actions):
                chunk = group_actions[i : i + max_actions]
                part_suffix = (
                    f"Part{i // max_actions + 1}" if len(group_actions) > max_actions else ""
                )

                new_stmt = Statement(
                    effect=statement.effect,
                    actions=chunk,
                    resources=list(statement.resources),
                    sid=None,  # Sid assigned by _reorganize_statements
                    conditions=(
                        copy.deepcopy(statement.conditions) if statement.conditions else None
                    ),
                    principals=(
                        copy.deepcopy(statement.principals) if statement.principals else None
                    ),
                )
                result.append(new_stmt)

        return result if result else [statement]

    def _generate_sid(self, actions: list[str], effect: str) -> str:
        """Generate a descriptive Sid from actions list.

        Creates human-readable statement IDs like 'AllowS3ReadAccess'
        or 'DenyIAMChanges'.

        Args:
            actions: List of IAM action names
            effect: Statement effect ('Allow' or 'Deny')

        Returns:
            Descriptive Sid string
        """
        if not actions:
            return f"{effect}GeneralAccess"

        # Extract service and action patterns
        services: set[str] = set()
        action_verbs: set[str] = set()

        for action in actions:
            parts = action.split(":", 1)
            if len(parts) == 2:
                services.add(parts[0].capitalize())
                verb = parts[1]
                # Extract verb prefix
                for prefix in (*self.READ_PREFIXES, *self.WRITE_PREFIXES):
                    if verb.startswith(prefix):
                        action_verbs.add(prefix)
                        break

        # Build Sid
        service_part = "".join(sorted(services)[:2])
        if not service_part:
            service_part = "General"

        # Determine access pattern
        if action_verbs:
            if action_verbs <= set(self.READ_PREFIXES):
                access_part = "ReadAccess"
            elif action_verbs <= set(self.WRITE_PREFIXES):
                access_part = "WriteAccess"
            else:
                access_part = "Access"
        elif len(actions) == 1:
            # Single action - use the action name directly
            action_name = actions[0].split(":")[-1] if ":" in actions[0] else (actions[0])
            access_part = action_name
        else:
            access_part = "Access"

        sid = f"{effect}{service_part}{access_part}"

        # Clean up: remove invalid characters
        sid = re.sub(r"[^A-Za-z0-9]", "", sid)

        return sid

    def _generate_unique_sid(
        self,
        actions: list[str],
        effect: str,
        used_sids: set[str],
    ) -> str:
        """Generate a unique Sid, appending a counter if needed.

        Args:
            actions: List of IAM action names
            effect: Statement effect
            used_sids: Set of already-used Sid strings

        Returns:
            Unique Sid string
        """
        base_sid = self._generate_sid(actions, effect)
        if base_sid not in used_sids:
            return base_sid
        counter = 2
        while f"{base_sid}{counter}" in used_sids:
            counter += 1
        return f"{base_sid}{counter}"

    def to_policy_json(self, policy: Policy) -> dict[str, Any]:
        """Convert Policy dataclass to IAM policy JSON format.

        Thin instance-method wrapper around the module-level
        :func:`serialize_policy` for backward compatibility.  The underlying
        transform is a pure function of ``policy`` — it does not read
        ``self.database`` or ``self.inventory`` — so callers that only need
        serialization (e.g. formatters) can call ``serialize_policy(policy)``
        directly without constructing a ``PolicyRewriter`` (which under Task
        8b D3 HARD-FAIL now requires a ``Database``).

        Args:
            policy: Policy object to convert

        Returns:
            Dictionary in standard IAM policy JSON format
        """
        return serialize_policy(policy)


def serialize_policy(policy: Policy) -> dict[str, Any]:
    """Convert a :class:`Policy` dataclass to an IAM policy JSON dict.

    Pure transform — no DB, no inventory, no side effects.  Split out of
    ``PolicyRewriter.to_policy_json`` so that output formatters (text/JSON/
    markdown) can render a rewritten policy without instantiating a
    ``PolicyRewriter`` (whose constructor now HARD-FAILS without a Database
    under Task 8b D3).

    Args:
        policy: Policy object to convert.

    Returns:
        Dictionary in standard IAM policy JSON format (Version / Id /
        Statement[Effect, Sid, Action|NotAction, Resource|NotResource,
        Condition, Principal]).
    """
    result: dict[str, Any] = {
        "Version": policy.version,
    }

    if policy.id:
        result["Id"] = policy.id

    statements: list[dict[str, Any]] = []
    for stmt in policy.statements:
        # Skip statements with no actions at all (can happen after
        # loop-back removes all invalid actions from a statement).
        if not stmt.actions and not stmt.not_actions:
            continue

        stmt_dict: dict[str, Any] = {
            "Effect": stmt.effect,
        }

        if stmt.sid:
            stmt_dict["Sid"] = stmt.sid

        if stmt.not_actions:
            stmt_dict["NotAction"] = stmt.not_actions
        else:
            stmt_dict["Action"] = stmt.actions[0] if len(stmt.actions) == 1 else stmt.actions

        if stmt.not_resources:
            stmt_dict["NotResource"] = stmt.not_resources
        elif stmt.resources:
            stmt_dict["Resource"] = (
                stmt.resources[0] if len(stmt.resources) == 1 else stmt.resources
            )
        else:
            stmt_dict["Resource"] = "*"

        if stmt.conditions:
            stmt_dict["Condition"] = stmt.conditions

        if stmt.principals:
            stmt_dict["Principal"] = stmt.principals

        statements.append(stmt_dict)

    result["Statement"] = statements
    return result

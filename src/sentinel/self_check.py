"""Self-check validator and pipeline orchestrator for IAM Policy Sentinel.

This module provides re-validation of rewritten policies, functional
completeness checking, remaining wildcard detection, Tier-2 action
preservation verification (Amendment 10, v0.8.0 -- NOT exclusion;
unknown actions are preserved in the rewrite with WARNING verdict),
assumption validation, and a loop-back mechanism that feeds failures
back to the rewriter bounded by ``--max-retries``.

Key behaviors:

* **Tier-2 preservation** (Amendment 10): ``_check_tier2_exclusion``
  emits findings at ``CheckSeverity.WARNING`` (was ``ERROR`` pre-v0.8.0);
  ``_apply_self_check_fixes`` only removes Tier-3 / ``ACTION_VALIDATION``
  (INVALID) actions. Unknown actions stay in ``rewritten_policy.statements``.
* **--strict** escalates WARNING verdict -> FAIL, restoring pre-v0.8.0
  safety for Tier-2 presence.
* **Issue 5 refuse-on-FAIL**: a FAIL verdict suppresses rewrite emission
  in the formatters unless ``--force-emit-rewrite`` is set (audited).
* **Pipeline DI** (P2-14): ``SelfCheckValidator.__init__`` accepts
  optional ``analyzer=`` and ``companion_detector=`` kwargs so Pipeline
  can reuse a single pre-built instance across the retry loop.
* **Shared DB connection** (P1-8 completion): the ``_validate_actions``
  loop wraps all classify calls in one ``get_connection()`` context.
* **Deferred constants import** (P0-3 α+γ): ``WRITE_PREFIXES`` and
  ``READ_INTENT_KEYWORDS`` are imported at function scope to avoid
  pulling pydantic-settings (~1.1s) on module import.
* **tier2_preserved_actions**: ``SelfCheckResult`` now exposes the list
  of preserved Tier-2 action strings (unions TIER2_IN_POLICY +
  TIER2_ACTION_KEPT -- M1 v0.8.1 fix). The deprecated
  ``tier2_excluded: bool`` shim remains for one release cycle but emits
  ``DeprecationWarning`` (L4 v0.8.1); scheduled for removal in v0.9.0.

See ``prod_imp.md § 17 Amendments 10 and 11`` for the decision record.
"""

from __future__ import annotations

import copy
import re
from dataclasses import dataclass, field
from enum import Enum
from typing import TYPE_CHECKING, Any

# P0-3 α+γ completion (phase 7.1) — constants imports deferred to function
# scope to break the cold-start chain.  Module-level
# `from .constants import WRITE_PREFIXES, READ_INTENT_KEYWORDS` triggers
# `_settings()` -> `get_settings()` -> pydantic_settings stack at first
# import (~1.1s).  The same deferred pattern already applied to analyzer,
# rewriter, and formatters in Phase 7; self_check.py was missed.
from .parser import (
    PolicyParser,
    Policy,
    Statement,
    ValidationResult,
    ValidationTier,
)
from .analyzer import (
    RiskAnalyzer,
    RiskFinding,
    RiskSeverity,
    CompanionPermissionDetector,
    AccessLevel,
    HITLSystem,
    HITLDecision,
)
from .rewriter import (
    PolicyRewriter,
    RewriteConfig,
    RewriteResult,
)
from .models import PolicyInput, PolicyOrigin

if TYPE_CHECKING:
    from .database import Database
    from .inventory import ResourceInventory


class CheckSeverity(Enum):
    """Severity levels for self-check findings.

    ERROR: Must fix before approval.
    WARNING: Should fix, may be acceptable.
    INFO: Informational observation.
    """

    ERROR = "ERROR"
    WARNING = "WARNING"
    INFO = "INFO"


class CheckVerdict(Enum):
    """Overall verdict from self-check validation.

    PASS: Policy meets all requirements.
    FAIL: Policy has errors that must be fixed.
    WARNING: Policy has warnings that should be reviewed.
    """

    PASS = "PASS"
    FAIL = "FAIL"
    WARNING = "WARNING"


@dataclass
class CheckFinding:
    """Individual finding from a self-check.

    Attributes:
        check_type: Category of check (e.g., ACTION_VALIDATION, ARN_FORMAT).
        severity: How severe the finding is.
        message: Human-readable description of the finding.
        action: IAM action associated with the finding, if any.
        resource: Resource ARN associated with the finding, if any.
        remediation: Suggested fix for the finding.
    """

    check_type: str
    severity: CheckSeverity
    message: str
    action: str | None = None
    resource: str | None = None
    remediation: str | None = None


@dataclass
class SelfCheckResult:
    """Aggregate result from all self-check validations.

    Attributes:
        verdict: Overall pass/fail/warning verdict.
        findings: All findings from the self-check.
        completeness_score: Coverage score from 0.0 to 1.0.
        assumptions_valid: Whether rewrite assumptions are reasonable.
        tier2_preserved_actions: List of Tier-2 (unknown) action strings
            preserved in the rewritten policy. Issue 2 (v0.8.0, Amendment 10)
            renamed this field from the legacy ``tier2_excluded: bool`` — the
            new semantic says "these were kept for manual review" rather than
            "these were dropped". A non-empty list means the verdict should
            be WARNING (or FAIL under --strict).
        summary: Human-readable summary of the self-check.
        confidence_summary: Per-aspect confidence scores from the pipeline.
    """

    verdict: CheckVerdict
    findings: list[CheckFinding]
    completeness_score: float
    assumptions_valid: bool
    tier2_preserved_actions: list[str]
    summary: str
    confidence_summary: dict[str, float] = field(default_factory=dict)

    @property
    def tier2_excluded(self) -> bool:
        """Backward-compat shim for the legacy ``tier2_excluded`` bool.

        Returns True when no Tier-2 actions survived the rewrite (i.e.
        ``tier2_preserved_actions`` is empty). Downstream consumers that
        still read ``tier2_excluded`` keep working; new code should read
        ``tier2_preserved_actions`` directly.

        v0.8.1 (L4): access now emits DeprecationWarning. The shim is
        semantically lossy — a corpus-populated DB run with zero Tier-2
        actions produces the same ``True`` value as a v0.7.0 run where
        actions WERE excluded, giving legacy consumers a false-negative
        warning path. Removal scheduled for v0.9.0.
        """
        import warnings

        warnings.warn(
            "tier2_excluded is deprecated; use tier2_preserved_actions "
            "(v0.8.0 Amendment 10). This shim will be removed in v0.9.0.",
            DeprecationWarning,
            stacklevel=2,
        )
        return not self.tier2_preserved_actions


@dataclass
class PipelineConfig:
    """Configuration for the end-to-end pipeline.

    Attributes:
        intent: Developer intent description.
        account_id: AWS account ID for ARN generation.
        region: AWS region for ARN generation.
        strict_mode: If True, WARNINGs are treated as FAILs.
        max_self_check_retries: Maximum loop-back iterations.
        add_companions: Whether to add companion permissions.
        add_conditions: Whether to inject condition keys.
        interactive: If True, prompt user for Tier 2 action approval.
        policy_type: Policy type hint (identity/resource/scp/boundary/None).
        condition_profile: Condition injection profile (strict/moderate/none).
        allow_wildcard_actions: Downgrade wildcard action ERRORs to WARNINGs.
        allow_wildcard_resources: Downgrade wildcard resource ERRORs to WARNINGs.
    """

    intent: str | None = None
    account_id: str | None = None
    region: str | None = None
    strict_mode: bool = False
    max_self_check_retries: int = 3
    add_companions: bool = True
    add_conditions: bool = True
    interactive: bool = False
    policy_type: str | None = None
    condition_profile: str = "moderate"
    allow_wildcard_actions: bool = False
    allow_wildcard_resources: bool = False


@dataclass
class PipelineResult:
    """Result of the full Validate-Analyze-Rewrite-SelfCheck pipeline.

    Attributes:
        original_policy: The input policy.
        rewritten_policy: The final rewritten policy.
        validation_results: Tier classifications from the VALIDATE step.
        risk_findings: Security risks from the ANALYZE step.
        rewrite_result: Output from the REWRITE step.
        self_check_result: Output from the SELF-CHECK step.
        iterations: Number of self-check loop-back iterations run.
        final_verdict: The final verdict after all iterations.
        pipeline_summary: Human-readable pipeline summary.
        hitl_decisions: HITL decisions for Tier 2 actions (empty if
            non-interactive).
    """

    original_policy: Policy
    rewritten_policy: Policy
    validation_results: list[ValidationResult]
    risk_findings: list[RiskFinding]
    rewrite_result: RewriteResult
    self_check_result: SelfCheckResult
    iterations: int
    final_verdict: CheckVerdict
    pipeline_summary: str
    hitl_decisions: list[HITLDecision] = field(default_factory=list)
    # M5 § 8.4 — provenance record of the input bytes.  Optional so
    # legacy callers that passed raw strings still work (a synthetic
    # stdin origin is attached via run_text()).
    origin: PolicyOrigin | None = None


# ARN format: starts with arn: and has at least 5 colon-separated parts
_ARN_BASIC_PATTERN = re.compile(r"^arn:[^:]+:[^:]+:[^:]*:[^:]*:.+$")


class SelfCheckValidator:
    """Re-validates rewritten policies for correctness and completeness.

    Runs six checks: action validation, ARN format, functional completeness,
    overly broad permissions, Tier 2 exclusion, and assumption validation.
    """

    def __init__(
        self,
        database: Database | None = None,
        inventory: ResourceInventory | None = None,
        *,
        risk_analyzer: RiskAnalyzer | None = None,
        companion_detector: CompanionPermissionDetector | None = None,
    ):
        """Initialize self-check validator.

        Args:
            database: Optional Database instance for action lookups.
            inventory: Optional ResourceInventory for ARN validation.
            risk_analyzer: P2-14 α DI slot — pre-built RiskAnalyzer
                instance to reuse.  Falls back to ``RiskAnalyzer(database)``
                if not provided (backward compat for direct callers).
            companion_detector: P2-14 α DI slot — pre-built
                CompanionPermissionDetector to reuse.  Falls back to
                ``CompanionPermissionDetector(database)`` if absent.
        """
        self.database = database
        self.inventory = inventory
        self.parser = PolicyParser(database)
        self.risk_analyzer = risk_analyzer or RiskAnalyzer(database)
        self.companion_detector = companion_detector or CompanionPermissionDetector(database)
        # U27: precompile READ_INTENT_KEYWORDS word-boundary patterns
        # once at __init__ so _check_functional_completeness doesn't
        # rebuild ~12 regexes on every self-check run.  Mirrors the
        # P2-15 α/β precompile-in-__init__ precedent in
        # analyzer.IntentMapper (analyzer.py:148-166).  The deferred
        # import preserves the P0-3 α cold-start contract —
        # SelfCheckValidator is never instantiated on
        # ``sentinel --version`` / metadata-only paths.
        from .constants import READ_INTENT_KEYWORDS

        self._compiled_read_intent_patterns: list[re.Pattern[str]] = [
            re.compile(r"\b" + re.escape(kw) + r"\b") for kw in READ_INTENT_KEYWORDS
        ]

    def run_self_check(
        self,
        rewrite_result: RewriteResult,
        config: PipelineConfig | None = None,
    ) -> SelfCheckResult:
        """Run all self-check validations on a rewritten policy.

        Orchestrates all six checks, computes a verdict and completeness
        score, and returns a unified result.

        Args:
            rewrite_result: Output from the rewriter.
            config: Pipeline configuration (defaults applied if None).

        Returns:
            SelfCheckResult with verdict, findings, and scores.
        """
        if config is None:
            config = PipelineConfig()

        policy = rewrite_result.rewritten_policy
        findings: list[CheckFinding] = []

        # Check 1: Validate actions
        findings.extend(self._validate_actions(policy))

        # Check 2: Check ARN formats
        findings.extend(self._check_arn_formats(policy, config))

        # Check 3: Functional completeness
        completeness_findings, completeness_score = self._check_functional_completeness(
            policy, rewrite_result, config
        )
        findings.extend(completeness_findings)

        # Check 4: Overly broad permissions
        findings.extend(self._check_overly_broad_permissions(policy, config))

        # Check 5: Tier 2 exclusion
        original_validation = self.parser.validate_policy(rewrite_result.original_policy)
        findings.extend(self._check_tier2_exclusion(policy, original_validation))

        # Check 6: Assumption validation
        assumption_findings = self._check_assumptions(rewrite_result)
        findings.extend(assumption_findings)
        assumptions_valid = not any(f.severity == CheckSeverity.ERROR for f in assumption_findings)

        # Check 7: Low-confidence rewrite decisions
        findings.extend(self._check_low_confidence(rewrite_result))

        # Issue 2 (v0.8.0, Amendment 10): record the list of Tier-2 actions
        # actually preserved in the rewritten policy. Replaces the legacy
        # ``tier2_excluded: bool`` which became semantically meaningless
        # after TIER2_IN_POLICY severity dropped to WARNING (the old
        # predicate would always be True).
        #
        # v0.8.1 (M1): union both surface paths — Tier-2 actions surface via
        # TIER2_IN_POLICY (from _check_tier2_exclusion) and TIER2_ACTION_KEPT
        # (from _validate_actions). The field name implies complete audit of
        # preserved Tier-2 actions; both paths must feed into it.
        tier2_preserved_actions = sorted(
            {
                f.action
                for f in findings
                if f.check_type in ("TIER2_IN_POLICY", "TIER2_ACTION_KEPT") and f.action is not None
            }
        )

        # Compute verdict
        verdict = self._compute_verdict(findings, config.strict_mode)

        # Build summary
        error_count = sum(1 for f in findings if f.severity == CheckSeverity.ERROR)
        warning_count = sum(1 for f in findings if f.severity == CheckSeverity.WARNING)
        info_count = sum(1 for f in findings if f.severity == CheckSeverity.INFO)
        summary = (
            f"Self-check {verdict.value}: "
            f"{error_count} error(s), {warning_count} warning(s), "
            f"{info_count} info. "
            f"Completeness: {completeness_score:.0%}"
        )

        return SelfCheckResult(
            verdict=verdict,
            findings=findings,
            completeness_score=completeness_score,
            assumptions_valid=assumptions_valid,
            tier2_preserved_actions=tier2_preserved_actions,
            summary=summary,
        )

    def _validate_actions(self, policy: Policy) -> list[CheckFinding]:
        """Re-validate every action in the rewritten policy.

        Flags Tier 3 actions as ERROR and Tier 2 (unknown) actions as
        WARNING — Tier 2 actions are preserved per Issue 2 (v0.8.0 /
        Amendment 10) to avoid silently dropping user intent.

        P1-8 β completion (phase 7.1): when ``self.database`` is available,
        share a single DB connection across the per-action classify loop.
        Previously each ``classify_action`` call opened its own connection
        (up to 3 round-trips per action) — for a 20-action rewritten policy
        that's ~60 connections where 1 suffices.  Mirrors the pattern
        ``PolicyParser.validate_policy`` uses post-P1-8 β.

        Args:
            policy: Rewritten policy to validate.

        Returns:
            List of CheckFinding objects.
        """
        findings: list[CheckFinding] = []

        if self.database is None:
            # Fallback: no DB -> per-action classify_action (which returns
            # TIER_2_UNKNOWN on every action without DB access anyway).
            for stmt in policy.statements:
                for action in stmt.actions:
                    if action == "*" or action == "*:*":
                        continue
                    result = self.parser.classify_action(action)
                    self._append_validate_finding(findings, action, result)
            return findings

        with self.database.get_connection() as conn:
            for stmt in policy.statements:
                for action in stmt.actions:
                    if action == "*" or action == "*:*":
                        continue
                    result = self.parser._classify_action_with_conn(action, conn)
                    self._append_validate_finding(findings, action, result)

        return findings

    def _append_validate_finding(
        self,
        findings: list[CheckFinding],
        action: str,
        result: ValidationResult,
    ) -> None:
        """Append a CheckFinding for a Tier 3 (invalid) or Tier 2 (unknown) action.

        Extracted helper for the shared-connection refactor so both the
        no-DB fallback path and the shared-connection hot path build
        findings identically.
        """
        if result.tier == ValidationTier.TIER_3_INVALID:
            findings.append(
                CheckFinding(
                    check_type="ACTION_VALIDATION",
                    severity=CheckSeverity.ERROR,
                    message=(f"Invalid action '{action}' in rewritten policy: {result.reason}"),
                    action=action,
                    remediation=f"Remove invalid action '{action}'",
                )
            )
        elif result.tier == ValidationTier.TIER_2_UNKNOWN:
            findings.append(
                CheckFinding(
                    check_type="TIER2_ACTION_KEPT",
                    severity=CheckSeverity.WARNING,
                    message=(
                        f"Tier 2 unknown action '{action}' kept in "
                        "rewritten policy (requires manual review)"
                    ),
                    action=action,
                    remediation=(f"Verify action '{action}' exists or refresh the IAM database"),
                )
            )

    def _check_arn_formats(
        self,
        policy: Policy,
        config: PipelineConfig | None = None,
    ) -> list[CheckFinding]:
        """Validate ARN formats in the rewritten policy.

        Checks for remaining wildcards, placeholder markers, and
        malformed ARN strings.

        Args:
            policy: Rewritten policy to validate.

        Returns:
            List of CheckFinding objects.
        """
        findings: list[CheckFinding] = []

        for stmt in policy.statements:
            # Check both resources and not_resources for ARN issues
            all_resources = list(stmt.resources)
            if stmt.not_resources:
                all_resources.extend(stmt.not_resources)

            allow_wc_res = config.allow_wildcard_resources if config else False
            for resource in all_resources:
                if resource == "*":
                    severity = CheckSeverity.WARNING if allow_wc_res else CheckSeverity.ERROR
                    findings.append(
                        CheckFinding(
                            check_type="REMAINING_WILDCARD",
                            severity=severity,
                            message="Wildcard resource '*' remains in rewritten policy",
                            resource=resource,
                            remediation=(
                                "Replace with specific resource ARNs "
                                "(use --allow-wildcard-resources to downgrade)"
                            ),
                        )
                    )
                elif "PLACEHOLDER" in resource:
                    findings.append(
                        CheckFinding(
                            check_type="PLACEHOLDER_ARN",
                            severity=CheckSeverity.INFO,
                            message=(
                                f"Placeholder ARN '{resource}' needs to be "
                                "replaced with a real ARN before deployment"
                            ),
                            resource=resource,
                            remediation=("Replace placeholder with actual resource ARN"),
                        )
                    )
                elif resource.startswith("arn:"):
                    if not _ARN_BASIC_PATTERN.match(resource):
                        findings.append(
                            CheckFinding(
                                check_type="ARN_FORMAT",
                                severity=CheckSeverity.ERROR,
                                message=(
                                    f"Malformed ARN: '{resource}'. Expected format: "
                                    "arn:partition:service:region:account:resource"
                                ),
                                resource=resource,
                                remediation="Fix the ARN format",
                            )
                        )

        return findings

    def _check_functional_completeness(
        self,
        policy: Policy,
        rewrite_result: RewriteResult,
        config: PipelineConfig,
    ) -> tuple[list[CheckFinding], float]:
        """Check if the rewritten policy preserves functional completeness.

        Verifies service coverage, companion permissions, access level
        alignment with intent, and action coverage.

        Args:
            policy: Rewritten policy.
            rewrite_result: Full rewrite result with original policy.
            config: Pipeline configuration.

        Returns:
            Tuple of (findings list, completeness score 0.0-1.0).
        """
        findings: list[CheckFinding] = []
        original = rewrite_result.original_policy

        # Extract services from original and rewritten
        original_services = self._extract_services(original)
        rewritten_services = self._extract_services(policy)

        # Score component 1: Service coverage (weight 0.3)
        if original_services:
            covered = original_services & rewritten_services
            service_score = len(covered) / len(original_services)
        else:
            service_score = 1.0

        missing_services = original_services - rewritten_services
        if missing_services:
            findings.append(
                CheckFinding(
                    check_type="MISSING_SERVICE_COVERAGE",
                    severity=CheckSeverity.WARNING,
                    message=(
                        f"Services from original policy not covered in rewritten "
                        f"policy: {', '.join(sorted(missing_services))}"
                    ),
                    remediation="Add actions for missing services",
                )
            )

        # Score component 2: Access level match with intent (weight 0.3)
        access_level_score = 1.0
        if config.intent:
            # U27: iterate precompiled patterns built at __init__ time.
            intent_lower = config.intent.lower()
            is_read_only = any(
                pat.search(intent_lower) for pat in self._compiled_read_intent_patterns
            )
            if is_read_only:
                write_actions = self._find_write_actions(policy)
                if write_actions:
                    access_level_score = 0.5
                    findings.append(
                        CheckFinding(
                            check_type="INTENT_MISMATCH",
                            severity=CheckSeverity.WARNING,
                            message=(
                                f"Intent is read-only but rewritten policy "
                                f"contains write actions: "
                                f"{', '.join(write_actions[:3])}"
                            ),
                            remediation=("Remove write actions to match read-only intent"),
                        )
                    )

        # Score component 3: Companion completeness (weight 0.2)
        all_actions = self._collect_allow_actions(policy)
        missing_companions = self.companion_detector.detect_missing_companions(all_actions)
        if missing_companions:
            companion_score = max(
                0.0,
                1.0 - (len(missing_companions) * 0.25),
            )
            for comp in missing_companions:
                findings.append(
                    CheckFinding(
                        check_type="MISSING_COMPANION",
                        severity=CheckSeverity.WARNING,
                        message=(
                            f"Missing companion permissions for "
                            f"{comp.primary_action}: "
                            f"{', '.join(comp.companion_actions)}"
                        ),
                        action=comp.primary_action,
                        remediation=(f"Add companion actions: {', '.join(comp.companion_actions)}"),
                    )
                )
        else:
            companion_score = 1.0

        # Score component 4: Action coverage (weight 0.2)
        original_actions = self._collect_allow_actions(original)
        rewritten_actions = set(all_actions)
        if original_actions:
            # Check how many original specific actions are still covered
            original_specific = {a for a in original_actions if "*" not in a}
            if original_specific:
                covered_actions = original_specific & rewritten_actions
                action_score = len(covered_actions) / len(original_specific)
            else:
                # Original was all wildcards, any expansion is fine
                action_score = 1.0 if rewritten_actions else 0.0
        else:
            action_score = 1.0

        # Weighted completeness score
        completeness_score = (
            service_score * 0.3
            + access_level_score * 0.3
            + companion_score * 0.2
            + action_score * 0.2
        )

        # Clamp to 0.0-1.0
        completeness_score = max(0.0, min(1.0, completeness_score))

        return findings, completeness_score

    def _check_overly_broad_permissions(
        self,
        policy: Policy,
        config: PipelineConfig | None = None,
    ) -> list[CheckFinding]:
        """Check for surviving wildcard actions and resources.

        Full wildcards (*, *:*) are ERROR by default (fail-closed).
        Service wildcards (s3:*) remain WARNING. Partial wildcards
        remain INFO. Use config.allow_wildcard_actions to downgrade.

        Args:
            policy: Rewritten policy to check.

        Returns:
            List of CheckFinding objects.
        """
        findings: list[CheckFinding] = []
        allow_wc_actions = config.allow_wildcard_actions if config else False

        for stmt in policy.statements:
            if stmt.effect != "Allow":
                continue

            for action in stmt.actions:
                if action == "*" or action == "*:*":
                    severity = CheckSeverity.WARNING if allow_wc_actions else CheckSeverity.ERROR
                    findings.append(
                        CheckFinding(
                            check_type="OVERLY_BROAD_ACTION",
                            severity=severity,
                            message=(f"Full wildcard action '{action}' in rewritten policy"),
                            action=action,
                            remediation=(
                                "Replace with specific service actions "
                                "(use --allow-wildcard-actions to downgrade)"
                            ),
                        )
                    )
                elif action.endswith(":*"):
                    findings.append(
                        CheckFinding(
                            check_type="OVERLY_BROAD_ACTION",
                            severity=CheckSeverity.WARNING,
                            message=(f"Service wildcard action '{action}' in rewritten policy"),
                            action=action,
                            remediation=("Replace with specific actions for the service"),
                        )
                    )
                elif "*" in action:
                    findings.append(
                        CheckFinding(
                            check_type="OVERLY_BROAD_ACTION",
                            severity=CheckSeverity.INFO,
                            message=(f"Partial wildcard action '{action}' in rewritten policy"),
                            action=action,
                            remediation=("Consider replacing with specific actions"),
                        )
                    )

        return findings

    def _check_tier2_exclusion(
        self,
        policy: Policy,
        validation_results: list[ValidationResult],
    ) -> list[CheckFinding]:
        """Verify no Tier 2 actions from original validation appear in rewritten policy.

        Cross-references the original validation results with the rewritten
        policy to ensure unknown actions were excluded.

        Args:
            policy: Rewritten policy.
            validation_results: Validation results from the original policy.

        Returns:
            List of CheckFinding objects.
        """
        findings: list[CheckFinding] = []

        tier2_actions = {
            r.action for r in validation_results if r.tier == ValidationTier.TIER_2_UNKNOWN
        }

        if not tier2_actions:
            return findings

        rewritten_actions = set()
        for stmt in policy.statements:
            rewritten_actions.update(stmt.actions)
            if stmt.not_actions:
                rewritten_actions.update(stmt.not_actions)

        # Issue 2 (v0.8.0, Amendment 10): Tier-2 actions are now PRESERVED
        # in the rewritten policy (not silently removed). Finding severity
        # downgraded from ERROR to WARNING — preserves the safety signal
        # via verdict=WARNING but refuses to drop the operator's actions.
        # Under --strict the WARNING escalates to FAIL, keeping the
        # fail-closed default available for CI pipelines.
        for action in sorted(tier2_actions & rewritten_actions):
            findings.append(
                CheckFinding(
                    check_type="TIER2_IN_POLICY",
                    severity=CheckSeverity.WARNING,
                    message=(
                        f"Tier 2 unknown action '{action}' preserved for "
                        "manual review. Run 'sentinel refresh' to verify."
                    ),
                    action=action,
                    remediation=(
                        f"Verify '{action}' is intentional, then run "
                        "sentinel refresh to populate the action corpus."
                    ),
                )
            )

        return findings

    def _check_assumptions(
        self,
        rewrite_result: RewriteResult,
    ) -> list[CheckFinding]:
        """Validate that the rewrite result includes meaningful assumptions.

        Checks that at minimum the database/inventory availability is
        documented, and that assumption strings are non-empty.

        Args:
            rewrite_result: Output from the rewriter.

        Returns:
            List of CheckFinding objects.
        """
        findings: list[CheckFinding] = []

        if not rewrite_result.assumptions:
            findings.append(
                CheckFinding(
                    check_type="MISSING_ASSUMPTIONS",
                    severity=CheckSeverity.WARNING,
                    message=(
                        "No assumptions recorded during rewrite. "
                        "At minimum, database and inventory status should be noted."
                    ),
                    remediation=(
                        "Document assumptions about database availability and resource inventory"
                    ),
                )
            )
            return findings

        for assumption in rewrite_result.assumptions:
            if not assumption or not assumption.strip():
                findings.append(
                    CheckFinding(
                        check_type="EMPTY_ASSUMPTION",
                        severity=CheckSeverity.WARNING,
                        message="Empty assumption string found in rewrite result",
                        remediation="Remove empty assumptions or add content",
                    )
                )

        return findings

    def _check_low_confidence(
        self,
        rewrite_result: RewriteResult,
    ) -> list[CheckFinding]:
        """Flag rewrite changes with confidence below 0.5.

        Args:
            rewrite_result: Output from the rewriter.

        Returns:
            List of CheckFinding objects for low-confidence decisions.
        """
        findings: list[CheckFinding] = []
        for change in rewrite_result.changes:
            if change.confidence < 0.5:
                findings.append(
                    CheckFinding(
                        check_type="LOW_CONFIDENCE",
                        severity=CheckSeverity.WARNING,
                        message=(
                            f"Low confidence ({change.confidence}) on "
                            f"{change.change_type}: {change.description}"
                        ),
                        remediation="Review this change manually",
                    )
                )
        return findings

    def _compute_verdict(
        self,
        findings: list[CheckFinding],
        strict_mode: bool,
    ) -> CheckVerdict:
        """Compute the overall verdict from findings.

        ERROR findings always produce FAIL. WARNING findings produce FAIL
        in strict mode, WARNING in normal mode. No errors/warnings produce PASS.

        Args:
            findings: All check findings.
            strict_mode: Whether to treat warnings as failures.

        Returns:
            CheckVerdict (PASS, FAIL, or WARNING).
        """
        has_error = any(f.severity == CheckSeverity.ERROR for f in findings)
        has_warning = any(f.severity == CheckSeverity.WARNING for f in findings)

        if has_error:
            return CheckVerdict.FAIL

        if has_warning:
            if strict_mode:
                return CheckVerdict.FAIL
            return CheckVerdict.WARNING

        return CheckVerdict.PASS

    def _extract_services(self, policy: Policy) -> set[str]:
        """Extract unique service prefixes from a policy.

        Args:
            policy: Policy to extract services from.

        Returns:
            Set of service prefix strings.
        """
        services: set[str] = set()
        for stmt in policy.statements:
            all_actions = list(stmt.actions)
            if stmt.not_actions:
                all_actions.extend(stmt.not_actions)
            for action in all_actions:
                parts = action.split(":", 1)
                if len(parts) == 2 and parts[0] != "*":
                    services.add(parts[0])
        return services

    def _find_write_actions(self, policy: Policy) -> list[str]:
        """Find actions that are likely write-level.

        Args:
            policy: Policy to scan.

        Returns:
            List of write action names.
        """
        from .constants import WRITE_PREFIXES  # P0-3 α+γ deferred (phase 7.1)

        write_actions: list[str] = []
        for stmt in policy.statements:
            if stmt.effect != "Allow":
                continue
            for action in stmt.actions:
                action_name = action.split(":")[-1] if ":" in action else action
                if any(action_name.startswith(p) for p in WRITE_PREFIXES):
                    write_actions.append(action)
        return write_actions

    def _collect_allow_actions(self, policy: Policy) -> list[str]:
        """Collect all actions from Allow statements.

        Args:
            policy: Policy to collect from.

        Returns:
            List of action name strings.
        """
        actions: list[str] = []
        for stmt in policy.statements:
            if stmt.effect == "Allow":
                actions.extend(stmt.actions)
        return actions


class Pipeline:
    """End-to-end Validate-Analyze-Rewrite-SelfCheck pipeline.

    Orchestrates all four pipeline steps and implements a loop-back
    mechanism that feeds self-check failures back to the rewriter.
    """

    def __init__(
        self,
        database: Database | None = None,
        inventory: ResourceInventory | None = None,
        config: PipelineConfig | None = None,
    ):
        """Initialize pipeline.

        Args:
            database: Optional Database instance.
            inventory: Optional ResourceInventory instance.
            config: Optional default :class:`PipelineConfig` (H2 DI slot).
                When provided, :meth:`run` uses this instance unless the
                caller passes a ``config`` argument of its own.  Library
                users get a clean injection point without monkey-patching;
                CLI callers keep their existing "pass per-run config"
                pattern and see zero behaviour change.
        """
        self.database = database
        self.inventory = inventory
        self.config = config
        # P2-14 α — eagerly construct both analyzer + companion detector
        # so Pipeline.run reuses one instance across pipeline stages AND
        # across self-check retry iterations (up to
        # ``config.max_self_check_retries``).  Previously
        # ``Pipeline.run`` constructed fresh instances on every call,
        # bypassing the bulk-load cache.
        self._risk_analyzer = RiskAnalyzer(database)
        self._companion_detector = CompanionPermissionDetector(database)

    def run(
        self,
        policy_input: "PolicyInput | str",
        config: PipelineConfig | None = None,
    ) -> PipelineResult:
        """Run the full pipeline on a :class:`PolicyInput`.

        Steps:
        1. VALIDATE: Parse and classify all actions.
        2. ANALYZE: Detect risks and missing companions.
        3. REWRITE: Generate least-privilege policy.
        4. SELF-CHECK: Validate the rewritten policy.
        Loop-back: If self-check fails and retries remain, apply fixes and
        re-run steps 3-4.

        Args:
            policy_input: Either a :class:`PolicyInput` (M4 primary) OR a
                raw JSON string (legacy path — routed through
                :meth:`run_text` with a DeprecationWarning).
            config: Pipeline configuration (defaults applied if None).

        Returns:
            PipelineResult with all step outputs and the PolicyOrigin.
        """
        if isinstance(policy_input, str):
            # M4 back-compat: detect the legacy string input and route
            # through run_text(), which stamps a stdin PolicyOrigin.
            # DeprecationWarning gives test-suite / library users a
            # migration nudge without breaking them.
            import warnings

            warnings.warn(
                "Pipeline.run(str) is deprecated; pass a PolicyInput "
                "(see sentinel.models.PolicyInput) or call "
                "Pipeline.run_text() for the legacy behaviour.",
                DeprecationWarning,
                stacklevel=2,
            )
            return self.run_text(policy_input, config=config)

        if config is None:
            # H2 DI slot: prefer the instance-level default over a fresh
            # PipelineConfig() when the caller didn't pass one explicitly.
            config = self.config if self.config is not None else PipelineConfig()

        # Step 1: VALIDATE
        parser = PolicyParser(self.database)
        policy = parser.parse_policy(policy_input.text)
        validation_results = parser.validate_policy(policy)

        # Step 2: ANALYZE
        all_actions: list[str] = []
        for stmt in policy.statements:
            all_actions.extend(stmt.actions)
            if stmt.not_actions:
                all_actions.extend(stmt.not_actions)

        # P2-14 α — reuse the pre-built instances from __init__
        risk_findings = self._risk_analyzer.analyze_actions(all_actions)
        missing_companions = self._companion_detector.detect_missing_companions(all_actions)

        # Step 2.5: HITL - Interactive Tier 2 action review
        hitl = HITLSystem(interactive=config.interactive)
        tier2_actions = [r for r in validation_results if r.tier == ValidationTier.TIER_2_UNKNOWN]
        rejected_actions: set[str] = set()

        if tier2_actions and config.interactive:
            for vr in tier2_actions:
                assumptions = [vr.reason] if vr.reason else []
                approved = hitl.flag_tier2_action(vr.action, assumptions)
                if not approved:
                    rejected_actions.add(vr.action)

            # Remove rejected actions from policy before rewriting
            if rejected_actions:
                policy = copy.deepcopy(policy)
                for stmt in policy.statements:
                    stmt.actions = [a for a in stmt.actions if a not in rejected_actions]
                policy.statements = [s for s in policy.statements if s.actions or s.not_actions]

        # Step 3: REWRITE
        rewriter = PolicyRewriter(self.database, self.inventory)
        rewrite_config = self._build_rewrite_config(config)
        rewrite_result = rewriter.rewrite_policy(policy, rewrite_config)

        # Step 4: SELF-CHECK with loop-back.  P2-14 α — pass the
        # already-built analyzer + detector so the SelfCheckValidator
        # doesn't re-bulk-load from the DB.
        checker = SelfCheckValidator(
            self.database,
            self.inventory,
            risk_analyzer=self._risk_analyzer,
            companion_detector=self._companion_detector,
        )
        self_check_result = checker.run_self_check(rewrite_result, config)

        iterations = 1

        while (
            self_check_result.verdict == CheckVerdict.FAIL
            and iterations < config.max_self_check_retries
        ):
            # Apply targeted fixes based on findings
            previous_policy = rewrite_result.rewritten_policy
            fixed_policy = self._apply_self_check_fixes(
                previous_policy,
                self_check_result.findings,
            )

            # Break early if fixes made no changes or policy is empty
            if not fixed_policy.statements or fixed_policy.statements == previous_policy.statements:
                break

            # Re-run rewrite on the fixed policy
            rewrite_result = RewriteResult(
                original_policy=rewrite_result.original_policy,
                rewritten_policy=fixed_policy,
                changes=rewrite_result.changes,
                assumptions=rewrite_result.assumptions,
                warnings=rewrite_result.warnings,
                companion_permissions_added=(rewrite_result.companion_permissions_added),
            )

            # Re-run self-check
            self_check_result = checker.run_self_check(rewrite_result, config)
            iterations += 1

        # Build summary
        summary_parts = [
            f"Pipeline completed in {iterations} iteration(s).",
            f"Validation: {len(validation_results)} actions classified.",
            f"Risk analysis: {len(risk_findings)} finding(s).",
            f"Rewrite: {len(rewrite_result.changes)} change(s).",
            f"Self-check: {self_check_result.verdict.value} "
            f"(completeness {self_check_result.completeness_score:.0%}).",
        ]

        hitl_decisions = hitl.get_decision_history()
        if hitl_decisions:
            approved_count = sum(1 for d in hitl_decisions if d.user_approved)
            rejected_count = len(hitl_decisions) - approved_count
            summary_parts.append(
                f"HITL: {len(hitl_decisions)} Tier 2 action(s) reviewed "
                f"({approved_count} approved, {rejected_count} rejected)."
            )

        return PipelineResult(
            original_policy=policy,
            rewritten_policy=rewrite_result.rewritten_policy,
            validation_results=validation_results,
            risk_findings=risk_findings,
            rewrite_result=rewrite_result,
            self_check_result=self_check_result,
            iterations=iterations,
            final_verdict=self_check_result.verdict,
            pipeline_summary=" ".join(summary_parts),
            hitl_decisions=hitl_decisions,
            origin=policy_input.origin,
        )

    def run_text(
        self,
        policy_text: str,
        config: PipelineConfig | None = None,
    ) -> PipelineResult:
        """Legacy string-in wrapper around :meth:`run`.

        Builds a synthetic :class:`PolicyInput` with
        ``source_type="stdin"`` and ``cache_status="N/A"`` so Origin-
        badge renderers still produce something meaningful.  Callers
        that want a proper origin should construct the
        :class:`PolicyInput` themselves (e.g., via a fetcher).
        """
        policy_input = PolicyInput.from_stdin_text(policy_text)
        return self.run(policy_input, config=config)

    def _apply_self_check_fixes(
        self,
        policy: Policy,
        findings: list[CheckFinding],
    ) -> Policy:
        """Apply targeted fixes based on self-check findings.

        Processes each ERROR finding and applies the appropriate fix:
        - ACTION_VALIDATION (Tier 3): Remove the invalid action.
        - TIER2_IN_POLICY: Remove the Tier 2 action.
        - REMAINING_WILDCARD: Flag only (cannot auto-fix without context).
        - MISSING_COMPANION: Add companion actions.

        Args:
            policy: Policy to fix.
            findings: Self-check findings to address.

        Returns:
            Modified policy with fixes applied.
        """
        fixed = copy.deepcopy(policy)

        # Collect actions to remove
        actions_to_remove: set[str] = set()
        companions_to_add: list[str] = []

        for finding in findings:
            # MISSING_COMPANION findings are WARNING severity but still
            # need processing in the loop-back to add companion actions.
            if (
                finding.severity != CheckSeverity.ERROR
                and finding.check_type != "MISSING_COMPANION"
            ):
                continue

            # Skip unfixable wildcard findings — these cannot be
            # auto-resolved without additional context (inventory, intent).
            # The loop-back would waste retries on them.
            if finding.check_type in (
                "OVERLY_BROAD_ACTION",
                "REMAINING_WILDCARD",
            ):
                continue

            # Issue 2 (v0.8.0, Amendment 10): only remove genuinely INVALID
            # (Tier 3) actions — Tier 2 actions are PRESERVED so the
            # operator's original intent survives the self-check loop.
            # TIER2_IN_POLICY findings now emit at WARNING severity; the
            # fixer just leaves them alone.
            if finding.check_type == "ACTION_VALIDATION":
                if finding.action:
                    actions_to_remove.add(finding.action)

            elif finding.check_type == "MISSING_COMPANION":
                if finding.action:
                    detected = self._companion_detector.detect_missing_companions([finding.action])
                    for comp in detected:
                        companions_to_add.extend(comp.companion_actions)

        # Remove invalid actions from all statements
        if actions_to_remove:
            for stmt in fixed.statements:
                stmt.actions = [a for a in stmt.actions if a not in actions_to_remove]

            # Remove empty statements (preserve NotAction statements)
            fixed.statements = [s for s in fixed.statements if s.actions or s.not_actions]

        # Add missing companion actions (skip those already in the policy)
        if companions_to_add:
            existing_actions: set[str] = set()
            for stmt in fixed.statements:
                existing_actions.update(stmt.actions)
                if stmt.not_actions:
                    existing_actions.update(stmt.not_actions)
            new_companions = [a for a in companions_to_add if a not in existing_actions]
            if new_companions:
                # Issue 1 (v0.8.0): The rewriter pass may already have
                # emitted a statement named "AllowCompanionPermissions"
                # (or the self_check pass may run multiple times via the
                # retry loop).  Generate a unique Sid suffix so AWS IAM's
                # Sid-uniqueness requirement is preserved.
                existing_sids = {s.sid for s in fixed.statements if s.sid}
                companion_sid = "AllowCompanionPermissions"
                counter = 2
                while companion_sid in existing_sids:
                    companion_sid = f"AllowCompanionPermissions{counter}"
                    counter += 1
                companion_stmt = Statement(
                    effect="Allow",
                    actions=new_companions,
                    resources=["*"],
                    sid=companion_sid,
                )
                fixed.statements.append(companion_stmt)

        return fixed

    def _build_rewrite_config(
        self,
        config: PipelineConfig,
    ) -> RewriteConfig:
        """Convert PipelineConfig to RewriteConfig.

        Args:
            config: Pipeline configuration.

        Returns:
            RewriteConfig for the rewriter.
        """
        return RewriteConfig(
            intent=config.intent,
            account_id=config.account_id,
            region=config.region,
            add_companions=config.add_companions,
            add_conditions=config.add_conditions,
            policy_type=config.policy_type,
            condition_profile=config.condition_profile,
        )

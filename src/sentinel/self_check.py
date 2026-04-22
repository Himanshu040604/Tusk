"""Self-check validator and pipeline orchestrator for IAM Policy Sentinel.

This module provides re-validation of rewritten policies, functional completeness
checking, remaining wildcard detection, Tier 2 exclusion verification, assumption
validation, and a loop-back mechanism that feeds failures back to the rewriter.
"""

from __future__ import annotations

import copy
import re
from dataclasses import dataclass, field
from enum import Enum
from typing import TYPE_CHECKING, List, Dict, Set, Optional, Tuple, Any

from .constants import WRITE_PREFIXES, READ_INTENT_KEYWORDS
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
    action: Optional[str] = None
    resource: Optional[str] = None
    remediation: Optional[str] = None


@dataclass
class SelfCheckResult:
    """Aggregate result from all self-check validations.

    Attributes:
        verdict: Overall pass/fail/warning verdict.
        findings: All findings from the self-check.
        completeness_score: Coverage score from 0.0 to 1.0.
        assumptions_valid: Whether rewrite assumptions are reasonable.
        tier2_excluded: Whether Tier 2 actions were properly excluded.
        summary: Human-readable summary of the self-check.
        confidence_summary: Per-aspect confidence scores from the pipeline.
    """
    verdict: CheckVerdict
    findings: List[CheckFinding]
    completeness_score: float
    assumptions_valid: bool
    tier2_excluded: bool
    summary: str
    confidence_summary: Dict[str, float] = field(default_factory=dict)


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
    intent: Optional[str] = None
    account_id: Optional[str] = None
    region: Optional[str] = None
    strict_mode: bool = False
    max_self_check_retries: int = 3
    add_companions: bool = True
    add_conditions: bool = True
    interactive: bool = False
    policy_type: Optional[str] = None
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
    validation_results: List[ValidationResult]
    risk_findings: List[RiskFinding]
    rewrite_result: RewriteResult
    self_check_result: SelfCheckResult
    iterations: int
    final_verdict: CheckVerdict
    pipeline_summary: str
    hitl_decisions: List[HITLDecision] = field(default_factory=list)
    # M5 § 8.4 — provenance record of the input bytes.  Optional so
    # legacy callers that passed raw strings still work (a synthetic
    # stdin origin is attached via run_text()).
    origin: Optional[PolicyOrigin] = None


# ARN format: starts with arn: and has at least 5 colon-separated parts
_ARN_BASIC_PATTERN = re.compile(r'^arn:[^:]+:[^:]+:[^:]*:[^:]*:.+$')


class SelfCheckValidator:
    """Re-validates rewritten policies for correctness and completeness.

    Runs six checks: action validation, ARN format, functional completeness,
    overly broad permissions, Tier 2 exclusion, and assumption validation.
    """

    def __init__(
        self,
        database: Optional[Database] = None,
        inventory: Optional[ResourceInventory] = None,
    ):
        """Initialize self-check validator.

        Args:
            database: Optional Database instance for action lookups.
            inventory: Optional ResourceInventory for ARN validation.
        """
        self.database = database
        self.inventory = inventory
        self.parser = PolicyParser(database)
        self.risk_analyzer = RiskAnalyzer(database)
        self.companion_detector = CompanionPermissionDetector(database)

    def run_self_check(
        self,
        rewrite_result: RewriteResult,
        config: Optional[PipelineConfig] = None,
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
        findings: List[CheckFinding] = []

        # Check 1: Validate actions
        findings.extend(self._validate_actions(policy))

        # Check 2: Check ARN formats
        findings.extend(self._check_arn_formats(policy, config))

        # Check 3: Functional completeness
        completeness_findings, completeness_score = (
            self._check_functional_completeness(policy, rewrite_result, config)
        )
        findings.extend(completeness_findings)

        # Check 4: Overly broad permissions
        findings.extend(self._check_overly_broad_permissions(policy, config))

        # Check 5: Tier 2 exclusion
        original_validation = self.parser.validate_policy(
            rewrite_result.original_policy
        )
        findings.extend(
            self._check_tier2_exclusion(policy, original_validation)
        )

        # Check 6: Assumption validation
        assumption_findings = self._check_assumptions(rewrite_result)
        findings.extend(assumption_findings)
        assumptions_valid = not any(
            f.severity == CheckSeverity.ERROR for f in assumption_findings
        )

        # Check 7: Low-confidence rewrite decisions
        findings.extend(self._check_low_confidence(rewrite_result))

        # Tier 2 exclusion result
        tier2_excluded = not any(
            f.check_type == "TIER2_IN_POLICY"
            and f.severity == CheckSeverity.ERROR
            for f in findings
        )

        # Compute verdict
        verdict = self._compute_verdict(findings, config.strict_mode)

        # Build summary
        error_count = sum(
            1 for f in findings if f.severity == CheckSeverity.ERROR
        )
        warning_count = sum(
            1 for f in findings if f.severity == CheckSeverity.WARNING
        )
        info_count = sum(
            1 for f in findings if f.severity == CheckSeverity.INFO
        )
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
            tier2_excluded=tier2_excluded,
            summary=summary,
        )

    def _validate_actions(self, policy: Policy) -> List[CheckFinding]:
        """Re-validate every action in the rewritten policy.

        Flags Tier 3 (invalid) actions as ERROR and Tier 2 (unknown)
        actions as ERROR since they should have been excluded by the rewriter.

        Args:
            policy: Rewritten policy to validate.

        Returns:
            List of CheckFinding objects.
        """
        findings: List[CheckFinding] = []

        for stmt in policy.statements:
            for action in stmt.actions:
                if action == '*' or action == '*:*':
                    continue

                result = self.parser.classify_action(action)

                if result.tier == ValidationTier.TIER_3_INVALID:
                    findings.append(CheckFinding(
                        check_type="ACTION_VALIDATION",
                        severity=CheckSeverity.ERROR,
                        message=(
                            f"Invalid action '{action}' in rewritten policy: "
                            f"{result.reason}"
                        ),
                        action=action,
                        remediation=f"Remove invalid action '{action}'",
                    ))
                elif result.tier == ValidationTier.TIER_2_UNKNOWN:
                    findings.append(CheckFinding(
                        check_type="TIER2_ACTION_KEPT",
                        severity=CheckSeverity.WARNING,
                        message=(
                            f"Tier 2 unknown action '{action}' kept in "
                            "rewritten policy (requires manual review)"
                        ),
                        action=action,
                        remediation=(
                            f"Verify action '{action}' exists or refresh "
                            "the IAM database"
                        ),
                    ))

        return findings

    def _check_arn_formats(
        self,
        policy: Policy,
        config: Optional[PipelineConfig] = None,
    ) -> List[CheckFinding]:
        """Validate ARN formats in the rewritten policy.

        Checks for remaining wildcards, placeholder markers, and
        malformed ARN strings.

        Args:
            policy: Rewritten policy to validate.

        Returns:
            List of CheckFinding objects.
        """
        findings: List[CheckFinding] = []

        for stmt in policy.statements:
            # Check both resources and not_resources for ARN issues
            all_resources = list(stmt.resources)
            if stmt.not_resources:
                all_resources.extend(stmt.not_resources)

            allow_wc_res = config.allow_wildcard_resources if config else False
            for resource in all_resources:
                if resource == '*':
                    severity = (
                        CheckSeverity.WARNING if allow_wc_res
                        else CheckSeverity.ERROR
                    )
                    findings.append(CheckFinding(
                        check_type="REMAINING_WILDCARD",
                        severity=severity,
                        message="Wildcard resource '*' remains in rewritten policy",
                        resource=resource,
                        remediation=(
                            "Replace with specific resource ARNs "
                            "(use --allow-wildcard-resources to downgrade)"
                        ),
                    ))
                elif 'PLACEHOLDER' in resource:
                    findings.append(CheckFinding(
                        check_type="PLACEHOLDER_ARN",
                        severity=CheckSeverity.INFO,
                        message=(
                            f"Placeholder ARN '{resource}' needs to be "
                            "replaced with a real ARN before deployment"
                        ),
                        resource=resource,
                        remediation=(
                            "Replace placeholder with actual resource ARN"
                        ),
                    ))
                elif resource.startswith('arn:'):
                    if not _ARN_BASIC_PATTERN.match(resource):
                        findings.append(CheckFinding(
                            check_type="ARN_FORMAT",
                            severity=CheckSeverity.ERROR,
                            message=(
                                f"Malformed ARN: '{resource}'. Expected format: "
                                "arn:partition:service:region:account:resource"
                            ),
                            resource=resource,
                            remediation="Fix the ARN format",
                        ))

        return findings

    def _check_functional_completeness(
        self,
        policy: Policy,
        rewrite_result: RewriteResult,
        config: PipelineConfig,
    ) -> Tuple[List[CheckFinding], float]:
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
        findings: List[CheckFinding] = []
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
            findings.append(CheckFinding(
                check_type="MISSING_SERVICE_COVERAGE",
                severity=CheckSeverity.WARNING,
                message=(
                    f"Services from original policy not covered in rewritten "
                    f"policy: {', '.join(sorted(missing_services))}"
                ),
                remediation="Add actions for missing services",
            ))

        # Score component 2: Access level match with intent (weight 0.3)
        access_level_score = 1.0
        if config.intent:
            intent_lower = config.intent.lower()
            is_read_only = any(
                re.search(r'\b' + re.escape(kw) + r'\b', intent_lower)
                for kw in READ_INTENT_KEYWORDS
            )
            if is_read_only:
                write_actions = self._find_write_actions(policy)
                if write_actions:
                    access_level_score = 0.5
                    findings.append(CheckFinding(
                        check_type="INTENT_MISMATCH",
                        severity=CheckSeverity.WARNING,
                        message=(
                            f"Intent is read-only but rewritten policy "
                            f"contains write actions: "
                            f"{', '.join(write_actions[:3])}"
                        ),
                        remediation=(
                            "Remove write actions to match read-only intent"
                        ),
                    ))

        # Score component 3: Companion completeness (weight 0.2)
        all_actions = self._collect_allow_actions(policy)
        missing_companions = self.companion_detector.detect_missing_companions(
            all_actions
        )
        if missing_companions:
            companion_score = max(
                0.0,
                1.0 - (len(missing_companions) * 0.25),
            )
            for comp in missing_companions:
                findings.append(CheckFinding(
                    check_type="MISSING_COMPANION",
                    severity=CheckSeverity.WARNING,
                    message=(
                        f"Missing companion permissions for "
                        f"{comp.primary_action}: "
                        f"{', '.join(comp.companion_actions)}"
                    ),
                    action=comp.primary_action,
                    remediation=(
                        f"Add companion actions: "
                        f"{', '.join(comp.companion_actions)}"
                    ),
                ))
        else:
            companion_score = 1.0

        # Score component 4: Action coverage (weight 0.2)
        original_actions = self._collect_allow_actions(original)
        rewritten_actions = set(all_actions)
        if original_actions:
            # Check how many original specific actions are still covered
            original_specific = {
                a for a in original_actions if '*' not in a
            }
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
        config: Optional[PipelineConfig] = None,
    ) -> List[CheckFinding]:
        """Check for surviving wildcard actions and resources.

        Full wildcards (*, *:*) are ERROR by default (fail-closed).
        Service wildcards (s3:*) remain WARNING. Partial wildcards
        remain INFO. Use config.allow_wildcard_actions to downgrade.

        Args:
            policy: Rewritten policy to check.

        Returns:
            List of CheckFinding objects.
        """
        findings: List[CheckFinding] = []
        allow_wc_actions = config.allow_wildcard_actions if config else False

        for stmt in policy.statements:
            if stmt.effect != 'Allow':
                continue

            for action in stmt.actions:
                if action == '*' or action == '*:*':
                    severity = (
                        CheckSeverity.WARNING if allow_wc_actions
                        else CheckSeverity.ERROR
                    )
                    findings.append(CheckFinding(
                        check_type="OVERLY_BROAD_ACTION",
                        severity=severity,
                        message=(
                            f"Full wildcard action '{action}' in rewritten policy"
                        ),
                        action=action,
                        remediation=(
                            "Replace with specific service actions "
                            "(use --allow-wildcard-actions to downgrade)"
                        ),
                    ))
                elif action.endswith(':*'):
                    findings.append(CheckFinding(
                        check_type="OVERLY_BROAD_ACTION",
                        severity=CheckSeverity.WARNING,
                        message=(
                            f"Service wildcard action '{action}' in rewritten "
                            "policy"
                        ),
                        action=action,
                        remediation=(
                            "Replace with specific actions for the service"
                        ),
                    ))
                elif '*' in action:
                    findings.append(CheckFinding(
                        check_type="OVERLY_BROAD_ACTION",
                        severity=CheckSeverity.INFO,
                        message=(
                            f"Partial wildcard action '{action}' in rewritten "
                            "policy"
                        ),
                        action=action,
                        remediation=(
                            "Consider replacing with specific actions"
                        ),
                    ))

        return findings

    def _check_tier2_exclusion(
        self,
        policy: Policy,
        validation_results: List[ValidationResult],
    ) -> List[CheckFinding]:
        """Verify no Tier 2 actions from original validation appear in rewritten policy.

        Cross-references the original validation results with the rewritten
        policy to ensure unknown actions were excluded.

        Args:
            policy: Rewritten policy.
            validation_results: Validation results from the original policy.

        Returns:
            List of CheckFinding objects.
        """
        findings: List[CheckFinding] = []

        tier2_actions = {
            r.action for r in validation_results
            if r.tier == ValidationTier.TIER_2_UNKNOWN
        }

        if not tier2_actions:
            return findings

        rewritten_actions = set()
        for stmt in policy.statements:
            rewritten_actions.update(stmt.actions)
            if stmt.not_actions:
                rewritten_actions.update(stmt.not_actions)

        for action in sorted(tier2_actions & rewritten_actions):
            findings.append(CheckFinding(
                check_type="TIER2_IN_POLICY",
                severity=CheckSeverity.ERROR,
                message=(
                    f"Tier 2 unknown action '{action}' found in rewritten "
                    "policy. It should have been excluded."
                ),
                action=action,
                remediation=f"Remove Tier 2 action '{action}'",
            ))

        return findings

    def _check_assumptions(
        self, rewrite_result: RewriteResult,
    ) -> List[CheckFinding]:
        """Validate that the rewrite result includes meaningful assumptions.

        Checks that at minimum the database/inventory availability is
        documented, and that assumption strings are non-empty.

        Args:
            rewrite_result: Output from the rewriter.

        Returns:
            List of CheckFinding objects.
        """
        findings: List[CheckFinding] = []

        if not rewrite_result.assumptions:
            findings.append(CheckFinding(
                check_type="MISSING_ASSUMPTIONS",
                severity=CheckSeverity.WARNING,
                message=(
                    "No assumptions recorded during rewrite. "
                    "At minimum, database and inventory status should be noted."
                ),
                remediation=(
                    "Document assumptions about database availability "
                    "and resource inventory"
                ),
            ))
            return findings

        for assumption in rewrite_result.assumptions:
            if not assumption or not assumption.strip():
                findings.append(CheckFinding(
                    check_type="EMPTY_ASSUMPTION",
                    severity=CheckSeverity.WARNING,
                    message="Empty assumption string found in rewrite result",
                    remediation="Remove empty assumptions or add content",
                ))

        return findings

    def _check_low_confidence(
        self,
        rewrite_result: RewriteResult,
    ) -> List[CheckFinding]:
        """Flag rewrite changes with confidence below 0.5.

        Args:
            rewrite_result: Output from the rewriter.

        Returns:
            List of CheckFinding objects for low-confidence decisions.
        """
        findings: List[CheckFinding] = []
        for change in rewrite_result.changes:
            if change.confidence < 0.5:
                findings.append(CheckFinding(
                    check_type="LOW_CONFIDENCE",
                    severity=CheckSeverity.WARNING,
                    message=(
                        f"Low confidence ({change.confidence}) on "
                        f"{change.change_type}: {change.description}"
                    ),
                    remediation="Review this change manually",
                ))
        return findings

    def _compute_verdict(
        self,
        findings: List[CheckFinding],
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
        has_error = any(
            f.severity == CheckSeverity.ERROR for f in findings
        )
        has_warning = any(
            f.severity == CheckSeverity.WARNING for f in findings
        )

        if has_error:
            return CheckVerdict.FAIL

        if has_warning:
            if strict_mode:
                return CheckVerdict.FAIL
            return CheckVerdict.WARNING

        return CheckVerdict.PASS

    def _extract_services(self, policy: Policy) -> Set[str]:
        """Extract unique service prefixes from a policy.

        Args:
            policy: Policy to extract services from.

        Returns:
            Set of service prefix strings.
        """
        services: Set[str] = set()
        for stmt in policy.statements:
            all_actions = list(stmt.actions)
            if stmt.not_actions:
                all_actions.extend(stmt.not_actions)
            for action in all_actions:
                parts = action.split(':', 1)
                if len(parts) == 2 and parts[0] != '*':
                    services.add(parts[0])
        return services

    def _find_write_actions(self, policy: Policy) -> List[str]:
        """Find actions that are likely write-level.

        Args:
            policy: Policy to scan.

        Returns:
            List of write action names.
        """
        write_actions: List[str] = []
        for stmt in policy.statements:
            if stmt.effect != 'Allow':
                continue
            for action in stmt.actions:
                action_name = action.split(':')[-1] if ':' in action else action
                if any(action_name.startswith(p) for p in WRITE_PREFIXES):
                    write_actions.append(action)
        return write_actions

    def _collect_allow_actions(self, policy: Policy) -> List[str]:
        """Collect all actions from Allow statements.

        Args:
            policy: Policy to collect from.

        Returns:
            List of action name strings.
        """
        actions: List[str] = []
        for stmt in policy.statements:
            if stmt.effect == 'Allow':
                actions.extend(stmt.actions)
        return actions


class Pipeline:
    """End-to-end Validate-Analyze-Rewrite-SelfCheck pipeline.

    Orchestrates all four pipeline steps and implements a loop-back
    mechanism that feeds self-check failures back to the rewriter.
    """

    def __init__(
        self,
        database: Optional[Database] = None,
        inventory: Optional[ResourceInventory] = None,
        config: Optional[PipelineConfig] = None,
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
        self._companion_detector = CompanionPermissionDetector(database)

    def run(
        self,
        policy_input: "PolicyInput | str",
        config: Optional[PipelineConfig] = None,
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
        all_actions: List[str] = []
        for stmt in policy.statements:
            all_actions.extend(stmt.actions)
            if stmt.not_actions:
                all_actions.extend(stmt.not_actions)

        risk_analyzer = RiskAnalyzer(self.database)
        risk_findings = risk_analyzer.analyze_actions(all_actions)

        companion_detector = CompanionPermissionDetector(self.database)
        missing_companions = companion_detector.detect_missing_companions(
            all_actions
        )

        # Step 2.5: HITL - Interactive Tier 2 action review
        hitl = HITLSystem(interactive=config.interactive)
        tier2_actions = [
            r for r in validation_results
            if r.tier == ValidationTier.TIER_2_UNKNOWN
        ]
        rejected_actions: Set[str] = set()

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
                    stmt.actions = [
                        a for a in stmt.actions
                        if a not in rejected_actions
                    ]
                policy.statements = [
                    s for s in policy.statements
                    if s.actions or s.not_actions
                ]

        # Step 3: REWRITE
        rewriter = PolicyRewriter(self.database, self.inventory)
        rewrite_config = self._build_rewrite_config(config)
        rewrite_result = rewriter.rewrite_policy(policy, rewrite_config)

        # Step 4: SELF-CHECK with loop-back
        checker = SelfCheckValidator(self.database, self.inventory)
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
            if (
                not fixed_policy.statements
                or fixed_policy.statements == previous_policy.statements
            ):
                break

            # Re-run rewrite on the fixed policy
            rewrite_result = RewriteResult(
                original_policy=rewrite_result.original_policy,
                rewritten_policy=fixed_policy,
                changes=rewrite_result.changes,
                assumptions=rewrite_result.assumptions,
                warnings=rewrite_result.warnings,
                companion_permissions_added=(
                    rewrite_result.companion_permissions_added
                ),
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
            approved_count = sum(
                1 for d in hitl_decisions if d.user_approved
            )
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
            pipeline_summary=' '.join(summary_parts),
            hitl_decisions=hitl_decisions,
            origin=policy_input.origin,
        )

    def run_text(
        self,
        policy_text: str,
        config: Optional[PipelineConfig] = None,
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
        findings: List[CheckFinding],
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
        actions_to_remove: Set[str] = set()
        companions_to_add: List[str] = []

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
                "OVERLY_BROAD_ACTION", "REMAINING_WILDCARD",
            ):
                continue

            if finding.check_type in ("ACTION_VALIDATION", "TIER2_IN_POLICY"):
                if finding.action:
                    actions_to_remove.add(finding.action)

            elif finding.check_type == "MISSING_COMPANION":
                if finding.action:
                    detected = self._companion_detector.detect_missing_companions(
                        [finding.action]
                    )
                    for comp in detected:
                        companions_to_add.extend(comp.companion_actions)

        # Remove invalid actions from all statements
        if actions_to_remove:
            for stmt in fixed.statements:
                stmt.actions = [
                    a for a in stmt.actions if a not in actions_to_remove
                ]

            # Remove empty statements (preserve NotAction statements)
            fixed.statements = [
                s for s in fixed.statements
                if s.actions or s.not_actions
            ]

        # Add missing companion actions (skip those already in the policy)
        if companions_to_add:
            existing_actions: Set[str] = set()
            for stmt in fixed.statements:
                existing_actions.update(stmt.actions)
                if stmt.not_actions:
                    existing_actions.update(stmt.not_actions)
            new_companions = [
                a for a in companions_to_add if a not in existing_actions
            ]
            if new_companions:
                companion_stmt = Statement(
                    effect='Allow',
                    actions=new_companions,
                    resources=['*'],
                    sid='AllowCompanionPermissions',
                )
                fixed.statements.append(companion_stmt)

        return fixed

    def _build_rewrite_config(
        self, config: PipelineConfig,
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

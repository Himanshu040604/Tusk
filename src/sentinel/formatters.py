"""Output formatters for IAM Policy Sentinel.

Provides text, JSON, and Markdown formatting for validation results,
risk findings, rewrite results, and pipeline output.
"""

from __future__ import annotations

import json
from typing import TYPE_CHECKING, List, Dict, Any, Optional

from .rewriter import serialize_policy

if TYPE_CHECKING:
    from .parser import Policy, ValidationResult
    from .analyzer import RiskFinding
    from .rewriter import RewriteResult
    from .self_check import PipelineResult


class TextFormatter:
    """Human-readable terminal output formatter.

    Uses [VALID], [CRITICAL], [WARN] tags with indented sections.
    """

    def format_validation(
        self,
        results: List[ValidationResult],
        policy: Policy,
    ) -> str:
        """Format validation results as text.

        Args:
            results: List of validation results.
            policy: The parsed policy.

        Returns:
            Formatted text string.
        """
        lines = ["=== Policy Validation Results ===", ""]
        lines.append(f"Version: {policy.version}")
        lines.append(f"Statements: {len(policy.statements)}")
        lines.append(f"Actions validated: {len(results)}")
        lines.append("")

        tier_counts = {"VALID": 0, "UNKNOWN": 0, "INVALID": 0}
        for r in results:
            tier_counts[r.tier.value] = tier_counts.get(r.tier.value, 0) + 1

        lines.append(f"  Tier 1 (Valid):   {tier_counts['VALID']}")
        lines.append(f"  Tier 2 (Unknown): {tier_counts['UNKNOWN']}")
        lines.append(f"  Tier 3 (Invalid): {tier_counts['INVALID']}")
        lines.append("")

        for r in results:
            tag = {
                "VALID": "[VALID]",
                "UNKNOWN": "[UNKNOWN]",
                "INVALID": "[INVALID]",
            }.get(r.tier.value, "[???]")
            lines.append(f"  {tag} {r.action}")
            lines.append(f"    Reason: {r.reason}")
            if r.access_level:
                lines.append(f"    Access level: {r.access_level}")
            if hasattr(r, 'confidence') and r.confidence < 1.0:
                lines.append(f"    Confidence: {r.confidence:.1f}")
            if r.suggestions:
                lines.append(
                    f"    Suggestions: {', '.join(r.suggestions)}"
                )

        return "\n".join(lines)

    def format_risk_findings(self, findings: List[RiskFinding]) -> str:
        """Format risk findings as text.

        Args:
            findings: List of risk findings.

        Returns:
            Formatted text string.
        """
        lines = ["=== Risk Analysis ===", ""]

        if not findings:
            lines.append("No risk findings detected.")
            return "\n".join(lines)

        lines.append(f"Total findings: {len(findings)}")
        lines.append("")

        for i, f in enumerate(findings, 1):
            tag = f"[{f.severity.value}]"
            lines.append(f"  {i}. {tag} {f.risk_type}")
            lines.append(f"     Action: {f.action}")
            lines.append(f"     {f.description}")
            lines.append(f"     Remediation: {f.remediation}")

        return "\n".join(lines)

    def format_rewrite_result(self, result: RewriteResult) -> str:
        """Format rewrite result as text.

        Args:
            result: Rewrite result.

        Returns:
            Formatted text string.
        """
        lines = ["=== Rewrite Result ===", ""]
        lines.append(f"Changes applied: {len(result.changes)}")
        lines.append(
            f"Companions added: {len(result.companion_permissions_added)}"
        )
        lines.append("")

        if result.changes:
            lines.append("Changes:")
            for c in result.changes:
                lines.append(f"  [{c.change_type}] {c.description}")
                lines.append(f"    Before: {c.original_value}")
                lines.append(f"    After:  {c.new_value}")

        if result.assumptions:
            lines.append("")
            lines.append("Assumptions:")
            for a in result.assumptions:
                lines.append(f"  - {a}")

        if result.warnings:
            lines.append("")
            lines.append("Warnings:")
            for w in result.warnings:
                lines.append(f"  [WARN] {w}")

        lines.append("")
        lines.append("Rewritten policy:")
        policy_dict = serialize_policy(result.rewritten_policy)
        lines.append(json.dumps(policy_dict, indent=2))

        return "\n".join(lines)

    def format_pipeline_result(self, result: PipelineResult) -> str:
        """Format full pipeline result as text.

        Args:
            result: Pipeline result.

        Returns:
            Formatted text string.
        """

        lines = ["=== IAM Policy Sentinel - Pipeline Result ===", ""]
        lines.append(f"Final verdict: [{result.final_verdict.value}]")
        lines.append(f"Iterations: {result.iterations}")
        lines.append("")
        lines.append(result.pipeline_summary)
        lines.append("")

        # Validation summary
        tier_counts = {"VALID": 0, "UNKNOWN": 0, "INVALID": 0}
        for r in result.validation_results:
            tier_counts[r.tier.value] = tier_counts.get(r.tier.value, 0) + 1
        lines.append(
            f"Validation: {tier_counts['VALID']} valid, "
            f"{tier_counts['UNKNOWN']} unknown, "
            f"{tier_counts['INVALID']} invalid"
        )

        # Tier 2 actions kept for review
        tier2_kept = [
            r for r in result.validation_results
            if r.tier.value == "UNKNOWN"
        ]
        if tier2_kept:
            lines.append("")
            lines.append("--- Tier 2 Actions Kept For Review ---")
            for r in tier2_kept:
                conf = getattr(r, 'confidence', 'N/A')
                lines.append(f"  [REVIEW] {r.action} (confidence: {conf})")
                lines.append(f"    {r.reason}")
            lines.append("")

        # Risk summary
        lines.append(f"Risk findings: {len(result.risk_findings)}")

        # Self-check summary
        sc = result.self_check_result
        lines.append(
            f"Self-check: {sc.verdict.value} "
            f"(completeness {sc.completeness_score:.0%})"
        )
        lines.append("")

        # Rewritten policy
        lines.append("Rewritten policy:")
        policy_dict = serialize_policy(result.rewritten_policy)
        lines.append(json.dumps(policy_dict, indent=2))

        return "\n".join(lines)

    def format_db_info(
        self,
        metadata: Dict[str, Optional[str]],
        service_count: int,
        action_count: int,
    ) -> str:
        """Format database info as text.

        Args:
            metadata: Database metadata key-value pairs.
            service_count: Number of services in DB.
            action_count: Number of actions in DB.

        Returns:
            Formatted text string.
        """
        lines = ["=== Database Info ===", ""]
        lines.append(f"Services: {service_count}")
        lines.append(f"Actions:  {action_count}")
        lines.append("")
        lines.append("Metadata:")
        for k, v in metadata.items():
            lines.append(f"  {k}: {v}")
        return "\n".join(lines)


class JsonFormatter:
    """JSON output formatter.

    Produces a single JSON document with nested structure.
    """

    def format_validation(
        self,
        results: List[ValidationResult],
        policy: Policy,
    ) -> str:
        """Format validation results as JSON.

        Args:
            results: List of validation results.
            policy: The parsed policy.

        Returns:
            JSON string.
        """
        data = {
            "version": policy.version,
            "statement_count": len(policy.statements),
            "results": [
                {
                    "action": r.action,
                    "tier": r.tier.value,
                    "reason": r.reason,
                    "access_level": r.access_level,
                    "suggestions": r.suggestions or [],
                    "confidence": getattr(r, 'confidence', 1.0),
                }
                for r in results
            ],
        }
        return json.dumps(data, indent=2)

    def format_risk_findings(self, findings: List[RiskFinding]) -> str:
        """Format risk findings as JSON.

        Args:
            findings: List of risk findings.

        Returns:
            JSON string.
        """
        data = {
            "total_findings": len(findings),
            "findings": [
                {
                    "risk_type": f.risk_type,
                    "severity": f.severity.value,
                    "action": f.action,
                    "description": f.description,
                    "remediation": f.remediation,
                }
                for f in findings
            ],
        }
        return json.dumps(data, indent=2)

    def format_rewrite_result(self, result: RewriteResult) -> str:
        """Format rewrite result as JSON.

        Args:
            result: Rewrite result.

        Returns:
            JSON string.
        """
        data = {
            "changes": [
                {
                    "change_type": c.change_type,
                    "description": c.description,
                    "original_value": c.original_value,
                    "new_value": c.new_value,
                    "statement_index": c.statement_index,
                }
                for c in result.changes
            ],
            "assumptions": result.assumptions,
            "warnings": result.warnings,
            "companion_permissions_added": [
                {
                    "primary_action": cp.primary_action,
                    "companion_actions": cp.companion_actions,
                    "reason": cp.reason,
                }
                for cp in result.companion_permissions_added
            ],
            "rewritten_policy": serialize_policy(
                result.rewritten_policy
            ),
        }
        return json.dumps(data, indent=2)

    def format_pipeline_result(self, result: PipelineResult) -> str:
        """Format full pipeline result as JSON.

        Args:
            result: Pipeline result.

        Returns:
            JSON string.
        """
        data = {
            "final_verdict": result.final_verdict.value,
            "iterations": result.iterations,
            "pipeline_summary": result.pipeline_summary,
            "validation": [
                {
                    "action": r.action,
                    "tier": r.tier.value,
                    "reason": r.reason,
                    "access_level": r.access_level,
                    "confidence": getattr(r, 'confidence', 1.0),
                }
                for r in result.validation_results
            ],
            "tier2_actions_for_review": [
                {
                    "action": r.action,
                    "reason": r.reason,
                    "confidence": getattr(r, 'confidence', 0.6),
                }
                for r in result.validation_results
                if r.tier.value == "UNKNOWN"
            ],
            "risk_findings": [
                {
                    "risk_type": f.risk_type,
                    "severity": f.severity.value,
                    "action": f.action,
                    "description": f.description,
                }
                for f in result.risk_findings
            ],
            "rewrite_changes": len(result.rewrite_result.changes),
            "self_check": {
                "verdict": result.self_check_result.verdict.value,
                "completeness_score": result.self_check_result.completeness_score,
                "findings_count": len(result.self_check_result.findings),
            },
            "rewritten_policy": serialize_policy(
                result.rewritten_policy
            ),
        }
        return json.dumps(data, indent=2)

    def format_db_info(
        self,
        metadata: Dict[str, Optional[str]],
        service_count: int,
        action_count: int,
    ) -> str:
        """Format database info as JSON.

        Args:
            metadata: Database metadata key-value pairs.
            service_count: Number of services in DB.
            action_count: Number of actions in DB.

        Returns:
            JSON string.
        """
        data = {
            "service_count": service_count,
            "action_count": action_count,
            "metadata": {k: v for k, v in metadata.items()},
        }
        return json.dumps(data, indent=2)


class MarkdownFormatter:
    """Markdown output formatter.

    Uses headers, tables, and fenced code blocks.
    """

    def format_validation(
        self,
        results: List[ValidationResult],
        policy: Policy,
    ) -> str:
        """Format validation results as Markdown.

        Args:
            results: List of validation results.
            policy: The parsed policy.

        Returns:
            Markdown string.
        """
        lines = ["# Policy Validation Results", ""]
        lines.append(f"- **Version:** {policy.version}")
        lines.append(f"- **Statements:** {len(policy.statements)}")
        lines.append(f"- **Actions validated:** {len(results)}")
        lines.append("")

        lines.append("| Action | Tier | Confidence | Reason |")
        lines.append("|--------|------|------------|--------|")
        for r in results:
            reason_escaped = r.reason.replace("|", "\\|")
            conf = getattr(r, 'confidence', 1.0)
            lines.append(f"| `{r.action}` | {r.tier.value} | {conf:.1f} | {reason_escaped} |")

        return "\n".join(lines)

    def format_risk_findings(self, findings: List[RiskFinding]) -> str:
        """Format risk findings as Markdown.

        Args:
            findings: List of risk findings.

        Returns:
            Markdown string.
        """
        lines = ["# Risk Analysis", ""]

        if not findings:
            lines.append("No risk findings detected.")
            return "\n".join(lines)

        lines.append(f"**Total findings:** {len(findings)}")
        lines.append("")
        lines.append("| # | Severity | Type | Action | Description |")
        lines.append("|---|----------|------|--------|-------------|")
        for i, f in enumerate(findings, 1):
            desc_escaped = f.description.replace("|", "\\|")
            lines.append(
                f"| {i} | {f.severity.value} | {f.risk_type} "
                f"| `{f.action}` | {desc_escaped} |"
            )

        return "\n".join(lines)

    def format_rewrite_result(self, result: RewriteResult) -> str:
        """Format rewrite result as Markdown.

        Args:
            result: Rewrite result.

        Returns:
            Markdown string.
        """
        lines = ["# Rewrite Result", ""]
        lines.append(f"- **Changes:** {len(result.changes)}")
        lines.append(
            f"- **Companions added:** "
            f"{len(result.companion_permissions_added)}"
        )
        lines.append("")

        if result.changes:
            lines.append("## Changes")
            lines.append("")
            lines.append("| Type | Description |")
            lines.append("|------|-------------|")
            for c in result.changes:
                desc_escaped = c.description.replace("|", "\\|")
                lines.append(f"| {c.change_type} | {desc_escaped} |")
            lines.append("")

        if result.assumptions:
            lines.append("## Assumptions")
            lines.append("")
            for a in result.assumptions:
                lines.append(f"- {a}")
            lines.append("")

        if result.warnings:
            lines.append("## Warnings")
            lines.append("")
            for w in result.warnings:
                lines.append(f"- {w}")
            lines.append("")

        lines.append("## Rewritten Policy")
        lines.append("")
        lines.append("```json")
        policy_dict = serialize_policy(result.rewritten_policy)
        lines.append(json.dumps(policy_dict, indent=2))
        lines.append("```")

        return "\n".join(lines)

    def format_pipeline_result(self, result: PipelineResult) -> str:
        """Format full pipeline result as Markdown.

        Args:
            result: Pipeline result.

        Returns:
            Markdown string.
        """
        lines = ["# IAM Policy Sentinel - Pipeline Result", ""]
        lines.append(f"**Final verdict:** {result.final_verdict.value}")
        lines.append(f"**Iterations:** {result.iterations}")
        lines.append("")
        lines.append(f"> {result.pipeline_summary}")
        lines.append("")

        # Validation summary
        tier_counts = {"VALID": 0, "UNKNOWN": 0, "INVALID": 0}
        for r in result.validation_results:
            tier_counts[r.tier.value] = tier_counts.get(r.tier.value, 0) + 1
        lines.append("## Validation Summary")
        lines.append("")
        lines.append(f"| Tier | Count |")
        lines.append(f"|------|-------|")
        lines.append(f"| Valid | {tier_counts['VALID']} |")
        lines.append(f"| Unknown | {tier_counts['UNKNOWN']} |")
        lines.append(f"| Invalid | {tier_counts['INVALID']} |")
        lines.append("")

        # Tier 2 actions kept for review
        tier2_kept = [
            r for r in result.validation_results
            if r.tier.value == "UNKNOWN"
        ]
        if tier2_kept:
            lines.append("## Tier 2 Actions Kept For Review")
            lines.append("")
            lines.append("| Action | Confidence | Reason |")
            lines.append("|--------|------------|--------|")
            for r in tier2_kept:
                conf = getattr(r, 'confidence', 'N/A')
                reason_esc = r.reason.replace("|", "\\|")
                lines.append(f"| `{r.action}` | {conf} | {reason_esc} |")
            lines.append("")

        # Risk findings
        if result.risk_findings:
            lines.append(f"## Risk Findings ({len(result.risk_findings)})")
            lines.append("")
            for f in result.risk_findings:
                lines.append(
                    f"- **[{f.severity.value}]** {f.action}: {f.description}"
                )
            lines.append("")

        # Self-check
        sc = result.self_check_result
        lines.append("## Self-Check")
        lines.append("")
        lines.append(f"- **Verdict:** {sc.verdict.value}")
        lines.append(f"- **Completeness:** {sc.completeness_score:.0%}")
        lines.append(f"- **Findings:** {len(sc.findings)}")
        lines.append("")

        # Rewritten policy
        lines.append("## Rewritten Policy")
        lines.append("")
        lines.append("```json")
        policy_dict = serialize_policy(result.rewritten_policy)
        lines.append(json.dumps(policy_dict, indent=2))
        lines.append("```")

        return "\n".join(lines)

    def format_db_info(
        self,
        metadata: Dict[str, Optional[str]],
        service_count: int,
        action_count: int,
    ) -> str:
        """Format database info as Markdown.

        Args:
            metadata: Database metadata key-value pairs.
            service_count: Number of services in DB.
            action_count: Number of actions in DB.

        Returns:
            Markdown string.
        """
        lines = ["# Database Info", ""]
        lines.append(f"- **Services:** {service_count}")
        lines.append(f"- **Actions:** {action_count}")
        lines.append("")
        lines.append("| Key | Value |")
        lines.append("|-----|-------|")
        for k, v in metadata.items():
            lines.append(f"| {k} | {v} |")
        return "\n".join(lines)

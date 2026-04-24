"""Output formatters for IAM Policy Sentinel.

Three formatters render the same ``PipelineResult`` into different
surfaces:

* :class:`TextFormatter` -- human-readable report with origin badge,
  findings table, "Actions Kept For Review" Tier-2 block, rewritten
  policy, and force-emit bypass banner.
* :class:`JsonFormatter` -- machine-readable; top-level fields per
  ``prod_imp.md § 8.7``: ``origin``, ``final_verdict``, ``findings``,
  ``rewrite_result``, ``self_check_result``, ``tier2_preserved_actions``,
  ``rewritten_policy``, ``semantic``, ``force_emit_rewrite_bypass``,
  ``bypass_reason``.
* :class:`MarkdownFormatter` -- PR-comment-ready with admonition-style
  blockquotes for the force-emit bypass banner.

Key behaviors:

* **Refuse-on-FAIL rewrite suppression** (Issue 5, v0.8.0): every
  ``format_pipeline_result`` accepts a keyword-only ``force_emit: bool =
  False`` parameter. On a FAIL verdict, the rewrite emission is
  suppressed unless ``force_emit=True``. The CLI surfaces this via
  ``--force-emit-rewrite`` (scoped to ``run`` / ``fetch`` /
  ``managed analyze`` per L2 v0.8.1).
* **Semantic field** (Amendment 10): JSON output gains a top-level
  ``"semantic"`` key -- ``"additions_only"`` when the rewrite contains
  only companion-addition changes (operator should MERGE with original);
  ``"complete_policy"`` otherwise (operator can wholesale-replace).
  Only present when ``rewrite_suppressed`` is ``False``.
  ``_is_additions_only`` uses an explicit inclusion-based change-type
  allowlist (L3 v0.8.1 -- robust to future change types).
* **Force-emit audit trail** (M2 + SEC-L4, v0.8.1): when
  ``force_emit=True``, JSON adds ``"force_emit_rewrite_bypass": true``
  + ``"bypass_reason": <string>``, text emits a ``[!] WARNING:
  --force-emit-rewrite bypassed FAIL verdict`` banner, markdown emits a
  ``> [!] FORCE-EMIT BYPASS`` blockquote. Also fires an audit-log
  structlog WARNING event ``force_emit_rewrite_bypass`` from the CLI
  layer (``cmd_run`` / ``cmd_fetch`` / ``cmd_managed_analyze``) with a
  ``bypass_of_failure`` boolean so SIEM rules can distinguish genuine
  FAIL-bypass from belt-and-suspenders PASS/WARNING override.
* **Deferred serialize_policy import** (P0-3 γ): the
  ``rewriter.serialize_policy`` import is deferred to a lazy shim so
  importing this module for ``sentinel --version`` doesn't pull the
  rewriter -> analyzer -> constants -> pydantic-settings chain.
* **Origin badge** (§ 8.4): the ``PolicyOrigin`` record is always
  rendered at the top of every report as a provenance receipt.
"""

from __future__ import annotations

import json
from typing import TYPE_CHECKING, Any

# P0-3 γ — defer `serialize_policy` import to function scope so importing
# formatters (e.g., `sentinel --version` touches sentinel/__init__.py
# lazy exports that reference formatters) doesn't pull the rewriter
# stack → analyzer → constants → pydantic-settings (~635ms cold-start).

if TYPE_CHECKING:
    from .parser import Policy, ValidationResult
    from .analyzer import RiskFinding
    from .rewriter import RewriteResult
    from .self_check import PipelineResult
    from .models import PolicyOrigin


def _serialize_policy(*args: Any, **kwargs: Any) -> Any:
    """Lazy shim — imports rewriter.serialize_policy only on first call."""
    from .rewriter import serialize_policy as _impl

    return _impl(*args, **kwargs)


# ---------------------------------------------------------------------------
# Origin-badge renderers (M5, § 8.4).  Three representations — text,
# json-shaped dict, markdown — share one factoring so the I1 caveat
# (SHA-256 attests bytes-we-acted-on, not upstream provenance) is a
# single place to audit.  Callers receive a short prefix-string (text /
# markdown) or a JSON-serialisable dict; the legacy tests that don't
# carry an origin simply get an empty string / omitted key.
# ---------------------------------------------------------------------------

_SHA_PREFIX_LEN = 12


def _origin_text(origin: "PolicyOrigin" | None) -> str:
    """One-line text badge or ``""`` when origin is absent."""
    if origin is None:
        return ""
    prefix = origin.sha256[:_SHA_PREFIX_LEN]
    return (
        f"Origin: {origin.source_type} {origin.source_spec} "
        f"(SHA256: {prefix}...) [CACHE: {origin.cache_status}]"
    )


def _origin_json(origin: "PolicyOrigin" | None) -> dict[str, str] | None:
    """JSON-serialisable origin sub-tree or None."""
    if origin is None:
        return None
    return {
        "source_type": origin.source_type,
        "source_spec": origin.source_spec,
        "sha256": origin.sha256,
        "fetched_at": origin.fetched_at.isoformat(),
        "cache_status": origin.cache_status,
    }


def _origin_markdown(origin: "PolicyOrigin" | None) -> str:
    """Markdown badge or ``""``."""
    if origin is None:
        return ""
    prefix = origin.sha256[:_SHA_PREFIX_LEN]
    return (
        f"**Origin:** {origin.source_type} — "
        f"`{origin.source_spec}` (SHA256 `{prefix}`) "
        f"— cache `{origin.cache_status}`"
    )


def _is_additions_only(result: "PipelineResult") -> bool:
    """Return True when the rewrite emits ONLY companion-add statements.

    Issue 2 (v0.8.0, Amendment 10): when the rewrite pipeline changes are
    limited to COMPANION_ADDED entries, the output is a PARTIAL rewrite
    (additions) rather than a complete narrowed policy.  The formatter
    relabels the output section so operators know to MERGE the additions
    with their original policy instead of wholesale-replacing it.

    v0.8.1 (L3): flipped from exclusion-based (reject WILDCARD_REPLACED,
    RESOURCE_SCOPED) to inclusion-based (only allow COMPANION_ADDED). The
    original exclusion was brittle: future change types (e.g., a new
    ``ACTION_NARROWED``) would default to additions-only unless the list
    was manually extended. The inclusion form is the correct default —
    new change types are treated as rewrites until explicitly allowlisted.
    Also note: the old code referenced a non-existent "RESOURCE_SCOPED"
    (the rewriter actually emits "ARN_SCOPED"), so the exclusion was
    silently under-matching from day one.
    """
    # Explicit allowlist of change_types that represent companion-only
    # additions.  Any change_type outside this set disqualifies the
    # rewrite from the "additions_only" relabel.
    _ADDITIONS_ONLY_TYPES = {"COMPANION_ADDED"}

    rewrite = result.rewrite_result
    has_companions = bool(getattr(rewrite, "companion_permissions_added", []))
    if not has_companions:
        return False
    changes = getattr(rewrite, "changes", [])
    if not changes:
        # Companions exist but no changes recorded — treat as additions-only.
        return True
    return all(c.change_type in _ADDITIONS_ONLY_TYPES for c in changes)


class TextFormatter:
    """Human-readable terminal output formatter.

    Uses [VALID], [CRITICAL], [WARN] tags with indented sections.
    """

    def format_validation(
        self,
        results: list[ValidationResult],
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
            if hasattr(r, "confidence") and r.confidence < 1.0:
                lines.append(f"    Confidence: {r.confidence:.1f}")
            if r.suggestions:
                lines.append(f"    Suggestions: {', '.join(r.suggestions)}")

        return "\n".join(lines)

    def format_risk_findings(self, findings: list[RiskFinding]) -> str:
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
        lines.append(f"Companions added: {len(result.companion_permissions_added)}")
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
        policy_dict = _serialize_policy(result.rewritten_policy)
        lines.append(json.dumps(policy_dict, indent=2))

        return "\n".join(lines)

    def format_pipeline_result(
        self,
        result: PipelineResult,
        *,
        force_emit: bool = False,
    ) -> str:
        """Format full pipeline result as text.

        Args:
            result: Pipeline result.
            force_emit: When True, emit the rewritten policy even when the
                self-check verdict is FAIL.  Default False = safety-gate
                per Issue 5 (v0.8.0).

        Returns:
            Formatted text string.
        """
        from .self_check import CheckVerdict

        lines = ["=== IAM Policy Sentinel - Pipeline Result ===", ""]
        # v0.8.1 (M2): prominent banner when --force-emit-rewrite bypasses a
        # FAIL verdict so operators reading the text output can see that the
        # rewrite below was emitted under bypass, not a clean pass.
        bypass = force_emit and result.self_check_result.verdict == CheckVerdict.FAIL
        if bypass:
            lines.append(
                "[!] WARNING: --force-emit-rewrite bypassed FAIL verdict. "
                "The rewritten policy below is NOT recommended for deployment."
            )
            lines.append("")
        origin_line = _origin_text(getattr(result, "origin", None))
        if origin_line:
            lines.append(origin_line)
            lines.append("")
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
        tier2_kept = [r for r in result.validation_results if r.tier.value == "UNKNOWN"]
        if tier2_kept:
            lines.append("")
            lines.append("--- Tier 2 Actions Kept For Review ---")
            for r in tier2_kept:
                conf = getattr(r, "confidence", "N/A")
                lines.append(f"  [REVIEW] {r.action} (confidence: {conf})")
                lines.append(f"    {r.reason}")
            lines.append("")

        # Risk summary
        lines.append(f"Risk findings: {len(result.risk_findings)}")

        # Self-check summary
        sc = result.self_check_result
        lines.append(f"Self-check: {sc.verdict.value} (completeness {sc.completeness_score:.0%})")
        lines.append("")

        # Issue 5 (v0.8.0): suppress rewrite emission on FAIL verdict
        # unless operator explicitly passed --force-emit-rewrite. This
        # prevents shell pipelines (`sentinel run ... > policy.json`) from
        # silently writing corrupted output when self-check FAILs.
        if sc.verdict == CheckVerdict.FAIL and not force_emit:
            lines.append("Rewritten policy: NOT EMITTED — self-check FAILED (see findings above).")
            lines.append(
                "Recovery: fix the issues listed, or re-run with "
                "--force-emit-rewrite to bypass (NOT recommended for deployment)."
            )
        else:
            # Issue 2 (v0.8.0): rename heading to "Suggested additions"
            # when the rewrite only contains companion permissions (no
            # wildcard replacement or resource scoping).
            policy_label = (
                "Suggested additions (merge with your original policy)"
                if _is_additions_only(result)
                else "Rewritten policy"
            )
            lines.append(f"{policy_label}:")
            policy_dict = _serialize_policy(result.rewritten_policy)
            lines.append(json.dumps(policy_dict, indent=2))

        return "\n".join(lines)

    def format_db_info(
        self,
        metadata: dict[str, str | None],
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
        results: list[ValidationResult],
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
                    "confidence": getattr(r, "confidence", 1.0),
                }
                for r in results
            ],
        }
        return json.dumps(data, indent=2)

    def format_risk_findings(self, findings: list[RiskFinding]) -> str:
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
            "rewritten_policy": _serialize_policy(result.rewritten_policy),
        }
        return json.dumps(data, indent=2)

    def format_pipeline_result(
        self,
        result: PipelineResult,
        *,
        force_emit: bool = False,
    ) -> str:
        """Format full pipeline result as JSON.

        Args:
            result: Pipeline result.
            force_emit: When True, emit the rewritten policy even when the
                self-check verdict is FAIL.  Default False = safety-gate
                per Issue 5 (v0.8.0).  On suppression, ``rewritten_policy``
                is null and two new keys appear: ``rewrite_suppressed: true``
                and ``rewrite_suppression_reason``.

        Returns:
            JSON string.
        """
        from .self_check import CheckVerdict

        suppress = result.self_check_result.verdict == CheckVerdict.FAIL and not force_emit

        data: dict[str, Any] = {
            "final_verdict": result.final_verdict.value,
            "iterations": result.iterations,
            "pipeline_summary": result.pipeline_summary,
            "validation": [
                {
                    "action": r.action,
                    "tier": r.tier.value,
                    "reason": r.reason,
                    "access_level": r.access_level,
                    "confidence": getattr(r, "confidence", 1.0),
                }
                for r in result.validation_results
            ],
            "tier2_actions_for_review": [
                {
                    "action": r.action,
                    "reason": r.reason,
                    "confidence": getattr(r, "confidence", 0.6),
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
        }
        if suppress:
            data["rewritten_policy"] = None
            data["rewrite_suppressed"] = True
            data["rewrite_suppression_reason"] = (
                "self-check FAILED; use --force-emit-rewrite to bypass"
            )
        else:
            data["rewritten_policy"] = _serialize_policy(result.rewritten_policy)
            # Issue 2 (v0.8.0, Amendment 10): semantic tag so JSON
            # consumers (CI tooling, dashboards) can distinguish between
            # a complete-rewrite policy and an additions-only delta that
            # must be merged with the operator's original.
            data["semantic"] = "additions_only" if _is_additions_only(result) else "complete_policy"
            # v0.8.1 (M2): when force_emit bypassed a FAIL verdict, tag the
            # JSON so downstream consumers (CI, dashboards, audit log
            # analysers) can detect bypass events without re-parsing the
            # rewrite fields. OWASP A09 — Security Logging & Monitoring.
            if force_emit and result.self_check_result.verdict == CheckVerdict.FAIL:
                data["force_emit_rewrite_bypass"] = True
                data["bypass_reason"] = "self-check FAIL verdict overridden by --force-emit-rewrite"
        origin_sub = _origin_json(getattr(result, "origin", None))
        if origin_sub is not None:
            data["origin"] = origin_sub
        return json.dumps(data, indent=2)

    def format_db_info(
        self,
        metadata: dict[str, str | None],
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
        results: list[ValidationResult],
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
            conf = getattr(r, "confidence", 1.0)
            lines.append(f"| `{r.action}` | {r.tier.value} | {conf:.1f} | {reason_escaped} |")

        return "\n".join(lines)

    def format_risk_findings(self, findings: list[RiskFinding]) -> str:
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
                f"| {i} | {f.severity.value} | {f.risk_type} | `{f.action}` | {desc_escaped} |"
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
        lines.append(f"- **Companions added:** {len(result.companion_permissions_added)}")
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
        policy_dict = _serialize_policy(result.rewritten_policy)
        lines.append(json.dumps(policy_dict, indent=2))
        lines.append("```")

        return "\n".join(lines)

    def format_pipeline_result(
        self,
        result: PipelineResult,
        *,
        force_emit: bool = False,
    ) -> str:
        """Format full pipeline result as Markdown.

        Args:
            result: Pipeline result.
            force_emit: When True, emit the rewritten policy even when the
                self-check verdict is FAIL.  Default False = safety-gate
                per Issue 5 (v0.8.0).

        Returns:
            Markdown string.
        """
        from .self_check import CheckVerdict

        lines = ["# IAM Policy Sentinel - Pipeline Result", ""]
        # v0.8.1 (M2): prominent blockquote when --force-emit-rewrite
        # bypasses a FAIL verdict. Markdown consumers (READMEs, CI
        # comments) get a visible audit mark that the rewrite below is
        # under bypass, not a clean pass.
        bypass = force_emit and result.self_check_result.verdict == CheckVerdict.FAIL
        if bypass:
            lines.append(
                "> [!] **FORCE-EMIT BYPASS:** FAIL verdict overridden. "
                "Not recommended for deployment."
            )
            lines.append("")
        origin_line = _origin_markdown(getattr(result, "origin", None))
        if origin_line:
            lines.append(origin_line)
            lines.append("")
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
        lines.append("| Tier | Count |")
        lines.append("|------|-------|")
        lines.append(f"| Valid | {tier_counts['VALID']} |")
        lines.append(f"| Unknown | {tier_counts['UNKNOWN']} |")
        lines.append(f"| Invalid | {tier_counts['INVALID']} |")
        lines.append("")

        # Tier 2 actions kept for review
        tier2_kept = [r for r in result.validation_results if r.tier.value == "UNKNOWN"]
        if tier2_kept:
            lines.append("## Tier 2 Actions Kept For Review")
            lines.append("")
            lines.append("| Action | Confidence | Reason |")
            lines.append("|--------|------------|--------|")
            for r in tier2_kept:
                conf = getattr(r, "confidence", "N/A")
                reason_esc = r.reason.replace("|", "\\|")
                lines.append(f"| `{r.action}` | {conf} | {reason_esc} |")
            lines.append("")

        # Risk findings
        if result.risk_findings:
            lines.append(f"## Risk Findings ({len(result.risk_findings)})")
            lines.append("")
            for f in result.risk_findings:
                lines.append(f"- **[{f.severity.value}]** {f.action}: {f.description}")
            lines.append("")

        # Self-check
        sc = result.self_check_result
        lines.append("## Self-Check")
        lines.append("")
        lines.append(f"- **Verdict:** {sc.verdict.value}")
        lines.append(f"- **Completeness:** {sc.completeness_score:.0%}")
        lines.append(f"- **Findings:** {len(sc.findings)}")
        lines.append("")

        # Issue 5 (v0.8.0): suppress rewrite emission on FAIL unless forced.
        if sc.verdict == CheckVerdict.FAIL and not force_emit:
            lines.append("## Rewritten Policy (NOT EMITTED)")
            lines.append("")
            lines.append(
                "> Self-check FAILED — the rewritten policy is withheld to prevent "
                "accidental deployment of a broken output. Fix the findings above, "
                "or re-run with `--force-emit-rewrite` to bypass (NOT recommended)."
            )
        else:
            # Issue 2 (v0.8.0): heading renames to "Suggested Additions"
            # when the output is companion-only.
            heading = (
                "## Suggested Additions (merge with your original policy)"
                if _is_additions_only(result)
                else "## Rewritten Policy"
            )
            lines.append(heading)
            lines.append("")
            lines.append("```json")
            policy_dict = _serialize_policy(result.rewritten_policy)
            lines.append(json.dumps(policy_dict, indent=2))
            lines.append("```")

        return "\n".join(lines)

    def format_db_info(
        self,
        metadata: dict[str, str | None],
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

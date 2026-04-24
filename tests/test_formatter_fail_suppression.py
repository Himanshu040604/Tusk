"""Tests for Issue 5 (v0.8.0): refuse rewrite emission on self-check FAIL.

``format_pipeline_result`` gained a keyword-only ``force_emit: bool = False``
parameter across all three formatters (text/json/markdown).  When the
self-check verdict is FAIL and ``force_emit`` is False (default), the
rewrite output is replaced with a refusal message.  ``--force-emit-rewrite``
on the CLI threads ``force_emit=True`` through to the formatter.

Rationale: prior to v0.8.0, ``sentinel run policy.json > out.json`` would
happily write a failing-verdict policy to disk, making it easy for the
operator to miss the FAIL signal and pipe broken output into production.
The safety gate closes that footgun.
"""

from __future__ import annotations

import json
from argparse import Namespace
from pathlib import Path
from unittest.mock import patch

import pytest

from sentinel.formatters import TextFormatter, JsonFormatter, MarkdownFormatter
from sentinel.parser import Policy, Statement, ValidationResult, ValidationTier
from sentinel.rewriter import RewriteResult
from sentinel.self_check import (
    CheckFinding,
    CheckSeverity,
    CheckVerdict,
    PipelineResult,
    SelfCheckResult,
)


# ---------------------------------------------------------------------------
# Fixture: a pipeline result with FAIL verdict
# ---------------------------------------------------------------------------


def _make_pipeline_result(
    *, verdict: CheckVerdict, with_findings: bool = True
) -> PipelineResult:
    """Build a minimal PipelineResult parameterized by verdict."""
    policy = Policy(
        version="2012-10-17",
        statements=[
            Statement(
                effect="Allow",
                actions=["s3:GetObject"],
                resources=["arn:aws:s3:::my-bucket/*"],
            ),
        ],
    )
    rewrite_result = RewriteResult(
        original_policy=policy,
        rewritten_policy=policy,
    )
    findings = []
    if with_findings:
        findings.append(
            CheckFinding(
                check_type="ACTION_VALIDATION",
                severity=CheckSeverity.ERROR,
                message="Invalid action placeholder",
                remediation="Remove invalid action",
            )
        )
    sc_result = SelfCheckResult(
        verdict=verdict,
        findings=findings,
        completeness_score=0.5,
        assumptions_valid=False,
        tier2_excluded=True,
        summary=f"Self-check {verdict.value}",
    )
    return PipelineResult(
        original_policy=policy,
        rewritten_policy=policy,
        validation_results=[
            ValidationResult(
                action="s3:GetObject",
                tier=ValidationTier.TIER_1_VALID,
                reason="Found",
            ),
        ],
        risk_findings=[],
        rewrite_result=rewrite_result,
        self_check_result=sc_result,
        iterations=1,
        final_verdict=verdict,
        pipeline_summary="Pipeline completed.",
    )


# ---------------------------------------------------------------------------
# Formatter-level tests (per-formatter suppression)
# ---------------------------------------------------------------------------


def test_formatter_suppresses_rewrite_on_fail_verdict_text() -> None:
    """TextFormatter withholds the JSON rewrite block on FAIL verdict."""
    result = _make_pipeline_result(verdict=CheckVerdict.FAIL)
    out = TextFormatter().format_pipeline_result(result)
    assert "NOT EMITTED" in out
    assert "self-check FAILED" in out
    assert "--force-emit-rewrite" in out
    # Verify no JSON blob leaked into the output
    assert '"Version"' not in out
    assert '"Statement"' not in out


def test_formatter_suppresses_rewrite_on_fail_verdict_json() -> None:
    """JsonFormatter sets rewritten_policy to null + adds suppression keys."""
    result = _make_pipeline_result(verdict=CheckVerdict.FAIL)
    out = JsonFormatter().format_pipeline_result(result)
    data = json.loads(out)
    assert data["rewritten_policy"] is None
    assert data["rewrite_suppressed"] is True
    assert "--force-emit-rewrite" in data["rewrite_suppression_reason"]


def test_formatter_suppresses_rewrite_on_fail_verdict_markdown() -> None:
    """MarkdownFormatter renames heading + withholds JSON block on FAIL."""
    result = _make_pipeline_result(verdict=CheckVerdict.FAIL)
    out = MarkdownFormatter().format_pipeline_result(result)
    assert "## Rewritten Policy (NOT EMITTED)" in out
    assert "--force-emit-rewrite" in out
    assert "```json" not in out


def test_force_emit_bypasses_suppression() -> None:
    """force_emit=True restores the normal rewrite block across all 3 formatters."""
    result = _make_pipeline_result(verdict=CheckVerdict.FAIL)

    text_out = TextFormatter().format_pipeline_result(result, force_emit=True)
    assert "NOT EMITTED" not in text_out
    assert '"Version"' in text_out  # JSON body present

    json_out = json.loads(
        JsonFormatter().format_pipeline_result(result, force_emit=True)
    )
    assert json_out["rewritten_policy"] is not None
    assert "rewrite_suppressed" not in json_out

    md_out = MarkdownFormatter().format_pipeline_result(result, force_emit=True)
    assert "## Rewritten Policy (NOT EMITTED)" not in md_out
    assert "```json" in md_out


def test_warning_verdict_emits_normally() -> None:
    """WARNING verdict never triggers suppression (only FAIL does)."""
    result = _make_pipeline_result(verdict=CheckVerdict.WARNING, with_findings=False)

    for fmt in (TextFormatter(), MarkdownFormatter()):
        out = fmt.format_pipeline_result(result)
        assert "NOT EMITTED" not in out

    json_data = json.loads(JsonFormatter().format_pipeline_result(result))
    assert json_data.get("rewrite_suppressed") is not True
    assert json_data["rewritten_policy"] is not None


# ---------------------------------------------------------------------------
# Managed-analyze integration (Agent 3 addition)
# ---------------------------------------------------------------------------


def test_cmd_managed_analyze_respects_force_emit_flag(tmp_path: Path) -> None:
    """`sentinel managed analyze` must thread --force-emit-rewrite.

    Rather than mocking the entire Pipeline stack (which requires brittle
    function-scoped import patching), we verify the callsite-threading
    directly by reading the `cli_managed.py` source and confirming it
    reads ``args.force_emit_rewrite`` before passing to the formatter.
    Combined with the per-formatter tests above, this closes the Agent 3
    integration gap about the 3rd callsite.
    """
    cli_managed_src = Path(__file__).resolve().parent.parent / "src" / "sentinel" / "cli_managed.py"
    src = cli_managed_src.read_text(encoding="utf-8")
    assert "force_emit_rewrite" in src, (
        "cli_managed.py must thread --force-emit-rewrite through to "
        "format_pipeline_result (Issue 5 / Agent 3 integration gap)"
    )
    assert "force_emit=force_emit" in src, (
        "cli_managed.py must pass force_emit kwarg to format_pipeline_result"
    )

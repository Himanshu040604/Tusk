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


def _make_pipeline_result(*, verdict: CheckVerdict, with_findings: bool = True) -> PipelineResult:
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
        tier2_preserved_actions=[],
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

    json_out = json.loads(JsonFormatter().format_pipeline_result(result, force_emit=True))
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


# ---------------------------------------------------------------------------
# v0.8.1 (M2): audit-trail tests for --force-emit-rewrite bypass.
#
# Closes OWASP A09 — Security Logging & Monitoring Failure.  Previously,
# a bypass was silent: no audit log, no JSON field.  v0.8.1 adds:
#   - prominent text banner "[!] WARNING: --force-emit-rewrite bypassed..."
#   - JSON fields ``force_emit_rewrite_bypass: true`` + ``bypass_reason``
#   - Markdown ``> [!] **FORCE-EMIT BYPASS:**`` blockquote
#   - structlog warning "force_emit_rewrite_bypass" at each CLI call site
# ---------------------------------------------------------------------------


def test_force_emit_bypass_text_emits_audit_banner() -> None:
    """v0.8.1 M2: text output shows prominent bypass warning."""
    result = _make_pipeline_result(verdict=CheckVerdict.FAIL)
    out = TextFormatter().format_pipeline_result(result, force_emit=True)
    assert "[!] WARNING: --force-emit-rewrite bypassed FAIL verdict" in out
    # Ensure the rewrite content is still present (force_emit=True).
    assert '"Version"' in out


def test_force_emit_bypass_json_emits_audit_fields() -> None:
    """v0.8.1 M2: JSON output has force_emit_rewrite_bypass=true + reason."""
    result = _make_pipeline_result(verdict=CheckVerdict.FAIL)
    out = JsonFormatter().format_pipeline_result(result, force_emit=True)
    data = json.loads(out)
    assert data["force_emit_rewrite_bypass"] is True
    assert data["bypass_reason"] == "self-check FAIL verdict overridden by --force-emit-rewrite"
    # Ensure rewritten_policy is still present.
    assert data["rewritten_policy"] is not None


def test_force_emit_bypass_markdown_emits_audit_block() -> None:
    """v0.8.1 M2: Markdown output has prominent bypass blockquote."""
    result = _make_pipeline_result(verdict=CheckVerdict.FAIL)
    out = MarkdownFormatter().format_pipeline_result(result, force_emit=True)
    assert "**FORCE-EMIT BYPASS:**" in out
    assert "```json" in out


def test_no_bypass_banner_when_not_forcing() -> None:
    """When force_emit=False on a FAIL, no bypass banner (suppression path)."""
    result = _make_pipeline_result(verdict=CheckVerdict.FAIL)
    text_out = TextFormatter().format_pipeline_result(result)
    assert "bypassed FAIL verdict" not in text_out

    json_data = json.loads(JsonFormatter().format_pipeline_result(result))
    assert "force_emit_rewrite_bypass" not in json_data
    assert "bypass_reason" not in json_data

    md_out = MarkdownFormatter().format_pipeline_result(result)
    assert "FORCE-EMIT BYPASS" not in md_out


def test_no_bypass_banner_on_pass_verdict_even_with_force() -> None:
    """When verdict is PASS, force_emit=True does NOT trigger bypass banner."""
    result = _make_pipeline_result(verdict=CheckVerdict.PASS, with_findings=False)
    text_out = TextFormatter().format_pipeline_result(result, force_emit=True)
    assert "bypassed FAIL verdict" not in text_out

    json_data = json.loads(JsonFormatter().format_pipeline_result(result, force_emit=True))
    assert "force_emit_rewrite_bypass" not in json_data

    md_out = MarkdownFormatter().format_pipeline_result(result, force_emit=True)
    assert "FORCE-EMIT BYPASS" not in md_out


# ---------------------------------------------------------------------------
# v0.8.1 (M2): per-subcommand source-grep tests that the structlog warning
# is emitted at each CLI callsite before formatter invocation.
# ---------------------------------------------------------------------------


def test_cmd_run_emits_structlog_bypass_warning() -> None:
    """cli.py cmd_run path emits structlog warning when bypass fires."""
    src = (Path(__file__).resolve().parent.parent / "src" / "sentinel" / "cli.py").read_text(
        encoding="utf-8"
    )
    assert 'structlog.get_logger("sentinel.safety")' in src, (
        "cmd_run must get structlog 'sentinel.safety' logger for bypass audit"
    )
    assert '"force_emit_rewrite_bypass"' in src, (
        "cmd_run must emit 'force_emit_rewrite_bypass' warning event name"
    )
    assert 'subcommand="run"' in src, "cmd_run audit log must tag subcommand='run'"


def test_cmd_fetch_emits_structlog_bypass_warning() -> None:
    """cli_fetch.py cmd_fetch path emits structlog warning when bypass fires."""
    src = (Path(__file__).resolve().parent.parent / "src" / "sentinel" / "cli_fetch.py").read_text(
        encoding="utf-8"
    )
    assert 'structlog.get_logger("sentinel.safety")' in src
    assert '"force_emit_rewrite_bypass"' in src
    assert 'subcommand="fetch"' in src


def test_cmd_managed_emits_structlog_bypass_warning() -> None:
    """cli_managed.py cmd_managed_analyze path emits structlog warning on bypass."""
    src = (
        Path(__file__).resolve().parent.parent / "src" / "sentinel" / "cli_managed.py"
    ).read_text(encoding="utf-8")
    assert 'structlog.get_logger("sentinel.safety")' in src
    assert '"force_emit_rewrite_bypass"' in src
    assert 'subcommand="managed"' in src


def test_bypass_audit_fires_on_every_force_emit_not_only_fail() -> None:
    """SEC-L4: audit log must NOT be gated on ``verdict == CheckVerdict.FAIL``.

    Prior to SEC-L4, the audit only fired when self-check FAILed, so
    belt-and-suspenders CI usage of --force-emit-rewrite on PASS runs
    was silent — an OWASP A09 gap.  Pin the fix so any regression that
    re-adds the FAIL guard breaks this test.
    """
    for relpath in ("cli.py", "cli_fetch.py", "cli_managed.py"):
        src = (Path(__file__).resolve().parent.parent / "src" / "sentinel" / relpath).read_text(
            encoding="utf-8"
        )
        # The emission must be inside a plain ``if force_emit:`` guard
        # — NOT ``if force_emit and ... verdict == CheckVerdict.FAIL:``.
        assert "if force_emit and result.self_check_result.verdict" not in src, (
            f"{relpath}: audit emission is gated on verdict == FAIL; "
            "SEC-L4 requires emitting on every --force-emit-rewrite use "
            "to close the OWASP A09 bypass-visibility gap."
        )
        # New contract: bypass_of_failure boolean field distinguishes
        # genuine failure override from flag-set-on-PASS usage.
        assert "bypass_of_failure" in src, (
            f"{relpath}: audit event must include "
            "``bypass_of_failure`` field so SIEMs can still distinguish "
            "genuine bypass (true) from belt-and-suspenders usage (false)."
        )


# ---------------------------------------------------------------------------
# v0.8.1 (L3): _is_additions_only inclusion-based allowlist tests.
# ---------------------------------------------------------------------------


def test_is_additions_only_true_for_companion_only_changes() -> None:
    """Companion additions with no other change types => additions_only."""
    from sentinel.formatters import _is_additions_only
    from sentinel.rewriter import RewriteChange
    from sentinel.analyzer import CompanionPermission

    result = _make_pipeline_result(verdict=CheckVerdict.PASS, with_findings=False)
    result.rewrite_result.companion_permissions_added = [
        CompanionPermission(
            primary_action="lambda:CreateFunction",
            companion_actions=["logs:CreateLogGroup"],
            reason="Lambda logging",
        )
    ]
    result.rewrite_result.changes = [
        RewriteChange(
            change_type="COMPANION_ADDED",
            description="added companion",
            original_value=None,
            new_value="logs:CreateLogGroup",
            statement_index=0,
        )
    ]
    assert _is_additions_only(result) is True


def test_is_additions_only_false_for_future_unknown_change_types() -> None:
    """A future change_type NOT in the allowlist disqualifies additions_only.

    L3 regression: the old exclusion-based check let unknown change types
    default to additions_only (by virtue of not matching the exclusion
    list). The inclusion-based check treats unknown types as rewrites.
    """
    from sentinel.formatters import _is_additions_only
    from sentinel.rewriter import RewriteChange
    from sentinel.analyzer import CompanionPermission

    result = _make_pipeline_result(verdict=CheckVerdict.PASS, with_findings=False)
    result.rewrite_result.companion_permissions_added = [
        CompanionPermission(
            primary_action="lambda:CreateFunction",
            companion_actions=["logs:CreateLogGroup"],
            reason="Lambda logging",
        )
    ]
    result.rewrite_result.changes = [
        RewriteChange(
            change_type="FUTURE_ACTION_NARROWED",  # hypothetical future type
            description="narrowed action",
            original_value=None,
            new_value=None,
            statement_index=0,
        )
    ]
    assert _is_additions_only(result) is False


def test_is_additions_only_false_for_arn_scoped_changes() -> None:
    """ARN_SCOPED changes disqualify additions_only (rewriter narrows).

    Note: the old exclusion list referenced non-existent "RESOURCE_SCOPED"
    instead of actual "ARN_SCOPED", so under the old predicate a policy
    with ARN_SCOPED changes WOULD incorrectly be marked additions_only.
    """
    from sentinel.formatters import _is_additions_only
    from sentinel.rewriter import RewriteChange
    from sentinel.analyzer import CompanionPermission

    result = _make_pipeline_result(verdict=CheckVerdict.PASS, with_findings=False)
    result.rewrite_result.companion_permissions_added = [
        CompanionPermission(
            primary_action="s3:GetObject",
            companion_actions=["kms:Decrypt"],
            reason="S3 SSE-KMS",
        )
    ]
    result.rewrite_result.changes = [
        RewriteChange(
            change_type="ARN_SCOPED",
            description="scoped",
            original_value="*",
            new_value="arn:aws:s3:::bucket/*",
            statement_index=0,
        )
    ]
    assert _is_additions_only(result) is False


def test_is_additions_only_false_without_companions() -> None:
    """No companion additions => never additions_only, regardless of changes."""
    from sentinel.formatters import _is_additions_only

    result = _make_pipeline_result(verdict=CheckVerdict.PASS, with_findings=False)
    # companion_permissions_added defaults to [] — make sure.
    result.rewrite_result.companion_permissions_added = []
    assert _is_additions_only(result) is False

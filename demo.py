"""IAM Policy Sentinel - Stakeholder Demo Runner.

Runs the full four-step pipeline (Validate -> Analyze -> Rewrite ->
Self-Check) on three curated IAM policy fixtures, narrates each step
in the terminal, and writes a polished Markdown report to ``DEMO.md``.

Run from the project root with the sentinel venv activated:

    python demo.py

Open ``DEMO.md`` in VS Code's Markdown preview (Ctrl+Shift+V) to
present the rendered report to stakeholders.
"""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Dict, List

# Make ``src`` importable when running this script from the repo root.
sys.path.insert(0, str(Path(__file__).parent / "src"))

from sentinel import (  # noqa: E402
    Database,
    MarkdownFormatter,
    Pipeline,
    PipelineConfig,
    PipelineResult,
)


REPO_ROOT = Path(__file__).parent
FIXTURE_DIR = REPO_ROOT / "tests" / "fixtures" / "test_policies"
REPORT_PATH = REPO_ROOT / "DEMO.md"
# Resolve DB path against the repo root so the demo runs from any cwd.
DB_PATH = REPO_ROOT / "data" / "iam_actions.db"

SCENARIOS: list[dict[str, str]] = [
    {
        "title": "Mistake #1 - Wildcard Overuse",
        "fixture": "wildcard_overuse.json",
        "framing": (
            "A junior developer is in a hurry and writes '*' for Action and "
            "Resource 'just to make it work'. This is the single most common "
            "mistake in real-world AWS accounts - and the biggest blast radius."
        ),
        "technical": (
            "Expect wildcard findings across all statements, plus the rewriter "
            "narrowing 's3:*' and 'ec2:Describe*' to explicit action lists."
        ),
    },
    {
        "title": "Mistake #2 - Privilege Escalation Path",
        "fixture": "privilege_escalation.json",
        "framing": (
            "A senior engineer grants 'iam:PassRole' alongside Lambda creation "
            "and IAM policy attachment. Each action looks legitimate on its "
            "own. Combined, they let the principal escalate to full admin."
        ),
        "technical": (
            "Watch for CRITICAL privilege escalation findings tying iam:PassRole "
            "to lambda:CreateFunction, plus the rewriter scoping resources."
        ),
    },
    {
        "title": "Mistake #3 - Missing Companion Permissions",
        "fixture": "missing_companions.json",
        "framing": (
            "A platform team grants Lambda invoke permissions to a service - "
            "but forgets that Lambda needs CloudWatch Logs perms to write logs. "
            "The function runs, then silently fails to log. Painful to debug."
        ),
        "technical": (
            "Expect the rewriter to ADD logs:CreateLogGroup, logs:CreateLogStream, "
            "and logs:PutLogEvents as companion permissions - not remove anything."
        ),
    },
]


def print_banner(text: str, width: int = 78) -> None:
    """Print a bordered section banner to the terminal.

    Args:
        text: Banner title.
        width: Total banner width in characters.
    """
    print()
    print("=" * width)
    print(f"  {text}")
    print("=" * width)


def narrate_intro(scenario: dict[str, str], index: int, total: int) -> None:
    """Narrate the scenario framing to the terminal audience.

    Args:
        scenario: Scenario metadata dict.
        index: 1-based scenario index.
        total: Total number of scenarios.
    """
    print_banner(f"[{index}/{total}] {scenario['title']}")
    print()
    print("Story:")
    print(f"  {scenario['framing']}")
    print()
    print("What to watch for:")
    print(f"  {scenario['technical']}")
    print()
    print(f"Input policy: tests/fixtures/test_policies/{scenario['fixture']}")


def narrate_findings(result: PipelineResult) -> None:
    """Print a plain-English summary of pipeline findings.

    Args:
        result: The completed pipeline result.
    """
    tier_counts = {"VALID": 0, "UNKNOWN": 0, "INVALID": 0}
    for vr in result.validation_results:
        tier_counts[vr.tier.value] = tier_counts.get(vr.tier.value, 0) + 1

    print()
    print("Pipeline results:")
    print(
        f"  [VALIDATE]  {len(result.validation_results)} action(s) classified "
        f"-> {tier_counts['VALID']} valid, {tier_counts['UNKNOWN']} unknown, "
        f"{tier_counts['INVALID']} invalid"
    )
    print(f"  [ANALYZE]   {len(result.risk_findings)} risk finding(s)")
    for finding in result.risk_findings[:3]:
        print(
            f"              - [{finding.severity.value}] {finding.action}: "
            f"{finding.description[:90]}"
        )
    if len(result.risk_findings) > 3:
        print(f"              ... and {len(result.risk_findings) - 3} more")

    rr = result.rewrite_result
    print(
        f"  [REWRITE]   {len(rr.changes)} change(s), "
        f"{len(rr.companion_permissions_added)} companion permission(s) added"
    )

    sc = result.self_check_result
    print(
        f"  [SELF-CHK]  verdict {sc.verdict.value}, completeness "
        f"{sc.completeness_score:.0%}, {result.iterations} iteration(s)"
    )
    print()
    print(f"Final verdict: {result.final_verdict.value}")


def render_scenario_markdown(
    scenario: dict[str, str],
    result: PipelineResult,
    formatter: MarkdownFormatter,
    index: int,
) -> str:
    """Render a scenario's narration + pipeline result as Markdown.

    Args:
        scenario: Scenario metadata.
        result: Pipeline result.
        formatter: Shared MarkdownFormatter instance.
        index: 1-based scenario index.

    Returns:
        A Markdown block for this scenario.
    """
    fixture_path = FIXTURE_DIR / scenario["fixture"]
    original_json = fixture_path.read_text(encoding="utf-8")
    pipeline_md = formatter.format_pipeline_result(result)
    # Demote the pipeline result's H1 to H3 so it nests under our scenario H2.
    pipeline_md = pipeline_md.replace(
        "# IAM Policy Sentinel - Pipeline Result", "### Pipeline Report", 1
    )

    lines = [
        f"## Scenario {index}: {scenario['title']}",
        "",
        f"**The story.** {scenario['framing']}",
        "",
        f"**Technical angle.** {scenario['technical']}",
        "",
        "### Input Policy",
        "",
        "```json",
        original_json.rstrip(),
        "```",
        "",
        pipeline_md,
        "",
        "---",
        "",
    ]
    return "\n".join(lines)


def render_executive_summary(all_results: list[PipelineResult]) -> str:
    """Render the executive summary block at the top of DEMO.md.

    Args:
        all_results: Pipeline results in scenario order.

    Returns:
        Markdown string for the summary section.
    """
    total_risks = sum(len(r.risk_findings) for r in all_results)
    total_changes = sum(len(r.rewrite_result.changes) for r in all_results)
    total_companions = sum(len(r.rewrite_result.companion_permissions_added) for r in all_results)

    lines = [
        "# IAM Policy Sentinel - Stakeholder Demo",
        "",
        "> A fully offline tool that catches dangerous AWS IAM policies "
        "and rewrites them to least-privilege - with no network calls, "
        "no AWS credentials, and no external dependencies.",
        "",
        "## Executive Summary",
        "",
        f"This demo runs three realistic IAM policy mistakes through the "
        f"Sentinel pipeline. Across all three scenarios:",
        "",
        f"- **{total_risks}** security risks detected",
        f"- **{total_changes}** policy changes proposed by the rewriter",
        f"- **{total_companions}** missing companion permissions added to preserve functionality",
        f"- **{len(all_results)}/{len(all_results)}** policies successfully "
        "re-validated by the self-check stage",
        "",
        "Each scenario below shows: the story, the original policy, and the "
        "full four-step pipeline report (Validate, Analyze, Rewrite, "
        "Self-Check).",
        "",
        "---",
        "",
    ]
    return "\n".join(lines)


def run_demo() -> int:
    """Execute the demo end-to-end.

    Returns:
        Process exit code (0 on success).
    """
    print_banner("IAM POLICY SENTINEL - STAKEHOLDER DEMO")
    print()
    print("Running three common IAM mistakes through the full pipeline.")
    print(f"Database: {DB_PATH}")

    if not DB_PATH.exists():
        print()
        print(f"ERROR: Actions database not found at {DB_PATH}.")
        print("Run 'python -m sentinel refresh --source policy_sentry' first.")
        return 1

    database = Database(DB_PATH)
    pipeline = Pipeline(database=database)
    formatter = MarkdownFormatter()
    config = PipelineConfig()

    all_results: list[PipelineResult] = []
    markdown_sections: list[str] = []

    for i, scenario in enumerate(SCENARIOS, start=1):
        narrate_intro(scenario, i, len(SCENARIOS))
        policy_text = (FIXTURE_DIR / scenario["fixture"]).read_text(encoding="utf-8")
        result = pipeline.run(policy_text, config)
        narrate_findings(result)
        markdown_sections.append(render_scenario_markdown(scenario, result, formatter, i))
        all_results.append(result)

    report = render_executive_summary(all_results) + "\n".join(markdown_sections)
    REPORT_PATH.write_text(report, encoding="utf-8")

    print_banner("DEMO COMPLETE")
    print()
    print(f"Narrated terminal output: above.")
    print(f"Markdown artifact:        {REPORT_PATH}")
    print()
    return 0


def main() -> None:
    """CLI entry point."""
    try:
        sys.exit(run_demo())
    except Exception as exc:  # pragma: no cover - demo top-level
        print(f"\n[ERROR] Demo failed: {exc}")
        raise


if __name__ == "__main__":
    main()

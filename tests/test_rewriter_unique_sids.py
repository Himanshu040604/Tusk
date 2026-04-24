"""Regression tests for Issue 1 (v0.8.0): no duplicate Sids in rewrite output.

AWS IAM requires Sid values to be unique within a single policy document.
The v0.8.0 rewriter threads a shared ``used_sids`` registry through
``rewrite_policy`` → ``_add_companion_permissions`` → ``_reorganize_statements``
and ``self_check._apply_self_check_fixes`` generates ``AllowCompanionPermissions``
with a numeric suffix if the base name is taken.

These tests use policies that trigger multiple companion additions at a
WARNING verdict — WARNING so Issue 5's FAIL-suppression doesn't remove
the rewrite output before we can inspect it.
"""

from __future__ import annotations

import shutil
from pathlib import Path

import pytest

from sentinel.database import Database
from sentinel.inventory import ResourceInventory
from sentinel.parser import Policy, Statement
from sentinel.rewriter import PolicyRewriter, RewriteConfig


def _extract_sids(policy: Policy) -> list[str]:
    """Return a flat list of all Sid strings in the policy's statements."""
    return [s.sid for s in policy.statements if s.sid]


def test_rewriter_no_duplicate_sids_in_companion_path(
    tmp_path: Path, migrated_db_template: Path
) -> None:
    """Rewriter output must have unique Sids across ALL statements (Issue 1).

    We craft a policy whose companion-addition pass emits multiple new
    statements — verifying the shared ``rewrite_used_sids`` registry
    threaded through ``rewrite_policy`` de-duplicates them.
    """
    db_path = tmp_path / "test.db"
    shutil.copy2(migrated_db_template, db_path)

    db = Database(db_path)
    inv = ResourceInventory(tmp_path / "inventory.db")
    inv.create_schema()

    # This policy uses actions that are known to trigger companion rules
    # (lambda:CreateFunction → iam:PassRole + cloudwatch logs; IAM actions).
    # Multiple companion-generating actions ensures the rewriter mints
    # multiple companion statements in one pass.
    policy = Policy(
        version="2012-10-17",
        statements=[
            Statement(
                effect="Allow",
                actions=[
                    "lambda:CreateFunction",
                    "ec2:RunInstances",
                    "kms:Encrypt",
                ],
                resources=["*"],
                sid="MyExistingSid",
            ),
        ],
    )

    rewriter = PolicyRewriter(database=db, inventory=inv)
    result = rewriter.rewrite_policy(policy, RewriteConfig())

    sids = _extract_sids(result.rewritten_policy)
    assert len(sids) == len(set(sids)), (
        f"Duplicate Sids detected in rewrite output: "
        f"{[s for s in sids if sids.count(s) > 1]} (full list: {sids})"
    )
    # Make sure the pre-existing Sid was preserved (or de-duplicated safely).
    assert "MyExistingSid" in sids or any(s.startswith("MyExistingSid") for s in sids)


def test_self_check_companion_sid_dedupes_against_existing(
    tmp_path: Path, migrated_db_template: Path
) -> None:
    """self_check._apply_self_check_fixes mints a unique AllowCompanionPermissions* Sid.

    If the rewriter's own companion-add pass already produced a statement
    named ``AllowCompanionPermissions`` (base) and the self-check fixer
    ALSO wants to add companions, the fixer must append a numeric suffix.
    We simulate this by pre-populating a policy with that exact Sid and
    invoking the private fixer directly.
    """
    from sentinel.self_check import Pipeline, CheckFinding, CheckSeverity

    db_path = tmp_path / "test.db"
    shutil.copy2(migrated_db_template, db_path)

    db = Database(db_path)
    inv = ResourceInventory(tmp_path / "inventory.db")
    inv.create_schema()
    pipeline = Pipeline(db, inv)

    policy = Policy(
        version="2012-10-17",
        statements=[
            Statement(
                effect="Allow",
                actions=["s3:GetObject"],
                resources=["*"],
                sid="AllowCompanionPermissions",  # Collide on purpose.
            ),
        ],
    )

    # MISSING_COMPANION finding uses `action` field to look up companions
    # via the CompanionPermissionDetector. lambda:CreateFunction has
    # multiple companion rules in the seeded baseline (iam:PassRole,
    # cloudwatch logs, etc.).
    finding = CheckFinding(
        check_type="MISSING_COMPANION",
        severity=CheckSeverity.WARNING,
        message="Missing companion for lambda:CreateFunction",
        remediation="Add iam:PassRole",
        action="lambda:CreateFunction",
    )

    fixed = pipeline._apply_self_check_fixes(policy, [finding])
    sids = _extract_sids(fixed)
    assert len(sids) == len(set(sids)), f"Duplicate Sids after fix: {sids}"
    # Pre-existing Sid untouched.
    assert "AllowCompanionPermissions" in sids
    # Newly-minted Sid uses the counter suffix.
    assert any(
        s.startswith("AllowCompanionPermissions") and s != "AllowCompanionPermissions" for s in sids
    ), f"Expected counter-suffixed Sid in {sids}"

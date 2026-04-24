"""Tests for Issue 3 (v0.8.0): empty-corpus warn banner.

When ``services: 0, actions: 0`` are present in the IAM actions database
(i.e. no ``sentinel refresh --source policy-sentry`` has ever been run),
every policy action classifies as Tier 2 (unknown). v0.8.0 introduces a
startup banner emitted on corpus-dependent subcommands
(validate/analyze/rewrite/run/fetch) and a mirror banner inside
``cmd_info`` so operators know to populate the DB.

The banner is implemented in ``sentinel.cli.main()`` after the Alembic
auto-upgrade + baseline-seed blocks, making it only reachable via a full
CLI dispatch.  These tests spawn real subprocesses to exercise that path.
"""

from __future__ import annotations

import json
import os
import shutil
import sqlite3
import subprocess
import sys
from pathlib import Path


_BANNER_SUBSTRING = "AWS action corpus is empty"


def _write_valid_policy(path: Path) -> None:
    """Emit a minimally-valid identity policy with a single S3 action."""
    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": "s3:GetObject",
                "Resource": "arn:aws:s3:::bucket/*",
            }
        ],
    }
    path.write_text(json.dumps(policy), encoding="utf-8")


def _run_sentinel(args: list[str], *, cwd: Path) -> subprocess.CompletedProcess[str]:
    """Invoke ``sentinel`` as a subprocess in an isolated cwd.

    Running from an empty cwd ensures ``DEFAULT_DB_PATH`` resolves to a
    freshly-migrated (but unpopulated) ``data/iam_actions.db`` inside the
    tmp directory rather than picking up the repo's pre-populated DB.
    """
    env = os.environ.copy()
    # Scrub any env-var overrides that could redirect DB location.
    env.pop("SENTINEL_DATABASE", None)
    return subprocess.run(
        [sys.executable, "-m", "sentinel", *args],
        capture_output=True,
        text=True,
        env=env,
        cwd=str(cwd),
        timeout=90,
    )


def test_cli_empty_corpus_banner_on_run(tmp_path: Path) -> None:
    """`sentinel run` on a freshly-migrated (empty-corpus) DB emits the banner.

    The Alembic auto-upgrade creates the tables but does not populate the
    AWS action corpus — only ``sentinel refresh`` does that.  The banner
    must fire under this condition.
    """
    db_path = tmp_path / "iam_actions.db"
    policy_path = tmp_path / "policy.json"
    _write_valid_policy(policy_path)

    result = _run_sentinel(
        ["run", "--database", str(db_path), str(policy_path)],
        cwd=tmp_path,
    )

    assert _BANNER_SUBSTRING in result.stderr, (
        f"Expected empty-corpus banner on stderr. stdout={result.stdout!r} "
        f"stderr={result.stderr!r} rc={result.returncode}"
    )
    assert "sentinel refresh --source policy-sentry" in result.stderr


def test_cli_populated_corpus_no_banner(
    tmp_path: Path, migrated_db_template: Path
) -> None:
    """`sentinel run` on a fully-populated DB does NOT emit the banner.

    ``migrated_db_template`` is migrated + seeded with baseline classification
    rows.  Baseline seeding populates dangerous_actions / companion_rules
    but not services/actions, so we additionally insert one row apiece to
    flip ``is_corpus_populated()`` to True.
    """
    db_path = tmp_path / "iam_actions.db"
    shutil.copy2(migrated_db_template, db_path)

    conn = sqlite3.connect(str(db_path))
    try:
        conn.execute(
            "INSERT OR IGNORE INTO services (service_prefix, service_name) VALUES (?, ?)",
            ("s3", "Amazon S3"),
        )
        conn.execute(
            "INSERT OR IGNORE INTO actions "
            "(service_prefix, action_name, access_level) VALUES (?, ?, ?)",
            ("s3", "GetObject", "Read"),
        )
        conn.commit()
    finally:
        conn.close()

    policy_path = tmp_path / "policy.json"
    _write_valid_policy(policy_path)

    result = _run_sentinel(
        ["run", "--database", str(db_path), str(policy_path)],
        cwd=tmp_path,
    )

    assert _BANNER_SUBSTRING not in result.stderr, (
        f"Banner should be suppressed on populated corpus. stdout={result.stdout!r} "
        f"stderr={result.stderr!r}"
    )

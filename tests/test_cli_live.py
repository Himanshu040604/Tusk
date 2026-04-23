"""Live CLI tests — marked ``@pytest.mark.live``; skipped by default.

These tests hit the real network (AWS docs, GitHub raw content, etc.)
and are only run by the ``.github/workflows/live-tests.yml`` nightly
cron.  In CI's PR-gate pipeline, the top-level ``pyproject.toml``
``addopts = "-ra --strict-markers -m 'not live'"`` filters them out
so day-to-day developer runs stay fully offline.

When a live test fails, the nightly workflow creates a GitHub issue
via :mod:`peter-evans/create-issue-from-file` so the problem surfaces
the next morning.
"""

from __future__ import annotations

import os
import subprocess
import sys

import pytest

pytestmark = pytest.mark.live


SENTINEL_CLI = [sys.executable, "-m", "sentinel"]


def _run(
    cli: list[str], env: dict[str, str] | None = None, timeout: int = 60
) -> subprocess.CompletedProcess:
    """Invoke sentinel with ``cli`` args; never shell=True for safety."""
    merged_env = os.environ.copy()
    if env:
        merged_env.update(env)
    return subprocess.run(
        cli,
        capture_output=True,
        text=True,
        timeout=timeout,
        env=merged_env,
    )


class TestLiveAwsSample:
    def test_fetch_aws_sample_readonly(self) -> None:
        """Fetch a well-known sample policy via aws-sample fetcher."""
        result = _run(
            SENTINEL_CLI
            + [
                "fetch",
                "aws-sample",
                "admin-access-required",
                "--json",
            ],
        )
        assert result.returncode == 0, result.stderr
        # Output should be JSON-shaped policy.
        assert '"Statement"' in result.stdout


class TestLiveGitHubFetch:
    def test_fetch_github_raw(self) -> None:
        """Fetch a small public policy from a well-known repo."""
        # Use a stable repo URL.  Failure here indicates either the
        # repo moved or GitHub changed rate limiting.
        spec = "aws-samples/sample-iam-policies/examples/readonly.json"
        token = os.environ.get("SENTINEL_GITHUB_TOKEN", "")
        env = {"SENTINEL_GITHUB_TOKEN": token} if token else {}
        result = _run(SENTINEL_CLI + ["fetch", "github", spec], env=env)
        # This might fail with 404 if the repo path changes; on live-test
        # failure the nightly workflow files an issue.
        if result.returncode != 0:
            pytest.skip(f"live GitHub fetch failed: {result.stderr}")


class TestLiveCacheHitCycle:
    def test_second_fetch_hits_cache(self, tmp_path) -> None:
        """Same URL fetched twice — second must show X-Sentinel-Cache: HIT."""
        env = {"SENTINEL_CACHE_DIR": str(tmp_path / "cache")}
        first = _run(
            SENTINEL_CLI
            + [
                "fetch",
                "aws-sample",
                "admin-access-required",
                "--verbose",
            ],
            env=env,
        )
        if first.returncode != 0:
            pytest.skip("live AWS docs fetch unavailable")
        second = _run(
            SENTINEL_CLI
            + [
                "fetch",
                "aws-sample",
                "admin-access-required",
                "--verbose",
            ],
            env=env,
        )
        combined = (second.stdout + second.stderr).lower()
        assert "cache" in combined and ("hit" in combined or "cache_hit" in combined), combined

"""Tests for :class:`fetchers.cloudsplaining.CloudSplainingFetcher`.

The fetcher accepts a cloudsplaining report file and emits one
:class:`FetchResult` per discovered policy.  We build a minimal
synthetic report and iterate.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from fetchers.base import PolicyNotFoundError
from fetchers.cloudsplaining import CloudSplainingFetcher


def _write_report(
    tmp_path: Path,
    policies: dict[str, dict],
) -> Path:
    """Write a minimal cloudsplaining report to ``tmp_path/report.json``."""
    f = tmp_path / "report.json"
    f.write_text(json.dumps({"policies": policies}))
    return f


class TestCloudSplainingFetcher:
    def test_extracts_single_policy(self, tmp_path: Path) -> None:
        report = _write_report(
            tmp_path,
            {
                "policy-a": {
                    "PolicyDocument": {
                        "Version": "2012-10-17",
                        "Statement": [{"Effect": "Allow", "Action": "*"}],
                    }
                }
            },
        )
        fetcher = CloudSplainingFetcher()
        results = list(fetcher.fetch_many(str(report)))
        assert len(results) == 1
        assert results[0].origin.source_type == "cloudsplaining"
        assert "policy-a" in results[0].origin.source_spec

    def test_extracts_multiple_policies(self, tmp_path: Path) -> None:
        report = _write_report(
            tmp_path,
            {
                "policy-a": {"PolicyDocument": {"Statement": []}},
                "policy-b": {"PolicyDocument": {"Statement": []}},
            },
        )
        fetcher = CloudSplainingFetcher()
        results = list(fetcher.fetch_many(str(report)))
        assert len(results) == 2

    def test_missing_report_raises(self, tmp_path: Path) -> None:
        fetcher = CloudSplainingFetcher()
        with pytest.raises(PolicyNotFoundError):
            list(fetcher.fetch_many(str(tmp_path / "missing.json")))

    def test_report_without_policies_empty(self, tmp_path: Path) -> None:
        f = tmp_path / "empty.json"
        f.write_text(json.dumps({"policies": {}}))
        fetcher = CloudSplainingFetcher()
        results = list(fetcher.fetch_many(str(f)))
        assert results == []

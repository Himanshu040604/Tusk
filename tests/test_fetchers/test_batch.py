"""Tests for :class:`fetchers.batch.BatchFetcher`.

Batch walks a directory and yields one :class:`FetchResult` per
policy file.  We exercise directory iteration, suffix filtering,
empty-directory behaviour, and the ``iter_fetch`` contract.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from sentinel.fetchers.base import PolicyNotFoundError
from sentinel.fetchers.batch import BatchFetcher


class TestBatchFetcher:
    def test_reads_each_policy_in_directory(self, tmp_path: Path) -> None:
        for i in range(3):
            (tmp_path / f"p{i}.json").write_text('{"Statement":[]}')
        fetcher = BatchFetcher()
        results = list(fetcher.iter_fetch(str(tmp_path)))
        assert len(results) == 3
        for r in results:
            assert r.origin.source_type == "local"

    def test_missing_directory_raises_policy_not_found(self, tmp_path: Path) -> None:
        fetcher = BatchFetcher()
        with pytest.raises(PolicyNotFoundError):
            list(fetcher.iter_fetch(str(tmp_path / "does-not-exist")))

    def test_directory_with_no_accepted_suffixes_raises(self, tmp_path: Path) -> None:
        (tmp_path / "not-a-policy.bin").write_text("x")
        fetcher = BatchFetcher()
        with pytest.raises(PolicyNotFoundError):
            list(fetcher.iter_fetch(str(tmp_path)))

    def test_multiple_suffixes_accepted(self, tmp_path: Path) -> None:
        (tmp_path / "p.json").write_text('{"Statement":[]}')
        (tmp_path / "p.yaml").write_text("Statement: []")
        (tmp_path / "p.yml").write_text("Statement: []")
        (tmp_path / "p.txt").write_text('{"Statement":[]}')
        (tmp_path / "ignored.bin").write_text("x")
        fetcher = BatchFetcher()
        results = list(fetcher.iter_fetch(str(tmp_path)))
        assert len(results) == 4

"""Tests for :class:`fetchers.batch.BatchFetcher`.

Batch iterates a source of specs and yields :class:`FetchResult` for
each.  We exercise the iteration + error-propagation contract only.
"""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock

import httpx
import pytest

from fetchers.base import FetcherError
from fetchers.batch import BatchFetcher


def _make_ok_response() -> httpx.Response:
    return httpx.Response(
        status_code=200, content=b"{}",
        headers={"X-Sentinel-Cache": "MISS"},
        request=httpx.Request("GET", "https://example.com/"),
    )


class TestBatchFetcher:
    def test_reads_each_line_of_batch_file(
        self, tmp_path: Path
    ) -> None:
        # Create a batch file with 3 local policies.
        for i in range(3):
            (tmp_path / f"p{i}.json").write_text('{"Statement":[]}')
        batch_file = tmp_path / "batch.txt"
        batch_file.write_text(
            "\n".join(str(tmp_path / f"p{i}.json") for i in range(3))
        )

        url_client = MagicMock()
        url_client.get.return_value = _make_ok_response()

        fetcher = BatchFetcher(
            url_client=url_client,
            settings=None,  # type: ignore[arg-type]  # unused for local specs
        )
        results = list(fetcher.fetch_many(str(batch_file)))
        assert len(results) == 3
        for r in results:
            # Each policy should have been resolved.
            assert r.origin.source_type in {"local", "url", "github"}

    def test_empty_batch_file(self, tmp_path: Path) -> None:
        f = tmp_path / "empty.txt"
        f.write_text("")
        url_client = MagicMock()
        fetcher = BatchFetcher(
            url_client=url_client, settings=None,  # type: ignore[arg-type]
        )
        results = list(fetcher.fetch_many(str(f)))
        assert results == []

    def test_comment_lines_skipped(self, tmp_path: Path) -> None:
        policy = tmp_path / "p.json"
        policy.write_text('{"Statement":[]}')
        batch = tmp_path / "b.txt"
        batch.write_text(
            f"# comment line\n{policy}\n\n# another\n"
        )
        url_client = MagicMock()
        fetcher = BatchFetcher(
            url_client=url_client, settings=None,  # type: ignore[arg-type]
        )
        results = list(fetcher.fetch_many(str(batch)))
        assert len(results) == 1

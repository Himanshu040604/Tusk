"""Tests for :class:`fetchers.local.LocalFileFetcher` and :class:`StdinFetcher`."""

from __future__ import annotations

import io
import sys
from pathlib import Path

import pytest

from fetchers.base import FetchResult, PolicyNotFoundError
from fetchers.local import LocalFileFetcher, StdinFetcher


class TestLocalFileFetcher:
    def test_reads_existing_file(self, tmp_path: Path) -> None:
        f = tmp_path / "policy.json"
        f.write_text('{"Version":"2012-10-17","Statement":[]}')
        result = LocalFileFetcher().fetch(str(f))
        assert isinstance(result, FetchResult)
        assert result.cache_status == "N/A"
        assert result.origin.source_type == "local"
        # source_spec is the absolute resolved path.
        assert Path(result.origin.source_spec).is_absolute()

    def test_missing_file_raises(self, tmp_path: Path) -> None:
        with pytest.raises(PolicyNotFoundError, match="not found"):
            LocalFileFetcher().fetch(str(tmp_path / "nope.json"))

    def test_directory_raises(self, tmp_path: Path) -> None:
        with pytest.raises(PolicyNotFoundError, match="regular file"):
            LocalFileFetcher().fetch(str(tmp_path))

    def test_body_sha256_matches(self, tmp_path: Path) -> None:
        import hashlib

        f = tmp_path / "p.json"
        content = b'{"Version":"2012-10-17","Statement":[]}'
        f.write_bytes(content)
        result = LocalFileFetcher().fetch(str(f))
        assert result.origin.sha256 == hashlib.sha256(content).hexdigest()


class TestStdinFetcher:
    def test_reads_stdin(self, monkeypatch: pytest.MonkeyPatch) -> None:
        payload = b'{"Version":"2012-10-17","Statement":[]}'
        fake_stdin = io.BytesIO(payload)
        monkeypatch.setattr(
            sys,
            "stdin",
            type("X", (), {"buffer": fake_stdin})(),
        )
        result = StdinFetcher().fetch("ignored")
        assert result.origin.source_type == "stdin"
        assert result.origin.source_spec == "<stdin>"
        assert result.body == payload

    def test_empty_stdin_raises(self, monkeypatch: pytest.MonkeyPatch) -> None:
        fake_stdin = io.BytesIO(b"   \n")
        monkeypatch.setattr(
            sys,
            "stdin",
            type("X", (), {"buffer": fake_stdin})(),
        )
        with pytest.raises(PolicyNotFoundError, match="empty"):
            StdinFetcher().fetch("ignored")

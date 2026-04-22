"""Tests for :class:`fetchers.github.GitHubFetcher`.

Covers spec-parsing for the three accepted forms, header injection when
a token is configured, and the no-token WARN path.
"""

from __future__ import annotations

from unittest.mock import MagicMock

import httpx
import pytest

from fetchers.base import InvalidSpecError
from fetchers.github import GitHubFetcher, _parse_spec
from sentinel.config import Settings


def _resp(body: bytes = b"{}", cache: str = "MISS") -> httpx.Response:
    return httpx.Response(
        status_code=200, content=body,
        headers={"X-Sentinel-Cache": cache},
        request=httpx.Request(
            "GET", "https://raw.githubusercontent.com/o/r/main/p.json"
        ),
    )


class TestParseSpec:
    def test_owner_repo_path(self) -> None:
        raw, canonical = _parse_spec("acme/policies/p.json")
        assert raw == (
            "https://raw.githubusercontent.com/acme/policies/main/p.json"
        )
        assert canonical == "acme/policies@main/p.json"

    def test_nested_path(self) -> None:
        raw, canonical = _parse_spec("acme/policies/dir/sub/p.json")
        assert "dir/sub/p.json" in raw
        assert canonical.endswith("dir/sub/p.json")

    def test_github_com_blob_url(self) -> None:
        raw, canonical = _parse_spec(
            "https://github.com/acme/policies/blob/dev/p.json"
        )
        assert raw.startswith("https://raw.githubusercontent.com/")
        assert "@dev" in canonical

    def test_raw_url_passed_through(self) -> None:
        spec = (
            "https://raw.githubusercontent.com/acme/policies/main/p.json"
        )
        raw, canonical = _parse_spec(spec)
        assert raw == spec
        assert canonical == "acme/policies@main/p.json"

    def test_invalid_spec(self) -> None:
        with pytest.raises(InvalidSpecError):
            _parse_spec("just-one-word")

    def test_unsupported_host(self) -> None:
        with pytest.raises(InvalidSpecError):
            _parse_spec("https://gitlab.com/x/y/raw/main/p.json")

    def test_malformed_raw_url(self) -> None:
        with pytest.raises(InvalidSpecError):
            _parse_spec("https://raw.githubusercontent.com/only/two")


class TestGitHubFetcher:
    def test_no_token_attaches_no_authorization(self) -> None:
        client = MagicMock()
        client.get.return_value = _resp()
        fetcher = GitHubFetcher(client=client, settings=Settings())
        fetcher.fetch("acme/policies/p.json")
        _args, kwargs = client.get.call_args
        assert "Authorization" not in kwargs.get("headers", {})

    def test_token_attaches_authorization(self) -> None:
        client = MagicMock()
        client.get.return_value = _resp()
        settings = Settings(github_token="ghp_faketoken")
        fetcher = GitHubFetcher(client=client, settings=settings)
        fetcher.fetch("acme/policies/p.json")
        _args, kwargs = client.get.call_args
        assert (
            kwargs.get("headers", {}).get("Authorization")
            == "token ghp_faketoken"
        )

    def test_no_token_emits_warn_once(self) -> None:
        client = MagicMock()
        client.get.return_value = _resp()
        fetcher = GitHubFetcher(client=client, settings=Settings())

        with pytest.MonkeyPatch().context() as m:
            warn_spy = MagicMock()
            m.setattr(fetcher._log, "warning", warn_spy)
            fetcher.fetch("acme/policies/p.json")
            fetcher.fetch("acme/policies/p2.json")
            # Only the first call warned.
            assert warn_spy.call_count == 1

    def test_source_tag_is_github(self) -> None:
        client = MagicMock()
        client.get.return_value = _resp()
        fetcher = GitHubFetcher(client=client, settings=Settings())
        fetcher.fetch("acme/policies/p.json")
        _args, kwargs = client.get.call_args
        assert kwargs.get("source") == "github"

"""Tests for :class:`fetchers.url.URLFetcher`.

Uses a mocked :class:`SentinelHTTPClient` so no real network is
touched.  VCR cassettes for true end-to-end coverage are recorded
during the M21 nightly live-tests run.
"""

from __future__ import annotations

from unittest.mock import MagicMock

import httpx
import pytest

from sentinel.fetchers.url import URLFetcher
from sentinel.fetchers.base import FetchResult


def _make_response(
    body: bytes = b'{"ok":true}',
    cache: str = "MISS",
) -> httpx.Response:
    return httpx.Response(
        status_code=200,
        content=body,
        headers={"X-Sentinel-Cache": cache, "Content-Type": "application/json"},
        request=httpx.Request("GET", "https://example.com/p.json"),
    )


class TestURLFetcher:
    def test_returns_fetch_result(self) -> None:
        client = MagicMock()
        client.get.return_value = _make_response()
        result = URLFetcher(client).fetch("https://example.com/p.json")
        assert isinstance(result, FetchResult)
        assert result.origin.source_type == "url"
        assert result.origin.source_spec == "https://example.com/p.json"

    def test_cache_hit_propagates_to_origin(self) -> None:
        client = MagicMock()
        client.get.return_value = _make_response(cache="HIT")
        result = URLFetcher(client).fetch("https://example.com/p.json")
        assert result.cache_status == "HIT"
        assert result.origin.cache_status == "HIT"

    def test_source_is_user_url(self) -> None:
        client = MagicMock()
        client.get.return_value = _make_response()
        URLFetcher(client).fetch("https://example.com/p.json")
        _args, kwargs = client.get.call_args
        assert kwargs.get("source") == "user_url"

    def test_spec_is_preserved_verbatim(self) -> None:
        """Even redirected final URL shouldn't overwrite origin.source_spec."""
        client = MagicMock()
        client.get.return_value = _make_response()
        spec = "https://example.com/PATH?x=1"
        result = URLFetcher(client).fetch(spec)
        assert result.origin.source_spec == spec

    @pytest.mark.vcr
    @pytest.mark.skip(reason="VCR cassette recorded during M21 nightly live-tests run")
    def test_live_recorded_fetch(self) -> None:
        """Placeholder — populated once live-tests workflow records cassette."""

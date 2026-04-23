"""Tests for :class:`fetchers.cloudsplaining.CloudSplainingFetcher`.

The fetcher composes a ``GitHubFetcher`` to retrieve policy examples from
``salesforce/cloudsplaining/examples/policies/`` and rewrites the origin
badge to read ``cloudsplaining``.
"""

from __future__ import annotations

from unittest.mock import MagicMock

import httpx

from sentinel.fetchers.cloudsplaining import CloudSplainingFetcher
from sentinel.config import Settings


def _resp(body: bytes = b"{}", cache: str = "MISS") -> httpx.Response:
    return httpx.Response(
        status_code=200,
        content=body,
        headers={"X-Sentinel-Cache": cache},
        request=httpx.Request(
            "GET",
            "https://raw.githubusercontent.com/salesforce/cloudsplaining/main/examples/policies/p.json",
        ),
    )


class TestCloudSplainingFetcher:
    def test_bare_filename_routes_to_examples_policies(self) -> None:
        client = MagicMock()
        client.get.return_value = _resp()
        fetcher = CloudSplainingFetcher(client=client, settings=Settings())
        fetcher.fetch("iam-privesc.json")
        # Verify the underlying GitHub call targeted examples/policies/.
        args, _kwargs = client.get.call_args
        assert "examples/policies/iam-privesc.json" in args[0]

    def test_origin_relabelled_to_cloudsplaining(self) -> None:
        client = MagicMock()
        client.get.return_value = _resp()
        fetcher = CloudSplainingFetcher(client=client, settings=Settings())
        result = fetcher.fetch("iam-privesc.json")
        assert result.origin.source_type == "cloudsplaining"
        assert result.origin.source_spec == "iam-privesc.json"

    def test_prejoined_subpath_not_duplicated(self) -> None:
        client = MagicMock()
        client.get.return_value = _resp()
        fetcher = CloudSplainingFetcher(client=client, settings=Settings())
        fetcher.fetch("examples/policies/nested/p.json")
        args, _kwargs = client.get.call_args
        # Should not get "examples/policies/examples/policies/..."
        assert args[0].count("examples/policies") == 1

    def test_leading_slash_stripped(self) -> None:
        client = MagicMock()
        client.get.return_value = _resp()
        fetcher = CloudSplainingFetcher(client=client, settings=Settings())
        fetcher.fetch("/iam-privesc.json")
        args, _kwargs = client.get.call_args
        # URL shouldn't have a double slash after the branch.
        assert "//iam-privesc.json" not in args[0]

"""Tests for :class:`fetchers.aws_sample.AWSSampleFetcher`.

The fetcher extracts a JSON policy from AWS docs HTML using selectolax.
We mock :class:`SentinelHTTPClient` and feed it pre-canned HTML.
"""

from __future__ import annotations

from unittest.mock import MagicMock

import httpx
import pytest

from fetchers.aws_sample import (
    AWSSampleFetcher,
    _extract_first_policy_block,
    _looks_like_policy_json,
)
from fetchers.base import PolicyNotFoundError


_VALID_POLICY = '{"Version":"2012-10-17","Statement":[{"Effect":"Allow"}]}'
_SHELL_SNIPPET = "aws s3 ls --region us-east-1"


def _html(payloads: list[str], tag: str = "pre") -> str:
    inner = "\n".join(f"<{tag}>{p}</{tag}>" for p in payloads)
    return f"<html><body>{inner}</body></html>"


def _resp(html: str) -> httpx.Response:
    return httpx.Response(
        status_code=200, content=html.encode("utf-8"),
        headers={"X-Sentinel-Cache": "MISS"},
        request=httpx.Request("GET", "https://docs.aws.amazon.com/x"),
    )


class TestLooksLikePolicyJson:
    def test_accepts_full_policy(self) -> None:
        assert _looks_like_policy_json(_VALID_POLICY)

    def test_rejects_shell_snippet(self) -> None:
        assert not _looks_like_policy_json(_SHELL_SNIPPET)

    def test_rejects_empty(self) -> None:
        assert not _looks_like_policy_json("")

    def test_rejects_non_policy_json(self) -> None:
        assert not _looks_like_policy_json('{"foo":"bar"}')


class TestExtractFirstPolicyBlock:
    def test_picks_first_policy_among_shell_blocks(self) -> None:
        html = _html([_SHELL_SNIPPET, _VALID_POLICY, _SHELL_SNIPPET])
        out = _extract_first_policy_block(html)
        assert "Statement" in out

    def test_checks_code_tag_too(self) -> None:
        html = _html([_VALID_POLICY], tag="code")
        assert "Statement" in _extract_first_policy_block(html)

    def test_raises_when_no_policy(self) -> None:
        html = _html([_SHELL_SNIPPET, "not json at all"])
        with pytest.raises(PolicyNotFoundError):
            _extract_first_policy_block(html)


class TestAWSSampleFetcher:
    def test_fetch_round_trip(self) -> None:
        client = MagicMock()
        client.get.return_value = _resp(_html([_VALID_POLICY]))
        result = AWSSampleFetcher(client).fetch("SampleName")
        assert result.origin.source_type == "aws-sample"
        assert result.origin.source_spec == "SampleName"
        # Body is the extracted policy JSON, NOT the HTML wrapper.
        assert b"Statement" in result.body
        assert b"<html>" not in result.body

    def test_source_is_aws_docs(self) -> None:
        client = MagicMock()
        client.get.return_value = _resp(_html([_VALID_POLICY]))
        AWSSampleFetcher(client).fetch("SampleName")
        _args, kwargs = client.get.call_args
        assert kwargs.get("source") == "aws_docs"

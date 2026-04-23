"""AWS policy sample fetcher — parses HTML from docs pages.

Spec: a sample policy name, e.g. ``"AmazonS3ReadOnlyAccess"``.  The
fetcher constructs the docs URL, fetches via :class:`SentinelHTTPClient`
with ``source="aws_docs"`` (7 d TTL per § 5.5), then extracts the
first JSON-shaped ``<pre>`` or ``<code>`` block using :mod:`selectolax`.

H26 note: the selectolax HTML parse budget is a Phase 6 benchmark
concern — not this phase's problem.

Raises :class:`PolicyNotFoundError` when no JSON block is found.
"""

from __future__ import annotations

import json
from typing import TYPE_CHECKING

from selectolax.parser import HTMLParser

from .base import Fetcher, FetchResult, PolicyNotFoundError
from ._http_helpers import build_fetch_result

if TYPE_CHECKING:  # pragma: no cover
    from sentinel.net.client import SentinelHTTPClient


# Sample page template.  Pinned in Amendment 4 — AWS moved the
# reference-policies subtree twice in 2024; this layout is current
# as of April 2026 and is allow-listed in defaults.toml.
_SAMPLE_URL_TEMPLATE = (
    "https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_examples_{name}.html"
)


def _looks_like_policy_json(text: str) -> bool:
    """Heuristic: parse and check for an IAM policy ``Version`` key.

    Works even when the page ships multiple ``<pre>`` blocks of which
    only one is an actual policy (the others being shell snippets).
    """
    try:
        parsed = json.loads(text)
    except (ValueError, TypeError):
        return False
    return isinstance(parsed, dict) and "Statement" in parsed


def _extract_first_policy_block(html: str) -> str:
    """Walk ``<pre>`` / ``<code>`` blocks, return first JSON-shaped one."""
    tree = HTMLParser(html)
    for tag in ("pre", "code"):
        for node in tree.css(tag):
            candidate = (node.text() or "").strip()
            if candidate and _looks_like_policy_json(candidate):
                return candidate
    raise PolicyNotFoundError("no IAM-policy-shaped JSON block found in AWS sample page")


class AWSSampleFetcher:
    """Fetches a canonical IAM policy example from the AWS docs."""

    def __init__(self, client: "SentinelHTTPClient") -> None:
        self._client = client

    def fetch(self, spec: str) -> FetchResult:
        url = _SAMPLE_URL_TEMPLATE.format(name=spec)
        response = self._client.get(url, source="aws_docs")
        html = response.text
        policy_json = _extract_first_policy_block(html)
        # Keep the fetched-bytes = the extracted JSON, NOT the raw HTML.
        # SHA-256 and body_bytes downstream should reflect the policy
        # we act on, not the page wrapper.
        body = policy_json.encode("utf-8")
        result = build_fetch_result(
            response=response,
            source_type="aws-sample",
            source_spec=spec,
        )
        # Rebuild with the extracted body + a recomputed SHA-256.
        import hashlib
        from dataclasses import replace
        from sentinel.models import PolicyOrigin

        new_origin = PolicyOrigin(
            source_type="aws-sample",
            source_spec=spec,
            sha256=hashlib.sha256(body).hexdigest(),
            fetched_at=result.origin.fetched_at,
            cache_status=result.cache_status,
        )
        return replace(result, body=body, origin=new_origin)


__all__ = ["AWSSampleFetcher", "Fetcher"]

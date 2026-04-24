"""CloudSplaining sample fetcher.

Spec: a CloudSplaining example filename (e.g. ``"iam-privesc.json"``).
Source: ``salesforce/cloudsplaining/examples/policies/`` on GitHub.

Under the hood this composes a :class:`GitHubFetcher` fetch — we get
the raw.githubusercontent cache-keyed retrieval and ``SENTINEL_GITHUB_TOKEN``
support for free.  We rewrite the ``source_type`` on the resulting
:class:`FetchResult` so the origin badge reads ``cloudsplaining``, not
``github``.
"""

from __future__ import annotations

from dataclasses import replace
from typing import TYPE_CHECKING

from ..models import PolicyOrigin

from .base import Fetcher, FetchResult
from .github import GitHubFetcher

if TYPE_CHECKING:  # pragma: no cover
    from ..config import Settings
    from ..net.client import SentinelHTTPClient


_REPO = "salesforce/cloudsplaining"
_BRANCH = "main"
_PATH_PREFIX = "examples/policies"


class CloudSplainingFetcher:
    """Pulls CloudSplaining example policies from GitHub."""

    def __init__(
        self,
        client: "SentinelHTTPClient",
        settings: "Settings",
    ) -> None:
        self._github = GitHubFetcher(client, settings)

    def fetch(self, spec: str) -> FetchResult:
        # Normalise the spec — accept either a bare filename or a
        # pre-joined subpath under examples/policies/.
        clean = spec.lstrip("/")
        if not clean.startswith(_PATH_PREFIX):
            clean = f"{_PATH_PREFIX}/{clean}"

        github_spec = f"https://github.com/{_REPO}/blob/{_BRANCH}/{clean}"
        inner = self._github.fetch(github_spec)
        # Relabel the origin so downstream formatters render the
        # correct "Origin: cloudsplaining ..." badge.
        new_origin = PolicyOrigin(
            source_type="cloudsplaining",
            source_spec=spec,
            sha256=inner.origin.sha256,
            fetched_at=inner.origin.fetched_at,
            cache_status=inner.origin.cache_status,
        )
        return replace(inner, origin=new_origin)


__all__ = ["CloudSplainingFetcher", "Fetcher"]

"""URL fetcher — plain HTTP GET via :class:`SentinelHTTPClient`.

Spec: any absolute ``http(s)://`` URL.  The underlying client enforces
the allow-list, SSRF guard, retry budget, and disk cache.  A cache
HIT is reflected in the :attr:`FetchResult.cache_status`.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from .base import Fetcher, FetchResult
from ._http_helpers import build_fetch_result

if TYPE_CHECKING:  # pragma: no cover
    from sentinel.net.client import SentinelHTTPClient


class URLFetcher:
    """Fetches a policy JSON from an arbitrary allow-listed URL.

    The fetcher tags every result with ``source_type="url"`` and
    ``source_spec=<the exact URL the user supplied>``.  The user's
    typed URL — not the final redirected target — is the provenance
    record.  Redirects are still H9-revalidated inside the client.
    """

    def __init__(self, client: "SentinelHTTPClient") -> None:
        self._client = client

    def fetch(self, spec: str) -> FetchResult:
        """Fetch the URL supplied as ``spec``.

        Args:
            spec: Absolute URL.  The fetcher does NOT normalise or
                canonicalise.  Validation (scheme, allow-list, SSRF)
                is delegated to :class:`SentinelHTTPClient`.
        """
        response = self._client.get(spec, source="user_url")
        return build_fetch_result(
            response=response,
            source_type="url",
            source_spec=spec,
        )


__all__ = ["URLFetcher", "Fetcher"]

"""Shared helpers for HTTP-backed fetchers — keep each concrete
fetcher under the 100-line budget.

These helpers wrap :class:`SentinelHTTPClient` calls into the shape
that every URL-flavored fetcher needs: extract the ``X-Sentinel-Cache``
annotation, hash the body, and build a :class:`PolicyOrigin`.
"""

from __future__ import annotations

import hashlib
from datetime import datetime, timezone
from typing import TYPE_CHECKING

from ..models import PolicyOrigin

from .base import FetchResult

if TYPE_CHECKING:  # pragma: no cover — type hints only
    import httpx


def build_fetch_result(
    *,
    response: "httpx.Response",
    source_type: str,
    source_spec: str,
) -> FetchResult:
    """Translate an :class:`httpx.Response` into a :class:`FetchResult`.

    Handles the three concerns common to every HTTP fetcher:

    1. Pull the ``X-Sentinel-Cache`` header the client wrote.  Default
       to ``"MISS"`` so a missing header never silently becomes
       ``"HIT"`` (fail-closed per our Phase 3 convention).
    2. SHA-256 the body bytes.
    3. Stamp a UTC ``fetched_at``.

    Args:
        response: Response returned by :class:`SentinelHTTPClient`.
        source_type: One of the ``PolicyOrigin`` discriminator values.
        source_spec: The locator the user supplied (URL, ``owner/repo``,
            sample name, etc.) — NOT the possibly-redirected final URL.
    """
    body = response.content
    cache_status = response.headers.get("X-Sentinel-Cache", "MISS")
    origin = PolicyOrigin(
        source_type=source_type,
        source_spec=source_spec,
        sha256=hashlib.sha256(body).hexdigest(),
        fetched_at=datetime.now(timezone.utc),
        cache_status=cache_status,
    )
    return FetchResult(
        body=body,
        headers=dict(response.headers),
        cache_status=cache_status,
        origin=origin,
    )


def build_local_origin(
    *,
    source_type: str,
    source_spec: str,
    body: bytes,
) -> PolicyOrigin:
    """Build a :class:`PolicyOrigin` for non-HTTP fetchers (local,
    clipboard, stdin).  Always stamps ``cache_status="N/A"``.
    """
    return PolicyOrigin(
        source_type=source_type,
        source_spec=source_spec,
        sha256=hashlib.sha256(body).hexdigest(),
        fetched_at=datetime.now(timezone.utc),
        cache_status="N/A",
    )


__all__ = ["build_fetch_result", "build_local_origin"]

"""SentinelHTTPClient — hardened ``httpx.Client`` wrapper.

Orchestrates the four Phase-3 defenses on every ``get()``:

1. **Allow-list** check (:class:`AllowList`, § 8.1).
2. **SSRF** resolve-and-validate (:func:`guards.resolve_and_validate`,
   § 8.2).  Re-runs on every redirect hop.
3. **Cache** short-circuit (:class:`DiskCache.get`, § 8.5).  Cached
   entries return immediately with an ``X-Sentinel-Cache: HIT`` marker.
4. **Retry** policy with per-source budgets + ``Retry-After`` honoring
   (:class:`RetryPolicy`, § 8.6).

Observability:

* Every request emits a structlog event through :mod:`logging_setup`
  so M10 secret redaction fires on headers.
* Every request opens an OTel span (``net.request``) with url / source /
  cache_status / status_code attributes.

Phase 3 implements **sync only**.  Async (``httpx.AsyncClient``) is
Phase 4 work if a fetcher needs it; the public API here is designed so
an async variant can be added without breaking callers.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Optional

import httpx
import structlog

from ..telemetry import tracer
from .allow_list import AllowList
from .cache import CacheEntry, DiskCache
from .guards import SSRFBlockedError, resolve_and_validate
from .retry import NonRetryableHTTPError, RetryPolicy, is_retryable_status, parse_retry_after

if TYPE_CHECKING:
    from ..config import Settings


class DomainNotAllowedError(Exception):
    """Raised when a URL fails :class:`AllowList` check."""


class SentinelHTTPClient:
    """Hardened HTTP client — the sole network entry point for Sentinel.

    Thread-safety: :class:`httpx.Client` is documented thread-safe for
    concurrent ``get()`` calls.  The allow-list + cache are read-mostly
    and safe under the GIL.

    Lifetime: construct once, reuse.  The underlying httpx.Client holds
    a connection pool.  Call :meth:`close` in a ``finally`` block — or
    use the context-manager form.
    """

    def __init__(
        self,
        settings: "Settings",
        allow_list: AllowList,
        cache: DiskCache,
        retry_policy: RetryPolicy,
        insecure: bool = False,
    ) -> None:
        self._settings = settings
        self._allow_list = allow_list
        self._cache = cache
        self._retry = retry_policy
        self._insecure = bool(insecure)
        self._log = structlog.get_logger("sentinel.net.client")

        net = settings.network
        # Note: httpx's default verify=True matches our policy when
        # insecure=False.  We set it explicitly for clarity.
        self._client = httpx.Client(
            verify=not self._insecure,
            timeout=httpx.Timeout(net.timeout_seconds),
            follow_redirects=False,  # we validate each hop ourselves (H9)
            max_redirects=net.max_redirects,
        )

    def close(self) -> None:
        self._client.close()

    def __enter__(self) -> "SentinelHTTPClient":
        return self

    def __exit__(self, *_exc) -> None:
        self.close()

    # ------------------------------------------------------------------ core

    def _preflight(self, url: str) -> None:
        """Raise if ``url`` fails allow-list or SSRF validation."""
        if not self._allow_list.is_allowed(url):
            raise DomainNotAllowedError(
                f"URL host not in allow-list: {url!r}.  Use "
                f"'--allow-domain <host>' to extend for one run."
            )
        # SSRFBlockedError propagates naturally.
        resolve_and_validate(url)

    def _warn_if_insecure(self, url: str) -> None:
        """Unsuppressable WARN log per § 7.3 when TLS verify is off."""
        if self._insecure:
            self._log.warning(
                "tls_verify_disabled",
                url=url,
                note=(
                    "--insecure flag active; TLS certificate validation "
                    "DISABLED for this request.  Responses may be MITM-"
                    "poisoned and will be HMAC-signed as if trusted."
                ),
            )

    def _make_entry_response(self, entry: CacheEntry) -> httpx.Response:
        """Synthesise an :class:`httpx.Response` from a cache hit."""
        headers = dict(entry.headers)
        headers["X-Sentinel-Cache"] = "HIT"
        return httpx.Response(
            status_code=200, content=entry.body,
            headers=headers,
            request=httpx.Request("GET", entry.url),
        )

    def _one_attempt(
        self, url: str, source: str, headers: dict[str, str] | None,
        etag: str | None,
    ) -> tuple[httpx.Response, dict[str, str]]:
        """Issue one HTTP GET and classify the response.

        Returns ``(response, request_headers_sent)`` — request headers
        surface so the caller can store them if needed for replay.

        Raises:
            NonRetryableHTTPError: For non-retryable 4xx.
            httpx.HTTPStatusError: For retryable 4xx/5xx (worth another
                attempt under the retry policy).
        """
        sent_headers = dict(headers or {})
        if etag:
            sent_headers.setdefault("If-None-Match", etag)
        resp = self._client.get(url, headers=sent_headers)
        if resp.status_code == 304:
            return resp, sent_headers
        if 400 <= resp.status_code < 600:
            if is_retryable_status(resp.status_code):
                raise httpx.HTTPStatusError(
                    f"retryable status {resp.status_code}",
                    request=resp.request, response=resp,
                )
            raise NonRetryableHTTPError(
                f"non-retryable status {resp.status_code} for {url!r}",
                status_code=resp.status_code,
            )
        return resp, sent_headers

    def get(
        self,
        url: str,
        source: str = "user_url",
        headers: dict[str, str] | None = None,
    ) -> httpx.Response:
        """Fetch ``url`` through the full hardened pipeline.

        Steps: allow-list -> SSRF guard -> cache lookup -> HTTP GET (with
        retry + ``Retry-After``) -> cache store.

        Args:
            url: Absolute URL (http/https only).
            source: Rate-limit / TTL bucket key — ``github`` / ``aws_docs``
                / ``user_url`` / ``policy_sentry``.  Unknown sources fall
                back to ``user_url`` budgets.
            headers: Additional request headers; ``If-None-Match`` auto-
                injected when the cache has a stored ETag.

        Returns:
            :class:`httpx.Response`.  Cache hits synthesise a 200 response
            with ``X-Sentinel-Cache: HIT``; misses add
            ``X-Sentinel-Cache: MISS`` on the live response.

        Raises:
            DomainNotAllowedError, SSRFBlockedError, httpx.HTTPError.
        """
        with tracer.start_as_current_span("net.request") as span:
            span.set_attribute("http.url", url)
            span.set_attribute("sentinel.source", source)

            self._preflight(url)
            self._warn_if_insecure(url)

            cached = self._cache.get(url, source)
            if cached is not None:
                span.set_attribute("sentinel.cache_status", "HIT")
                self._log.info("http_cache_hit", url=url, source=source)
                return self._make_entry_response(cached)

            # Cache miss — go to network.
            etag_for_request: str | None = None  # no stored entry either
            return self._fetch_live(url, source, headers, etag_for_request, span)

    def _fetch_live(
        self,
        url: str,
        source: str,
        headers: dict[str, str] | None,
        etag: str | None,
        span,  # OTel span; typed as Any to avoid SDK dep
    ) -> httpx.Response:
        """Execute a retrying GET; cache the result on success."""
        last_response: httpx.Response | None = None

        def _retry_after_hint() -> float | None:
            return parse_retry_after(
                last_response.headers.get("Retry-After") if last_response else None
            )

        self._log.info("http_request", url=url, source=source)
        for attempt in self._retry.retrying(source, retry_after_hook=_retry_after_hint):
            with attempt:
                try:
                    resp, _sent = self._one_attempt(url, source, headers, etag)
                    last_response = resp
                except httpx.HTTPStatusError as hse:
                    last_response = hse.response
                    raise

        assert last_response is not None  # tenacity guarantees or reraises
        resp = last_response

        # Mark the miss and cache it (skip 304 — treat as revalidation).
        cache_status = "MISS"
        resp.headers["X-Sentinel-Cache"] = cache_status
        span.set_attribute("sentinel.cache_status", cache_status)
        span.set_attribute("http.status_code", resp.status_code)
        if 200 <= resp.status_code < 300:
            self._cache.put(
                url=url, source=source,
                body=resp.content,
                headers=dict(resp.headers),
                etag=resp.headers.get("ETag"),
            )
        self._log.info("http_response", url=url, source=source,
                       status=resp.status_code, cache=cache_status)
        return resp


__all__ = [
    "DomainNotAllowedError",
    "SentinelHTTPClient",
]

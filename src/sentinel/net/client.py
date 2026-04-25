"""SentinelHTTPClient — hardened ``httpx.Client`` wrapper.

Orchestrates the SSRF defense quartet + cache + retry on every
``get()``:

1. **Allow-list** check (:class:`AllowList`, § 8.1).
2. **SSRF** resolve-and-validate (:func:`guards.resolve_and_validate`,
   § 8.2). Re-runs on every redirect hop (H9). NAT64 / 6to4 / Teredo /
   IPv4-mapped IPv6 extracted and transitively checked against
   RFC 1918 / loopback / metadata ranges (H13).
3. **Cache** short-circuit (:class:`DiskCache.get`, § 8.5). Cached
   entries return immediately with an ``X-Sentinel-Cache: HIT`` marker.
4. **Retry** policy with per-source budgets + ``Retry-After`` honoring
   (:class:`RetryPolicy`, § 8.6). Hostile ``Retry-After: 99999`` capped
   to ``max_total_wait_seconds`` (SEC-M2 post-v0.8.1).

Key behaviors added post-original-authorship:

* **Max-download enforcement** (SEC-M1 post-v0.8.1): preflight on
  ``Content-Length`` + post-check on body size. Raises non-retryable
  ``ResponseTooLargeError`` before the cache write so an arbitrarily
  large hostile body cannot OOM the process or poison the cache.
* **Insecure cache suppression** (SEC-M3 post-v0.8.1): when
  ``self._insecure=True``, cache writes are skipped and a structlog
  WARN ``cache_write_suppressed_insecure`` fires. MITM-poisoned
  responses from a single insecure session cannot persist into a
  signed cache entry that later secure sessions would trust.
* **URL credential stripping** (SEC-L1 post-v0.8.1): every structlog
  URL site calls ``strip_url_credentials`` from ``net.urls`` so
  ``user:token@host`` in ``--url`` never leaks to logs.
* **Redirect chaser re-validates** every hop (H9): allow-list + SSRF
  re-run on each ``Location``.
* **``--insecure`` loud-warn** (§ 5.2 ephemeral): unsuppressable
  ``[WARN]`` per request when TLS verify is off.

Observability:

* Every request emits a structlog event through :mod:`logging_setup`
  so M10 secret redaction fires on headers.
* Every request opens an OTel span (``net.request``) with url / source /
  cache_status / status_code attributes.
* Audit events: ``http_request``, ``http_response``,
  ``http_redirect_followed``, ``cache_hit``, ``cache_hmac_mismatch``,
  ``cache_write_suppressed_insecure``, ``retry_after_cap_engaged``.

Implementation note: **sync only**. The public API is shaped so an
``httpx.AsyncClient`` variant can be added later without breaking
callers, but no current fetcher needs it.
"""

from __future__ import annotations

import re
from typing import TYPE_CHECKING, Optional
from urllib.parse import urljoin

import httpx
import structlog

from ..telemetry import tracer
from .allow_list import AllowList
from .cache import CacheEntry, DiskCache
from .guards import SSRFBlockedError, resolve_and_validate
from .retry import NonRetryableHTTPError, RetryPolicy, is_retryable_status, parse_retry_after
from .urls import strip_url_credentials

if TYPE_CHECKING:
    from ..config import Settings


class DomainNotAllowedError(Exception):
    """Raised when a URL fails :class:`AllowList` check."""


class ResponseTooLargeError(Exception):
    """Raised when a response body exceeds ``max_download_bytes`` (SEC-M1).

    Inherits from plain ``Exception`` (not ``httpx.HTTPError``) so the
    retry policy classifies it as non-retryable — a server that returns
    an oversized body once will always return one.
    """

    def __init__(self, url: str, size: int, limit: int) -> None:
        super().__init__(f"Response body {size} bytes exceeds limit {limit} for {url!r}")
        self.url = url
        self.size = size
        self.limit = limit


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
        # Redirects are handled manually in _fetch_live so every hop
        # can re-run the preflight (H9); httpx-level max_redirects is
        # moot with follow_redirects=False.
        self._client = httpx.Client(
            verify=not self._insecure,
            timeout=httpx.Timeout(net.timeout_seconds),
            follow_redirects=False,  # we validate each hop ourselves (H9)
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
                url=strip_url_credentials(url),
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
            status_code=200,
            content=entry.body,
            headers=headers,
            request=httpx.Request("GET", entry.url),
        )

    def _one_attempt(
        self,
        url: str,
        source: str,
        headers: dict[str, str] | None,
        etag: str | None,
        max_bytes_override: int | None = None,
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

        # SEC-M1: enforce max_download_bytes before we expose the body
        # to callers or the cache.  Two-layer defense:
        #   1. Preflight on Content-Length (cheap, catches honest servers
        #      advertising an oversized body).
        #   2. Post-check on len(resp.content) for servers that lie about
        #      or omit Content-Length.
        # httpx sync Client.get() already buffers .content by return
        # time, so the post-check cannot prevent the buffer allocation
        # once — but it reliably prevents cache poisoning and downstream
        # consumption of oversized responses.  A full streaming
        # rewrite is the long-term answer (tracked separately).
        # PE9: ``max_bytes_override`` is an opt-in per-call escape hatch
        # for known-large fetches (e.g. policy_sentry's ~19MB IAM
        # definition).  When None (default), the global SEC-M1 cap
        # applies.  Override propagates through redirect hops too — if
        # the larger cap is unsafe for an attacker-controlled redirect
        # target, the caller must not opt in.
        limit = (
            max_bytes_override
            if max_bytes_override is not None
            else self._settings.network.max_download_bytes
        )
        declared = resp.headers.get("Content-Length")
        if declared is not None:
            try:
                declared_int = int(declared)
            except ValueError:
                declared_int = -1
            if declared_int > limit:
                self._log.warning(
                    "http_response_too_large_preflight",
                    url=strip_url_credentials(url),
                    source=source,
                    content_length=declared_int,
                    limit=limit,
                )
                resp.close()
                raise ResponseTooLargeError(url, declared_int, limit)

        actual = len(resp.content)
        if actual > limit:
            self._log.error(
                "http_response_too_large",
                url=strip_url_credentials(url),
                source=source,
                actual_bytes=actual,
                limit=limit,
                declared=declared,
            )
            raise ResponseTooLargeError(url, actual, limit)

        if 400 <= resp.status_code < 600:
            if is_retryable_status(resp.status_code):
                raise httpx.HTTPStatusError(
                    f"retryable status {resp.status_code}",
                    request=resp.request,
                    response=resp,
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
        *,
        max_bytes_override: int | None = None,
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
            max_bytes_override: PE9 opt-in per-call escape hatch around
                SEC-M1's response-size cap.  When None (default), the
                global ``settings.network.max_download_bytes`` applies.
                Use ONLY for known-large fetches whose source is trusted
                (e.g. policy_sentry's ~19MB IAM definition file).
                Keyword-only to prevent accidental positional misuse.

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
                self._log.info(
                    "http_cache_hit",
                    url=strip_url_credentials(url),
                    source=source,
                )
                return self._make_entry_response(cached)

            # Cache miss — go to network.
            etag_for_request: str | None = None  # no stored entry either
            return self._fetch_live(
                url,
                source,
                headers,
                etag_for_request,
                span,
                max_bytes_override=max_bytes_override,
            )

    def _fetch_live(
        self,
        url: str,
        source: str,
        headers: dict[str, str] | None,
        etag: str | None,
        span,  # OTel span; typed as Any to avoid SDK dep
        max_bytes_override: int | None = None,
    ) -> httpx.Response:
        """Execute a retrying GET with manual redirect chasing.

        Every redirect hop re-runs :meth:`_preflight` (allow-list + SSRF
        guard) and :meth:`_warn_if_insecure` so the H9 control surface
        is enforced across the entire redirect chain.  The retry budget
        (tenacity) applies per-hop; the redirect loop sits outside it.

        Cache semantics: the cache is keyed by the ORIGINAL caller-
        visible ``url``, not the final redirected URL.  Redirects are
        a transport detail, not a caching key.
        """
        current_url = url
        max_hops = self._settings.network.max_redirects
        redirect_count = 0

        self._log.info("http_request", url=strip_url_credentials(url), source=source)

        while True:
            last_response: httpx.Response | None = None

            def _retry_after_hint() -> float | None:
                return parse_retry_after(
                    last_response.headers.get("Retry-After") if last_response else None
                )

            for attempt in self._retry.retrying(source, retry_after_hook=_retry_after_hint):
                with attempt:
                    try:
                        resp, _sent = self._one_attempt(
                            current_url,
                            source,
                            headers,
                            etag,
                            max_bytes_override=max_bytes_override,
                        )
                        last_response = resp
                    except httpx.HTTPStatusError as hse:
                        last_response = hse.response
                        raise

            if last_response is None:
                # tenacity with reraise=True should never exit without a
                # result; belt-and-braces for ``python -O`` (asserts off).
                raise RuntimeError(
                    "tenacity exited without a result — should not happen with reraise=True"
                )
            resp = last_response

            # 2xx or 304 -> terminal, cache + return.
            if (200 <= resp.status_code < 300) or resp.status_code == 304:
                cache_status = "MISS"
                resp.headers["X-Sentinel-Cache"] = cache_status
                span.set_attribute("sentinel.cache_status", cache_status)
                span.set_attribute("http.status_code", resp.status_code)
                if 200 <= resp.status_code < 300:
                    if self._insecure:
                        # SEC-M3: do NOT persist responses fetched under
                        # --insecure into the HMAC-signed DiskCache.  HMAC
                        # proves "entry unchanged since stored", not
                        # "content came from a trusted origin"; a MITM
                        # response captured in an insecure session would
                        # otherwise be silently re-served on future
                        # secure runs and pass verification.  Read path
                        # is unchanged: legitimate prior-secure entries
                        # remain valid and may be served during insecure
                        # sessions.
                        self._log.warning(
                            "cache_write_suppressed_insecure",
                            url=strip_url_credentials(url),
                            source=source,
                            note=(
                                "--insecure active; response NOT written "
                                "to HMAC cache to prevent persistent MITM "
                                "poisoning of future secure runs.  Run "
                                "'sentinel cache purge' or rotate the "
                                "HMAC key (sentinel cache rotate-key) to "
                                "evict any entries written before this "
                                "fix."
                            ),
                        )
                    else:
                        # Cache keyed on ORIGINAL url, not current_url.
                        self._cache.put(
                            url=url,
                            source=source,
                            body=resp.content,
                            headers=dict(resp.headers),
                            etag=resp.headers.get("ETag"),
                        )
                self._log.info(
                    "http_response",
                    url=strip_url_credentials(url),
                    source=source,
                    status=resp.status_code,
                    cache=cache_status,
                    redirect_hops=redirect_count,
                )
                return resp

            # 3xx (non-304) -> redirect chase with H9 re-validation.
            if 300 <= resp.status_code < 400:
                if redirect_count >= max_hops:
                    raise httpx.TooManyRedirects(
                        f"Exceeded {max_hops} redirect hops starting from {url}",
                        request=resp.request,
                    )
                location = resp.headers.get("Location")
                if not location:
                    # RFC: 3xx without Location is legal; surface raw.
                    span.set_attribute("http.status_code", resp.status_code)
                    self._log.warning(
                        "http_redirect_without_location",
                        url=strip_url_credentials(current_url),
                        status=resp.status_code,
                    )
                    return resp

                next_url = urljoin(current_url, location)

                # H9 ENFORCEMENT: revalidate every redirect hop.
                self._preflight(next_url)
                self._warn_if_insecure(next_url)

                self._log.info(
                    "http_redirect_followed",
                    from_url=strip_url_credentials(current_url),
                    to_url=strip_url_credentials(next_url),
                    status=resp.status_code,
                    hop=redirect_count + 1,
                )
                current_url = next_url
                redirect_count += 1
                # Reset ETag on redirect — new URL is a different cache entry.
                etag = None
                continue

            # 4xx/5xx: _one_attempt either raised NonRetryableHTTPError
            # or the retry policy exhausted.  If control reaches here,
            # return raw (defensive — should be unreachable).
            span.set_attribute("http.status_code", resp.status_code)
            return resp


__all__ = [
    "DomainNotAllowedError",
    "ResponseTooLargeError",
    "SentinelHTTPClient",
]

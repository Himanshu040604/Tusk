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

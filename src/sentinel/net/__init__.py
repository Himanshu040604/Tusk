"""Network core for Sentinel (Phase 3).

Hardened HTTP client with SSRF defenses, URL allow-list, HMAC-signed disk
cache, and per-source retry budgets.  See prod_imp.md § 8 for the full
spec.
"""

from __future__ import annotations

from .allow_list import AllowList
from .cache import CacheEntry, DiskCache
from .client import DomainNotAllowedError, SentinelHTTPClient
from .guards import SSRFBlockedError, resolve_and_validate
from .retry import NonRetryableHTTPError, RetryPolicy

__all__ = [
    "AllowList",
    "CacheEntry",
    "DiskCache",
    "DomainNotAllowedError",
    "NonRetryableHTTPError",
    "RetryPolicy",
    "SentinelHTTPClient",
    "SSRFBlockedError",
    "resolve_and_validate",
]

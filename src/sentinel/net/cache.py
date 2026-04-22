"""Disk cache with HMAC integrity + per-source TTL (§ 8.5).

Every entry is a JSON file under ``$XDG_CACHE_HOME/sentinel/``.  The
file name is ``SHA-256(canonical_url) + ".json"`` and the body carries
an HMAC-SHA256 signature computed with the **derived** cache sub-key
(Amendment 6 Theme D) — not the root key directly.

Signature input binds ``(url_hash, source, body_sha256, etag,
fetched_at_ts)``.  Verification with :func:`hmac.compare_digest`
rejects tampered entries; a signature mismatch invalidates the entry
and triggers refetch.

Graceful degradation: if the cache dir is unwritable (read-only
container / locked-down CI), the cache falls back to a process-lifetime
in-memory dict with a single ``[WARN]`` on first fetch.

Public API:

* :class:`CacheEntry` — frozen dataclass returned by ``get()``.
* :class:`DiskCache` — the cache itself.
* :func:`canonical_url` — URL canonicalization helper (stable key input).
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import sys
import tempfile
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Final, Optional
from urllib.parse import urlsplit, urlunsplit

import structlog

from ..hmac_keys import derive_cache_key

_ENTRY_VERSION: Final[int] = 1
_SIG_LABEL: Final[bytes] = b"sentinel-v1/cache-entry"


def canonical_url(url: str) -> str:
    """Return a stable canonical form of ``url`` for cache keying.

    Lowercases scheme + host, strips default ports, removes fragment,
    preserves query order as-received (the caller is expected to have
    already sorted if semantic de-duplication is desired).
    """
    parts = urlsplit(url)
    scheme = parts.scheme.lower()
    host = (parts.hostname or "").lower()
    port = parts.port
    default_port = {"http": 80, "https": 443}.get(scheme)
    netloc = host
    if port and port != default_port:
        netloc = f"{host}:{port}"
    if parts.username:
        # Strip creds-in-URL — they must not influence the cache key.
        pass
    return urlunsplit((scheme, netloc, parts.path or "/", parts.query, ""))


def url_key(url: str) -> str:
    """SHA-256 hex of the canonical URL — the cache filename stem."""
    return hashlib.sha256(canonical_url(url).encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class CacheEntry:
    """One cache hit.  Returned by :meth:`DiskCache.get`.

    Attributes:
        url: Canonical URL this entry was keyed on.
        source: Source tag (``aws_docs`` / ``github`` / ``user_url`` / ...).
        body: Raw response bytes (decoded from base64 on load).
        headers: Response headers as a plain dict.
        etag: ``ETag`` header value if present, for ``If-None-Match``.
        fetched_at: Unix timestamp when the entry was written.
        ttl_seconds: How long this entry is valid.
    """

    url: str
    source: str
    body: bytes
    headers: dict[str, str]
    etag: str | None
    fetched_at: float
    ttl_seconds: int

    @property
    def expires_at(self) -> float:
        return self.fetched_at + self.ttl_seconds

    def is_fresh(self, now: float | None = None) -> bool:
        return (now or time.time()) < self.expires_at


def _default_cache_dir() -> Path:
    """XDG cache dir resolver; Windows uses LOCALAPPDATA.

    Honors ``SENTINEL_CACHE_DIR`` > ``XDG_CACHE_HOME`` > platform default.
    """
    override = os.environ.get("SENTINEL_CACHE_DIR")
    if override:
        return Path(override)
    xdg = os.environ.get("XDG_CACHE_HOME")
    if xdg:
        return Path(xdg) / "sentinel"
    if sys.platform == "win32":
        local = os.environ.get("LOCALAPPDATA")
        if local:
            return Path(local) / "sentinel" / "cache"
    return Path.home() / ".cache" / "sentinel"


def _default_ttl_by_source() -> dict[str, int]:
    """Default TTL map mirroring ``[cache]`` in defaults.toml (seconds)."""
    return {
        "aws_docs": 168 * 3600,
        "policy_sentry": 72 * 3600,
        "github": 24 * 3600,
        "user_url": 1 * 3600,
    }


def _sign(key: bytes, url_hash: str, source: str, body: bytes,
          etag: str | None, fetched_at: float) -> str:
    """Compute the HMAC-SHA256 hex digest for a cache entry.

    Input binds all forgery-sensitive fields: the URL hash (key),
    source (TTL bucket), body SHA-256 (content), etag (conditional
    refresh token), fetched_at timestamp (freshness anchor).  A label
    prefix domain-separates this MAC from any other HMAC that might
    later reuse the same key.
    """
    body_hash = hashlib.sha256(body).hexdigest()
    msg = b"\x1e".join([
        _SIG_LABEL,
        url_hash.encode("ascii"),
        source.encode("utf-8"),
        body_hash.encode("ascii"),
        (etag or "").encode("utf-8"),
        f"{fetched_at:.6f}".encode("ascii"),
    ])
    return hmac.new(key, msg, hashlib.sha256).hexdigest()


class DiskCache:
    """HMAC-signed on-disk response cache with per-source TTL.

    Instances are cheap to construct; file I/O is lazy.  The cache key
    (``K_cache``) is derived once per process from
    :func:`sentinel.hmac_keys.derive_cache_key` and memoised on the
    instance.  If the cache directory cannot be created / written, the
    cache transparently falls back to an in-memory dict for the process
    lifetime (documented behaviour in § 8.5).
    """

    def __init__(
        self,
        cache_dir: Path | None = None,
        ttl_seconds_by_source: dict[str, int] | None = None,
    ) -> None:
        self._cache_dir = cache_dir or _default_cache_dir()
        self._ttl = ttl_seconds_by_source or _default_ttl_by_source()
        self._mem: dict[str, bytes] | None = None
        self._key: bytes | None = None
        self._log = structlog.get_logger("sentinel.net.cache")
        self._ensure_dir()

    # ------------------------------------------------------------------ utils

    def _ensure_dir(self) -> None:
        """Create the cache dir; fall back to in-memory on OSError."""
        try:
            self._cache_dir.mkdir(parents=True, exist_ok=True)
        except OSError as exc:
            self._log.warning(
                "cache_dir_unwritable",
                path=str(self._cache_dir),
                error=str(exc),
                note="falling back to in-memory cache for this process",
            )
            self._mem = {}

    def _derived_key(self) -> bytes:
        if self._key is None:
            try:
                self._key = derive_cache_key()
            except OSError as exc:
                # Cache-key storage itself unwritable — in-memory fallback.
                self._log.warning(
                    "cache_key_unwritable",
                    error=str(exc),
                    note="falling back to in-memory cache",
                )
                # Derive an ephemeral per-process key so HMAC still binds.
                import secrets as _secrets

                self._key = _secrets.token_bytes(32)
                if self._mem is None:
                    self._mem = {}
        return self._key

    def _entry_path(self, url: str) -> Path:
        return self._cache_dir / (url_key(url) + ".json")

    def key(self, url: str) -> str:
        """Public accessor for the cache key (SHA-256 of canonical URL)."""
        return url_key(url)

    def ttl_for(self, source: str) -> int:
        """Return the TTL (seconds) for a source, defaulting to ``user_url``."""
        return self._ttl.get(source, self._ttl.get("user_url", 3600))

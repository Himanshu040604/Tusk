"""Fetcher Protocol + shared exception hierarchy — Phase 4 Task 1.

All eight concrete fetchers (url, github, aws_sample, aws_managed,
cloudsplaining, clipboard, batch, stdin) implement :class:`Fetcher`
and return :class:`FetchResult`.  This keeps the CLI's ``fetch``
subcommand dispatcher and the Pipeline's ingestion path polymorphic.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol

from sentinel.models import PolicyOrigin


class FetcherError(Exception):
    """Base class for all fetcher-side failures."""


class PolicyNotFoundError(FetcherError):
    """The fetcher reached the source but no policy JSON was present."""


class ClipboardUnavailable(FetcherError):
    """The clipboard backend could not be opened on this host."""


class InvalidSpecError(FetcherError):
    """The caller-supplied spec string was malformed for this fetcher."""


@dataclass(frozen=True)
class FetchResult:
    """One fetched policy payload + its provenance record.

    Attributes:
        body: Raw bytes exactly as received (or read from disk /
            clipboard).  Downstream code decodes on demand — storing
            bytes keeps the SHA-256 stable across encodings.
        headers: HTTP response headers or synthetic ``{}`` for local
            sources.  ``X-Sentinel-Cache`` is preserved from the
            :class:`~sentinel.net.client.SentinelHTTPClient` pass.
        cache_status: ``"HIT"``, ``"MISS"`` or ``"N/A"``.  Mirrors
            :attr:`PolicyOrigin.cache_status` and drives the Origin
            badge renderer.
        origin: The :class:`PolicyOrigin` to attach to the pipeline
            input.  The caller should use this verbatim when building
            the :class:`~sentinel.models.PolicyInput`.
    """

    body: bytes
    headers: dict[str, str]
    cache_status: str
    origin: PolicyOrigin


class Fetcher(Protocol):
    """Polymorphic fetcher contract.

    Implementations are cheap-to-construct, may cache HTTP responses
    through :class:`SentinelHTTPClient`, and must never perform network
    I/O outside of that client.
    """

    def fetch(self, spec: str) -> FetchResult:
        """Fetch one policy.

        Args:
            spec: Fetcher-specific locator — URL, ``owner/repo/path``,
                sample name, managed policy name, file path, etc.

        Returns:
            A :class:`FetchResult`.

        Raises:
            FetcherError: On any fetcher-side failure.
        """
        ...


__all__ = [
    "ClipboardUnavailable",
    "Fetcher",
    "FetcherError",
    "FetchResult",
    "InvalidSpecError",
    "PolicyNotFoundError",
]

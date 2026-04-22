"""Fetchers package — Phase 4.

Each fetcher implements :class:`Fetcher` and returns a
:class:`FetchResult` whose :class:`sentinel.models.PolicyOrigin` is
consumed by the Pipeline and the Origin-badge formatters.
"""

from __future__ import annotations

from .aws_managed import AWSManagedFetcher
from .aws_sample import AWSSampleFetcher
from .base import (
    ClipboardUnavailable,
    Fetcher,
    FetcherError,
    FetchResult,
    InvalidSpecError,
    PolicyNotFoundError,
)
from .batch import BatchFetcher
from .clipboard import ClipboardFetcher
from .cloudsplaining import CloudSplainingFetcher
from .github import GitHubFetcher
from .local import LocalFileFetcher, StdinFetcher
from .url import URLFetcher

__all__ = [
    "AWSManagedFetcher",
    "AWSSampleFetcher",
    "BatchFetcher",
    "ClipboardFetcher",
    "ClipboardUnavailable",
    "CloudSplainingFetcher",
    "Fetcher",
    "FetcherError",
    "FetchResult",
    "GitHubFetcher",
    "InvalidSpecError",
    "LocalFileFetcher",
    "PolicyNotFoundError",
    "StdinFetcher",
    "URLFetcher",
]

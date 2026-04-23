"""Local / stdin fetchers — zero-network policy ingestion.

These two are trivial but live in the fetchers package so the CLI
dispatcher can treat every source uniformly (all produce a
:class:`FetchResult` with a :class:`PolicyOrigin`).
"""

from __future__ import annotations

import sys
from pathlib import Path

from .base import Fetcher, FetchResult, PolicyNotFoundError
from ._http_helpers import build_local_origin


class LocalFileFetcher:
    """Reads a single JSON or YAML file from the local filesystem.

    Stamps ``source_type="local"`` and ``source_spec=<absolute path>``
    so provenance reflects the exact file on disk, not the caller-
    supplied (possibly relative) arg.
    """

    def fetch(self, spec: str) -> FetchResult:
        path = Path(spec)
        if not path.exists():
            raise PolicyNotFoundError(f"file not found: {spec!r}")
        if not path.is_file():
            raise PolicyNotFoundError(f"not a regular file: {spec!r}")
        body = path.read_bytes()
        origin = build_local_origin(
            source_type="local",
            source_spec=str(path.resolve()),
            body=body,
        )
        return FetchResult(
            body=body,
            headers={},
            cache_status="N/A",
            origin=origin,
        )


class StdinFetcher:
    """Reads a policy from ``sys.stdin``.

    Spec is ignored — stdin is a singleton.  Raises
    :class:`PolicyNotFoundError` when the caller pipes nothing.
    """

    def fetch(self, spec: str) -> FetchResult:  # noqa: ARG002
        data = sys.stdin.buffer.read()
        if not data.strip():
            raise PolicyNotFoundError("stdin was empty")
        origin = build_local_origin(
            source_type="stdin",
            source_spec="<stdin>",
            body=data,
        )
        return FetchResult(
            body=data,
            headers={},
            cache_status="N/A",
            origin=origin,
        )


__all__ = ["LocalFileFetcher", "StdinFetcher", "Fetcher"]

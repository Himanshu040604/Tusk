"""Batch fetcher — walks a directory and yields one FetchResult per file.

Spec: a directory path.  The fetcher is a generator (``iter_fetch``)
because the caller decides ``--fail-fast`` semantics.  The sync
``fetch`` method (Protocol compliance) returns the FIRST result; real
use of the batch fetcher should go through ``iter_fetch``.

Permission errors are *skipped* with a structlog WARN (§ 11.1 — "a
single unreadable file should not kill a 200-file batch").  Missing-
directory or "no matching files" cases raise :class:`PolicyNotFoundError`
because they're configuration errors, not transient I/O issues.
"""

from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path

import structlog

from .base import Fetcher, FetchResult, PolicyNotFoundError
from ._http_helpers import build_local_origin


_ACCEPTED_SUFFIXES = (".json", ".txt", ".yaml", ".yml")


class BatchFetcher:
    """Yields one :class:`FetchResult` per policy file under a directory.

    Order: :meth:`Path.rglob` default — file-system dependent.  The
    pipeline treats each result independently so order is not
    semantically meaningful, but tests may want to sort.
    """

    def __init__(self) -> None:
        self._log = structlog.get_logger("sentinel.fetchers.batch")

    def iter_fetch(self, spec: str) -> Iterator[FetchResult]:
        root = Path(spec)
        if not root.exists() or not root.is_dir():
            raise PolicyNotFoundError(f"not a directory: {spec!r}")

        matched_any = False
        for path in sorted(root.rglob("*")):
            if not path.is_file():
                continue
            if path.suffix.lower() not in _ACCEPTED_SUFFIXES:
                continue
            try:
                body = path.read_bytes()
            except PermissionError as exc:
                self._log.warning(
                    "batch_permission_denied", path=str(path), error=str(exc),
                )
                continue
            except OSError as exc:
                self._log.warning(
                    "batch_read_failed", path=str(path), error=str(exc),
                )
                continue
            matched_any = True
            origin = build_local_origin(
                source_type="local",
                source_spec=str(path.resolve()),
                body=body,
            )
            yield FetchResult(
                body=body, headers={}, cache_status="N/A", origin=origin,
            )

        if not matched_any:
            raise PolicyNotFoundError(
                f"no policy files (.json/.txt/.yaml/.yml) under {spec!r}"
            )

    def fetch(self, spec: str) -> FetchResult:
        """Protocol compliance — returns the first match only.

        Real callers want :meth:`iter_fetch`.  This method is a
        convenience for test harnesses and the CLI's "dry run" path.
        """
        return next(iter(self.iter_fetch(spec)))


__all__ = ["BatchFetcher", "Fetcher"]

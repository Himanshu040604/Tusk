"""AWS managed policy fetcher — DB-backed lookup (offline).

Reads from the ``managed_policies`` table seeded by
``src/refresh/aws_managed_policies.py`` (scraper).  Three operations:

* :meth:`list_names` — all managed policy names.
* :meth:`show` — a full policy JSON document as bytes.
* :meth:`fetch` — protocol-compliant entry that returns the document
  wrapped in a :class:`FetchResult` ready for the pipeline.

M17 query discipline: every SELECT uses an **explicit column list**.
``SELECT *`` is banned outside ``migrations/versions/`` — the
``policy_document`` column is ~6 KB per row and accidental wildcard
queries blow up memory fast at ~1000 managed policies.
"""

from __future__ import annotations

import sqlite3
from typing import TYPE_CHECKING

from .base import Fetcher, FetchResult, PolicyNotFoundError
from ._http_helpers import build_local_origin

if TYPE_CHECKING:  # pragma: no cover
    from sentinel.database import Database


_COLS_SUMMARY = "policy_name, policy_arn, description, version, fetched_at"
_COLS_FULL = (
    "policy_name, policy_arn, policy_document, description, version, "
    "fetched_at, policy_document_hmac"
)


class AWSManagedFetcher:
    """DB-backed accessor for AWS managed policies."""

    def __init__(self, database: "Database") -> None:
        self._db = database

    # ---------------------------------------------------------------- list

    def list_names(self) -> list[str]:
        """Return all managed policy names in alphabetic order.

        Uses the explicit ``policy_name`` column only — the cheapest
        query we can issue, avoids paging policy_document bytes.
        """
        with self._db.get_connection() as conn:
            rows = conn.execute(
                "SELECT policy_name FROM managed_policies ORDER BY policy_name"
            ).fetchall()
        return [row["policy_name"] if isinstance(row, sqlite3.Row) else row[0] for row in rows]

    # ---------------------------------------------------------------- summary

    def summary(self, name: str) -> dict[str, str | None]:
        """Return metadata-only summary — no document bytes."""
        with self._db.get_connection() as conn:
            row = conn.execute(
                f"SELECT {_COLS_SUMMARY} FROM managed_policies WHERE policy_name = ?",
                (name,),
            ).fetchone()
        if row is None:
            raise PolicyNotFoundError(f"managed policy not found: {name!r}")
        return (
            {k: row[k] for k in row.keys()}
            if isinstance(row, sqlite3.Row)
            else dict(
                zip(("policy_name", "policy_arn", "description", "version", "fetched_at"), row)
            )
        )

    # ---------------------------------------------------------------- show

    def _load_document(self, name: str) -> tuple[bytes, str]:
        """Return ``(policy_document_bytes, stored_hmac)`` or raise."""
        with self._db.get_connection() as conn:
            row = conn.execute(
                f"SELECT {_COLS_FULL} FROM managed_policies WHERE policy_name = ?",
                (name,),
            ).fetchone()
        if row is None:
            raise PolicyNotFoundError(f"managed policy not found: {name!r}")
        doc = row["policy_document"] if isinstance(row, sqlite3.Row) else row[2]
        mac = row["policy_document_hmac"] if isinstance(row, sqlite3.Row) else row[6]
        return doc.encode("utf-8"), str(mac)

    def show(self, name: str) -> bytes:
        """Return the policy_document JSON bytes for a managed policy."""
        body, _mac = self._load_document(name)
        return body

    # ---------------------------------------------------------------- fetch

    def fetch(self, spec: str) -> FetchResult:
        body, _mac = self._load_document(spec)
        origin = build_local_origin(
            source_type="aws-managed",
            source_spec=spec,
            body=body,
        )
        return FetchResult(
            body=body,
            headers={},
            cache_status="N/A",
            origin=origin,
        )


__all__ = ["AWSManagedFetcher", "Fetcher"]

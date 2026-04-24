"""Loader + live scraper for the ``managed_policies`` table.

The AWS managed policy list is enumerated at:

* ``https://docs.aws.amazon.com/IAM/latest/UserGuide/
   reference_aws-managed-policies.html``

with each policy's JSON hosted at per-policy pages.  The scraper
fetches via :class:`SentinelHTTPClient` (``source="aws_docs"``,
7 d TTL) and writes rows to ``managed_policies`` signed with the
``policy_document_hmac`` HMAC column (M12, Phase 2 Task 6a).

This module deliberately keeps two entry points:

* :class:`ManagedPoliciesLoader` — read a local JSON file/dir of
  pre-fetched documents and write to DB.  Used by the CLI's
  ``refresh --source managed-policies`` flow for offline refresh.
* :class:`ManagedPoliciesLiveScraper` — thin live-scrape wrapper
  (``--live``) that fetches pages through the hardened HTTP client.

Both paths reuse :func:`_insert_row` so HMAC signing is centralised.
"""

from __future__ import annotations

import hashlib
import hmac
import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import TYPE_CHECKING

import structlog

from ..hmac_keys import derive_db_row_key

if TYPE_CHECKING:  # pragma: no cover
    from ..database import Database
    from ..net.client import SentinelHTTPClient


@dataclass
class ManagedPoliciesStats:
    """Counters for a managed-policies refresh run."""

    policies_added: int = 0
    policies_updated: int = 0
    errors: list[str] = field(default_factory=list)


def _sign_document(policy_document: str) -> str:
    """HMAC-SHA256 the policy_document bytes with the DB row key (M12)."""
    key = derive_db_row_key()
    return hmac.new(key, policy_document.encode("utf-8"), hashlib.sha256).hexdigest()


def _insert_row(
    database: "Database",
    *,
    name: str,
    arn: str,
    document: str,
    description: str | None,
    version: str | None,
) -> str:
    """Upsert one managed_policies row and return 'ADD' or 'UPDATE'."""
    doc_hmac = _sign_document(document)
    fetched_at = datetime.now(timezone.utc).isoformat()
    with database.get_connection() as conn:
        existing = conn.execute(
            "SELECT policy_name FROM managed_policies WHERE policy_name = ?",
            (name,),
        ).fetchone()
        change = "UPDATE" if existing else "ADD"
        conn.execute(
            "INSERT OR REPLACE INTO managed_policies "
            "(policy_name, policy_arn, policy_document, description, "
            " version, fetched_at, policy_document_hmac) "
            "VALUES (?, ?, ?, ?, ?, ?, ?)",
            (name, arn, document, description, version, fetched_at, doc_hmac),
        )
    return change


class ManagedPoliciesLoader:
    """Offline loader for the ``managed_policies`` table."""

    def __init__(self, database: "Database") -> None:
        self._db = database
        self._log = structlog.get_logger("sentinel.refresh.managed_policies")

    def load_from_file(self, path: Path) -> ManagedPoliciesStats:
        """Load a single JSON file containing one or many policies."""
        raw = json.loads(path.read_text(encoding="utf-8"))
        entries = raw if isinstance(raw, list) else [raw]
        return self._load_entries(entries)

    def load_from_directory(self, root: Path) -> ManagedPoliciesStats:
        stats = ManagedPoliciesStats()
        for json_file in sorted(root.glob("*.json")):
            try:
                partial = self.load_from_file(json_file)
            except (OSError, ValueError) as exc:
                stats.errors.append(f"{json_file.name}: {exc}")
                continue
            stats.policies_added += partial.policies_added
            stats.policies_updated += partial.policies_updated
            stats.errors.extend(partial.errors)
        return stats

    def _load_entries(self, entries: list[dict]) -> ManagedPoliciesStats:
        stats = ManagedPoliciesStats()
        for entry in entries:
            try:
                change = _insert_row(
                    self._db,
                    name=entry["policy_name"],
                    arn=entry["policy_arn"],
                    document=json.dumps(entry["policy_document"], sort_keys=True),
                    description=entry.get("description"),
                    version=entry.get("version"),
                )
            except (KeyError, TypeError) as exc:
                stats.errors.append(f"{entry!r}: {exc}")
                continue
            if change == "ADD":
                stats.policies_added += 1
            else:
                stats.policies_updated += 1
        return stats


class ManagedPoliciesLiveScraper:
    """Live HTTP scraper — fetches policy JSON via SentinelHTTPClient.

    Minimal Phase 4 implementation: a ``scrape_one(name, url)`` entry
    the CLI can drive in a loop.  Page enumeration (walking the
    reference index) is Phase 5's search/compare work.
    """

    def __init__(
        self,
        database: "Database",
        client: "SentinelHTTPClient",
    ) -> None:
        self._db = database
        self._client = client
        self._log = structlog.get_logger("sentinel.refresh.managed_scraper")

    def scrape_one(
        self,
        *,
        name: str,
        arn: str,
        url: str,
        description: str | None = None,
        version: str | None = None,
    ) -> str:
        """Fetch one policy doc from ``url`` and upsert into the DB."""
        resp = self._client.get(url, source="aws_docs")
        # Expect the URL to return JSON (not HTML) — the managed-policy
        # documents endpoint is direct JSON, not the HTML docs page.
        document = resp.text
        # Verify it parses as JSON so we never store HTML-as-policy.
        json.loads(document)
        change = _insert_row(
            self._db,
            name=name,
            arn=arn,
            document=document,
            description=description,
            version=version,
        )
        self._log.info("managed_policy_upserted", name=name, change=change)
        return change


__all__ = [
    "ManagedPoliciesLiveScraper",
    "ManagedPoliciesLoader",
    "ManagedPoliciesStats",
]

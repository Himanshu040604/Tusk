"""Loader + live scraper for the ``managed_policies`` table.

The AWS managed policy list is enumerated at:

* ``https://docs.aws.amazon.com/IAM/latest/UserGuide/
   reference_aws-managed-policies.html``

with each policy's JSON hosted at per-policy pages.  The scraper
fetches via :class:`SentinelHTTPClient` (``source="github"`` since
Bundle B.9; was ``"aws_docs"`` historically,
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


# Bundle B.8: fallback mirror chain. If the primary IAMTrail URL fails
# (HTTP error or shape drift), derive an iann0036/iam-dataset URL from
# the policy name and try that instead. iann0036 uses a different
# envelope shape — `.document` instead of `.PolicyVersion.Document` —
# so _unwrap_envelope handles both forms.
#
# Pinned to a specific iann0036 commit (Bundle B.7 pattern) for the same
# silent-drift protection.
_IANN0036_PIN = "bca9a21efb90cd8b7ef4a94247c968c30e8d467e"  # pragma: allowlist secret  # public git SHA, not a credential
_IANN0036_FALLBACK_BASE = (
    f"https://raw.githubusercontent.com/iann0036/iam-dataset/{_IANN0036_PIN}/aws/managedpolicies"
)


def _unwrap_envelope(parsed: object, url: str) -> tuple[str, str | None]:
    """Extract canonical IAM doc + optional version from a mirror response.

    Tries IAMTrail shape first (``.PolicyVersion.Document``), then
    iann0036 shape (``.document``). Returns ``(canonical_doc_json,
    version_or_none)``. Raises ``ValueError`` if neither shape matches.

    Why two shapes: IAMTrail mirrors AWS's ``GetPolicyVersion`` API
    response verbatim (so the wrapper carries ``VersionId`` + metadata).
    iann0036/iam-dataset publishes a custom envelope with the inner
    ``Document`` at ``.document`` (lowercase) plus its own metadata
    fields (``access_levels``, ``credentials_exposure``, etc.).
    """
    if not isinstance(parsed, dict):
        raise ValueError(f"managed-policy mirror {url!r} returned non-dict body")
    # IAMTrail shape (preferred — GetPolicyVersion envelope).
    if "PolicyVersion" in parsed:
        pv = parsed["PolicyVersion"]
        if isinstance(pv, dict):
            inner = pv.get("Document")
            if isinstance(inner, dict) and "Statement" in inner:
                return json.dumps(inner, sort_keys=True), pv.get("VersionId")
    # iann0036 shape (fallback — `document` lowercase, no version field).
    if "document" in parsed:
        inner = parsed["document"]
        if isinstance(inner, dict) and "Statement" in inner:
            return json.dumps(inner, sort_keys=True), None
    raise ValueError(
        f"managed-policy mirror {url!r} matches neither IAMTrail "
        f"(.PolicyVersion.Document) nor iann0036 (.document) envelope"
    )


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
        """Fetch one policy doc from ``url`` and upsert into the DB.

        Bundle M.2: the IAMTrail mirror returns the AWS GetPolicyVersion
        envelope::

            {"PolicyVersion": {"Document": {"Version": ..., "Statement": [...]},
                                "VersionId": "v3", "IsDefaultVersion": true,
                                "CreateDate": "..."}}

        We unwrap to the inner ``Document`` (raw IAM policy with top-level
        Version/Statement) before HMAC-signing + storing, so downstream
        readers see a real policy document. The strict shape validation
        fails closed (raises ``ValueError``) on schema drift — aligned
        with § 2 Principle 4 — rather than silently storing the wrapper
        as-policy.

        ``effective_version`` falls back to ``pv["VersionId"]`` from the
        envelope when the caller doesn't pin one explicitly, so the
        ``version`` column auto-populates from the mirror.
        """
        # Bundle B.9: source tag is "github" because the upstream is now
        # raw.githubusercontent.com/zoph-io/IAMTrail (Bundle M). Aligns
        # the cache TTL (24h github vs 168h aws_docs) with reality.
        #
        # Bundle B.8: try the primary URL; on any failure (HTTP, JSON,
        # or shape drift) fall back to iann0036/iam-dataset with the
        # appropriate envelope adapter via _unwrap_envelope.
        actual_url = url
        try:
            resp = self._client.get(url, source="github")
            parsed = json.loads(resp.text)
            document, mirror_version = _unwrap_envelope(parsed, url)
        except Exception as primary_exc:  # noqa: BLE001
            fallback_url = f"{_IANN0036_FALLBACK_BASE}/{name}.json"
            self._log.warning(
                "managed_policy_primary_mirror_failed_falling_back",
                primary_url=url,
                fallback_url=fallback_url,
                primary_error=repr(primary_exc),
            )
            try:
                resp = self._client.get(fallback_url, source="github")
                parsed = json.loads(resp.text)
                document, mirror_version = _unwrap_envelope(parsed, fallback_url)
                actual_url = fallback_url
            except Exception as fallback_exc:  # noqa: BLE001
                raise ValueError(
                    f"both managed-policy mirrors failed for {name!r}: "
                    f"primary={primary_exc!r}; fallback={fallback_exc!r}"
                ) from fallback_exc
        effective_version = version or mirror_version
        change = _insert_row(
            self._db,
            name=name,
            arn=arn,
            document=document,
            description=description,
            version=effective_version,
        )
        self._log.info(
            "managed_policy_upserted",
            name=name,
            change=change,
            version=effective_version,
            source_url=actual_url,
            used_fallback=actual_url != url,
        )
        return change


__all__ = [
    "ManagedPoliciesLiveScraper",
    "ManagedPoliciesLoader",
    "ManagedPoliciesStats",
]

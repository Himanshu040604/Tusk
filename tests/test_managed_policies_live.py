"""Tests for the managed-policies live scraper (Bundle M.3).

Two test classes:

1. ``TestScrapeOneUnwrapsEnvelope`` — unit tests with a mock HTTP client
   verifying the GetPolicyVersion envelope unwrap behavior added in
   Bundle M.2.

2. ``TestLiveIamtrailMirror`` — gated on ``@pytest.mark.live``; fetches
   the real IAMTrail mirror and asserts the envelope shape is intact,
   so a future schema change at the upstream mirror surfaces as a
   nightly cron failure rather than silent corruption.
"""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import MagicMock

import pytest

from sentinel.database import Database
from sentinel.migrations import check_and_upgrade_all_dbs
from sentinel.refresh.aws_managed_policies import ManagedPoliciesLiveScraper


def _migrated_db(tmp_path: Path) -> Database:
    """Build a freshly-migrated DB so managed_policies table exists."""
    iam_db = tmp_path / "iam_actions.db"
    inv_db = tmp_path / "resource_inventory.db"
    check_and_upgrade_all_dbs(iam_db_path=iam_db, inventory_db_path=inv_db)
    return Database(iam_db)


def _mock_client(response_json: dict | str) -> MagicMock:
    """Mock SentinelHTTPClient with a `.get(url, source=...)` returning text."""
    client = MagicMock()
    text = response_json if isinstance(response_json, str) else json.dumps(response_json)
    resp = MagicMock()
    resp.text = text
    client.get.return_value = resp
    return client


class TestScrapeOneUnwrapsEnvelope:
    """Bundle M.2: scraper unwraps GetPolicyVersion envelope before storing."""

    def test_unwraps_policy_version_document_before_storing(self, tmp_path):
        """Stored policy_document is the inner Document, NOT the wrapper."""
        db = _migrated_db(tmp_path)
        envelope = {
            "PolicyVersion": {
                "Document": {
                    "Version": "2012-10-17",
                    "Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}],
                },
                "VersionId": "v1",
                "IsDefaultVersion": True,
                "CreateDate": "2015-02-06T18:39:46+00:00",
            }
        }
        scraper = ManagedPoliciesLiveScraper(db, _mock_client(envelope))
        scraper.scrape_one(
            name="AdministratorAccess",
            arn="arn:aws:iam::aws:policy/AdministratorAccess",
            url="https://example.com/AdministratorAccess",
        )
        with db.get_connection() as conn:
            row = conn.execute(
                "SELECT policy_document, version FROM managed_policies WHERE policy_name = ?",
                ("AdministratorAccess",),
            ).fetchone()
        stored = json.loads(row["policy_document"])
        # The wrapper key MUST NOT survive into stored doc.
        assert "PolicyVersion" not in stored
        assert stored["Version"] == "2012-10-17"
        assert stored["Statement"][0]["Effect"] == "Allow"
        # version column auto-populated from envelope's VersionId.
        assert row["version"] == "v1"

    def test_rejects_non_envelope_shape(self, tmp_path):
        """Raw IAM doc (no wrapper) must raise ValueError matching PolicyVersion."""
        db = _migrated_db(tmp_path)
        raw_doc = {
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}],
        }
        scraper = ManagedPoliciesLiveScraper(db, _mock_client(raw_doc))
        with pytest.raises(ValueError, match="PolicyVersion"):
            scraper.scrape_one(
                name="X",
                arn="arn:aws:iam::aws:policy/X",
                url="https://example.com/X",
            )

    def test_rejects_envelope_missing_document_statement(self, tmp_path):
        """Envelope present but Document.Statement missing -> ValueError."""
        db = _migrated_db(tmp_path)
        envelope_no_statement = {
            "PolicyVersion": {
                "Document": {"Version": "2012-10-17"},  # no Statement
                "VersionId": "v1",
            }
        }
        scraper = ManagedPoliciesLiveScraper(db, _mock_client(envelope_no_statement))
        with pytest.raises(ValueError, match="Statement"):
            scraper.scrape_one(
                name="X",
                arn="arn:aws:iam::aws:policy/X",
                url="https://example.com/X",
            )

    def test_explicit_version_kwarg_overrides_envelope_version_id(self, tmp_path):
        """Caller-supplied version kwarg wins over envelope's VersionId."""
        db = _migrated_db(tmp_path)
        envelope = {
            "PolicyVersion": {
                "Document": {
                    "Version": "2012-10-17",
                    "Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}],
                },
                "VersionId": "v1",
            }
        }
        scraper = ManagedPoliciesLiveScraper(db, _mock_client(envelope))
        scraper.scrape_one(
            name="AdministratorAccess",
            arn="arn:aws:iam::aws:policy/AdministratorAccess",
            url="https://example.com/X",
            version="explicit-v99",  # caller pin
        )
        with db.get_connection() as conn:
            row = conn.execute(
                "SELECT version FROM managed_policies WHERE policy_name = ?",
                ("AdministratorAccess",),
            ).fetchone()
        assert row["version"] == "explicit-v99"


@pytest.mark.live
class TestLiveIamtrailMirror:
    """Live mirror shape regression — gated by @pytest.mark.live (nightly only)."""

    def test_iamtrail_mirror_returns_getpolicyversion_envelope(self):
        """Real fetch against the IAMTrail mirror returns the expected envelope.

        If this test starts failing in the nightly cron, the upstream
        mirror schema has drifted and Bundle M.2's strict shape check
        will start raising in the daily refresh — surface the issue here
        first so we get a focused signal rather than a generic ValueError
        from the scraper.
        """
        import httpx

        url = (
            "https://raw.githubusercontent.com/zoph-io/IAMTrail/master/policies/AdministratorAccess"
        )
        resp = httpx.get(url, timeout=15.0, follow_redirects=True)
        assert resp.status_code == 200, f"IAMTrail fetch failed: {resp.status_code}"
        body = resp.json()
        assert isinstance(body, dict), "Expected dict at top level"
        assert "PolicyVersion" in body, (
            f"IAMTrail upstream schema drift: missing PolicyVersion key. "
            f"Top-level keys: {list(body.keys())}"
        )
        pv = body["PolicyVersion"]
        assert isinstance(pv, dict) and "Document" in pv, (
            f"IAMTrail PolicyVersion missing Document. Keys: {list(pv.keys())}"
        )
        doc = pv["Document"]
        assert "Statement" in doc and "Version" in doc, (
            f"IAMTrail Document missing Statement/Version. Keys: {list(doc.keys())}"
        )

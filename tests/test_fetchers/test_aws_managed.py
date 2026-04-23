"""Tests for :class:`fetchers.aws_managed.AWSManagedFetcher`.

Pure DB-backed fetcher — no HTTP.  Uses the ``make_test_db`` helper
and inserts sample managed_policies rows directly.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from sentinel.fetchers.aws_managed import AWSManagedFetcher
from sentinel.fetchers.base import PolicyNotFoundError


def _insert_managed_policy(
    db_path: Path,
    name: str,
    document: str,
    arn: str | None = None,
) -> None:
    import sqlite3

    from sentinel.hmac_keys import sign_row

    arn = arn or f"arn:aws:iam::aws:policy/{name}"
    version = "v1"
    fetched_at = "2026-04-22T00:00:00Z"
    description = f"Test managed policy {name}"
    columns = {
        "policy_arn": arn,
        "policy_document": document,
        "description": description,
        "version": version,
        "fetched_at": fetched_at,
    }
    hmac_hex = sign_row("managed_policies", (name,), columns)

    conn = sqlite3.connect(db_path)
    try:
        conn.execute(
            "INSERT INTO managed_policies "
            "(policy_name, policy_arn, policy_document, description, "
            "version, fetched_at, policy_document_hmac) "
            "VALUES (?, ?, ?, ?, ?, ?, ?)",
            (
                name,
                arn,
                document,
                description,
                version,
                fetched_at,
                hmac_hex,
            ),
        )
        conn.commit()
    finally:
        conn.close()


@pytest.fixture
def managed_db(tmp_path: Path, migrated_db_template: Path):
    """Fresh Phase-2 DB with two managed policies pre-inserted.

    v0.7.0 (Phase 7.3): uses ``template=migrated_db_template`` for the
    session-scoped fast-copy path.
    """
    from tests.conftest import make_test_db

    db_path = make_test_db(tmp_path, template=migrated_db_template)
    _insert_managed_policy(
        db_path,
        "ReadOnly",
        json.dumps({"Version": "2012-10-17", "Statement": [{"Effect": "Allow"}]}),
    )
    _insert_managed_policy(
        db_path,
        "Admin",
        json.dumps({"Version": "2012-10-17", "Statement": [{"Effect": "Allow"}]}),
    )
    from sentinel.database import Database

    return Database(db_path)


class TestAWSManagedFetcher:
    def test_list_names_returns_sorted(self, managed_db) -> None:
        names = AWSManagedFetcher(managed_db).list_names()
        assert "ReadOnly" in names
        assert "Admin" in names
        assert names == sorted(names)

    def test_summary_returns_metadata_only(self, managed_db) -> None:
        summary = AWSManagedFetcher(managed_db).summary("ReadOnly")
        assert "policy_document" not in summary
        assert summary["policy_name"] == "ReadOnly"
        assert summary["policy_arn"].endswith("ReadOnly")

    def test_summary_missing_raises(self, managed_db) -> None:
        with pytest.raises(PolicyNotFoundError):
            AWSManagedFetcher(managed_db).summary("NotARealPolicy")

    def test_show_returns_policy_bytes(self, managed_db) -> None:
        body = AWSManagedFetcher(managed_db).show("ReadOnly")
        assert b"Statement" in body

    def test_fetch_builds_fetch_result(self, managed_db) -> None:
        result = AWSManagedFetcher(managed_db).fetch("ReadOnly")
        assert result.origin.source_type == "aws-managed"
        assert result.origin.source_spec == "ReadOnly"
        assert result.cache_status == "N/A"

"""Explicit smoke tests that wire the previously-orphaned fixtures into
a consumer context.

Phase 7 P2-11 α shipped two new conftest fixtures (``migrated_db_template``
and ``signed_db_row``) but no test imported them -- the "implemented
but unused" rot pattern flagged by the post-ship test review.

These tests close the gap:

* ``migrated_db_template`` is consumed via ``make_test_db(template=...)``
  to exercise the fast-copy path (≥1ms per test instead of ~200ms
  migration).
* ``signed_db_row`` is consumed to construct a canonical HMAC-signed row
  for both the Theme-D K_db branch and the custom-key forgery branch.

Per phase7_postship_review_tests.md § "Dimension A — test-infrastructure".
"""

from __future__ import annotations

from pathlib import Path

import pytest

from tests.conftest import make_test_db, signed_db_row

# NOTE: xdist stability is handled by the `_reset_hmac_cache_after_test`
# autouse fixture in conftest.py (v0.6.2).  No per-test cleanup needed here.


# ---------------------------------------------------------------------------
# migrated_db_template — fast-copy path
# ---------------------------------------------------------------------------


def test_migrated_db_template_exists(migrated_db_template: Path) -> None:
    """Fixture produces a session-lived template DB at HEAD + seeded."""
    assert migrated_db_template.exists()
    # Phase-2 table must be present.
    import sqlite3

    conn = sqlite3.connect(str(migrated_db_template))
    try:
        tables = {r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")}
    finally:
        conn.close()
    assert "dangerous_actions" in tables
    assert "companion_rules" in tables


def test_make_test_db_fast_copy_from_template(tmp_path: Path, migrated_db_template: Path) -> None:
    """make_test_db(template=...) path returns a usable per-test DB."""
    path = make_test_db(tmp_path, template=migrated_db_template)
    assert path.exists()
    assert path.parent == tmp_path
    assert path != migrated_db_template

    # Confirm the copy has the same Phase-2 seed content.
    import sqlite3

    conn = sqlite3.connect(str(path))
    try:
        rows = conn.execute("SELECT COUNT(*) FROM dangerous_actions").fetchone()
    finally:
        conn.close()
    assert rows is not None and rows[0] > 0, (
        "Template copy should retain seeded dangerous_actions rows"
    )


# ---------------------------------------------------------------------------
# signed_db_row — K_db branch and custom-key branch
# ---------------------------------------------------------------------------


def test_signed_db_row_default_key_produces_valid_hmac(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Default branch: signed_db_row delegates to hmac_keys.sign_row
    using the per-install K_db.  verify_row must accept the result.
    """
    monkeypatch.setenv("SENTINEL_DATA_DIR", str(tmp_path))
    # Reset cached keys so they derive from this tmp_path.
    import sentinel.hmac_keys as hk

    hk._reset_cache()
    try:
        from sentinel.hmac_keys import verify_row

        row = signed_db_row(
            table="dangerous_actions",
            pk=("iam:PassRole", "privilege_escalation"),
            row_data={"description": "Allows role switching to higher privilege"},
        )
        assert "row_hmac" in row
        hmac_val = row.pop("row_hmac")
        assert verify_row(
            "dangerous_actions",
            ("iam:PassRole", "privilege_escalation"),
            row,
            hmac_val,
        )
    finally:
        # Reset so the next test on this xdist worker re-derives from the
        # session-shared SENTINEL_DATA_DIR (not our tmp_path).
        hk._reset_cache()


def test_signed_db_row_custom_key_matches_manual_hmac() -> None:
    """Custom-key branch: signed_db_row must compute the same digest
    as hmac_keys.sign_row when the same bytes are injected via K_db.
    """
    import hashlib
    import hmac as _hmac

    key = b"A" * 32
    table = "dangerous_actions"
    pk = ("iam:PassRole", "privilege_escalation")
    row_data = {"description": "test"}

    # Manually reproduce the canonical serialization.
    parts: list[bytes] = [table.encode("utf-8")]
    parts.extend(str(v).encode("utf-8") for v in pk)
    for k in sorted(row_data.keys()):
        parts.append(k.encode("utf-8"))
        parts.append(b"\x1f")
        parts.append(str(row_data[k]).encode("utf-8"))
        parts.append(b"\x1e")
    msg = b"\x1e".join(parts)
    expected = _hmac.new(key, msg, hashlib.sha256).hexdigest()

    row = signed_db_row(table=table, pk=pk, row_data=row_data, key=key)
    assert row["row_hmac"] == expected


def test_signed_db_row_rejects_preexisting_row_hmac() -> None:
    """Passing row_hmac in row_data via the custom-key branch must
    raise ValueError (contract: the fixture produces row_hmac, it
    doesn't accept a pre-computed one).
    """
    with pytest.raises(ValueError, match="row_hmac"):
        signed_db_row(
            table="t",
            pk=("x",),
            row_data={"row_hmac": "deadbeef"},
            key=b"\x00" * 32,
        )

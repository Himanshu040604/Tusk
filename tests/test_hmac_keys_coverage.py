"""Security-critical coverage tests for ``sentinel.hmac_keys``.

Targets the previously-uncovered paths (v0.6.1 coverage: 75%):

* ``_data_dir`` env-var precedence (XDG_DATA_HOME, LOCALAPPDATA, fallback).
* Corrupt-size key regeneration path (no signed rows present).
* ``_write_key`` OSError swallow on Windows/non-POSIX chmod.
* ``verify_row`` rejects ``row_hmac`` in input (ValueError -> False).
* ``regenerate_root_key`` rotation clears derived sub-keys.

Per phase7_postship_review_tests.md § "Dimension B — coverage analysis".
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest

from sentinel.hmac_keys import (
    HMACError,
    derive_cache_key,
    derive_db_row_key,
    regenerate_root_key,
    sign_row,
    verify_row,
)
import sentinel.hmac_keys as hk

# NOTE: xdist stability is handled by the `_reset_hmac_cache_after_test`
# autouse fixture in conftest.py (v0.6.2).  No per-test cleanup needed here.


# ---------------------------------------------------------------------------
# _data_dir resolution paths
# ---------------------------------------------------------------------------


def test_data_dir_honors_sentinel_data_dir(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """SENTINEL_DATA_DIR is the highest precedence layer."""
    monkeypatch.setenv("SENTINEL_DATA_DIR", str(tmp_path / "overlay"))
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "xdg"))
    resolved = hk._data_dir()
    assert resolved == tmp_path / "overlay"


def test_data_dir_honors_xdg_data_home(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """XDG_DATA_HOME fallback when SENTINEL_DATA_DIR absent."""
    monkeypatch.delenv("SENTINEL_DATA_DIR", raising=False)
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "xdg"))
    resolved = hk._data_dir()
    assert resolved == tmp_path / "xdg" / "sentinel"


# ---------------------------------------------------------------------------
# Corrupt-size key regen path (first-install state)
# ---------------------------------------------------------------------------


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX perm semantics")
def test_corrupt_size_key_regenerated_on_clean_install(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """Truncated key + no signed DB rows -> warn + regenerate.

    Exercises lines 117-129 (size mismatch, first-install branch).
    """
    monkeypatch.setenv("SENTINEL_DATA_DIR", str(tmp_path))
    key_file = tmp_path / "cache.key"
    # Write an 8-byte (not 32) key.
    key_file.write_bytes(b"truncate")
    os.chmod(key_file, 0o600)  # Proper mode so perm check passes.

    hk._root_key_cached = None
    try:
        key = hk._load_or_create_root_key()
        assert len(key) == 32, "Key should be regenerated to canonical size"
        captured = capsys.readouterr()
        assert "unexpected size" in captured.err
    finally:
        # Reset so the next test on this xdist worker re-derives from the
        # session-shared SENTINEL_DATA_DIR (not our tmp_path).
        hk._reset_cache()


# ---------------------------------------------------------------------------
# regenerate_root_key rotation semantics
# ---------------------------------------------------------------------------


def test_regenerate_root_key_clears_derived_subkeys(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Rotation resets K_cache / K_db so they are re-derived from the new root."""
    monkeypatch.setenv("SENTINEL_DATA_DIR", str(tmp_path))
    hk._reset_cache()
    try:
        old_cache = derive_cache_key()
        old_db = derive_db_row_key()
        new_root = regenerate_root_key()

        assert len(new_root) == 32
        new_cache = derive_cache_key()
        new_db = derive_db_row_key()
        # Both sub-keys MUST differ from their pre-rotation values.
        assert new_cache != old_cache
        assert new_db != old_db
    finally:
        # CRITICAL: reset so the NEXT test on this xdist worker re-derives
        # K_db from the session-shared SENTINEL_DATA_DIR (not our tmp_path).
        # Without this, the shared seeded DB's HMAC rows fail verification.
        hk._reset_cache()


# ---------------------------------------------------------------------------
# verify_row rejects row_hmac in input
# ---------------------------------------------------------------------------


def test_verify_row_rejects_row_hmac_in_columns() -> None:
    """Passing row_hmac inside columns -> sign_row raises ValueError
    and verify_row swallows it, returning False (defensive).

    Exercises lines 283-284 (except ValueError branch).
    """
    cols_with_hmac = {"description": "x", "row_hmac": "deadbeef"}
    result = verify_row("some_table", ("pk",), cols_with_hmac, "deadbeef")
    assert result is False


def test_sign_row_rejects_row_hmac_in_columns() -> None:
    """sign_row must raise ValueError if called with row_hmac in columns."""
    with pytest.raises(ValueError, match="row_hmac"):
        sign_row("some_table", ("pk",), {"row_hmac": "x"})


# ---------------------------------------------------------------------------
# _write_key — POSIX and graceful OSError on chmod
# ---------------------------------------------------------------------------


def test_write_key_swallows_chmod_oserror(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """_write_key must swallow OSError from os.chmod (Windows no-op path).

    Exercises line 212-214 (except OSError: pass).
    """

    def _failing_chmod(*_args, **_kwargs) -> None:
        raise OSError("simulated Windows chmod no-op")

    monkeypatch.setattr("sentinel.hmac_keys.os.chmod", _failing_chmod)
    key_path = tmp_path / "cache.key"
    # Should NOT raise despite chmod failure — the bytes are still written.
    hk._write_key(key_path, b"\x00" * 32)
    assert key_path.read_bytes() == b"\x00" * 32

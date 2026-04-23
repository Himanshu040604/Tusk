"""Tests for :mod:`sentinel.net.cache` (Phase 3 + Amendment 6 Theme D).

Covers:

* Basic put/get round-trip.
* HMAC verification rejects tampered bodies + foreign-key signatures.
* Amendment 6 Theme D domain separation: K_cache MUST NOT equal K_db.
* Atomic write (no ``.tmp`` leftovers on success, cleaned up on failure).
* Graceful in-memory fallback when the cache dir is unwritable.
* ``rotate_key`` wipes the cache and invalidates old signatures.
* TTL expiry evicts entries silently.
* URL canonicalization keys match for trivial variants.
"""

from __future__ import annotations

import json
import os
import time
from pathlib import Path
from unittest.mock import patch

import pytest

from sentinel import hmac_keys
from sentinel.net.cache import DiskCache, canonical_url, url_key


@pytest.fixture(autouse=True)
def _isolate_hmac_cache(tmp_path_factory: pytest.TempPathFactory) -> None:
    """Isolate each cache test's HMAC state from the session data dir.

    test_cache exercises key rotation via ``DiskCache.rotate_key()``, which
    rewrites ``$SENTINEL_DATA_DIR/cache.key`` — invalidating every HMAC-
    signed row the rest of the suite has already written (dangerous_actions,
    companion_rules, etc.).  We work around this by temporarily pointing
    ``SENTINEL_DATA_DIR`` at a per-test throw-away directory: rotations
    happen inside that sandbox and never leak back into the session's
    shared data dir.
    """
    sandbox = tmp_path_factory.mktemp("hmac-sandbox")
    prior = os.environ.get("SENTINEL_DATA_DIR")
    os.environ["SENTINEL_DATA_DIR"] = str(sandbox)
    hmac_keys._reset_cache()
    try:
        yield
    finally:
        hmac_keys._reset_cache()
        if prior is None:
            os.environ.pop("SENTINEL_DATA_DIR", None)
        else:
            os.environ["SENTINEL_DATA_DIR"] = prior


# ---------------------------------------------------------------------------
# canonical_url / url_key
# ---------------------------------------------------------------------------


class TestCanonicalUrl:
    def test_lowercases_scheme_and_host(self) -> None:
        assert canonical_url("HTTPS://Example.COM/a") == "https://example.com/a"

    def test_strips_default_port(self) -> None:
        assert canonical_url("https://example.com:443/") == "https://example.com/"
        assert canonical_url("http://example.com:80/") == "http://example.com/"

    def test_keeps_non_default_port(self) -> None:
        assert canonical_url("https://example.com:8443/") == "https://example.com:8443/"

    def test_drops_fragment(self) -> None:
        assert canonical_url("https://x.com/#anchor") == "https://x.com/"

    def test_url_key_is_deterministic(self) -> None:
        assert url_key("https://x.com/a") == url_key("https://x.com/a")
        assert url_key("https://x.com/a") != url_key("https://x.com/b")


# ---------------------------------------------------------------------------
# DiskCache basics
# ---------------------------------------------------------------------------


class TestDiskCacheBasics:
    def test_put_then_get_roundtrip(self, tmp_path: Path) -> None:
        cache = DiskCache(cache_dir=tmp_path)
        cache.put(
            url="https://example.com/",
            source="user_url",
            body=b"hello",
            headers={"Content-Type": "text/plain"},
            etag='"abc"',
        )
        entry = cache.get("https://example.com/", "user_url")
        assert entry is not None
        assert entry.body == b"hello"
        assert entry.etag == '"abc"'
        assert entry.source == "user_url"

    def test_get_missing_returns_none(self, tmp_path: Path) -> None:
        cache = DiskCache(cache_dir=tmp_path)
        assert cache.get("https://missing.example.com/", "user_url") is None

    def test_stats_counts_entries(self, tmp_path: Path) -> None:
        cache = DiskCache(cache_dir=tmp_path)
        cache.put("https://a.example/", "user_url", b"xxx")
        cache.put("https://b.example/", "user_url", b"yyy")
        stats = cache.stats()
        assert stats["count"] == 2
        assert stats["total_bytes"] > 0

    def test_purge_removes_all(self, tmp_path: Path) -> None:
        cache = DiskCache(cache_dir=tmp_path)
        cache.put("https://a.example/", "user_url", b"xxx")
        cache.put("https://b.example/", "user_url", b"yyy")
        assert cache.purge() == 2
        assert cache.stats()["count"] == 0

    def test_invalidate_one_entry(self, tmp_path: Path) -> None:
        cache = DiskCache(cache_dir=tmp_path)
        cache.put("https://a.example/", "user_url", b"xxx")
        cache.invalidate("https://a.example/")
        assert cache.get("https://a.example/", "user_url") is None


# ---------------------------------------------------------------------------
# HMAC integrity
# ---------------------------------------------------------------------------


class TestHmacIntegrity:
    def test_tampered_body_invalidates(self, tmp_path: Path) -> None:
        cache = DiskCache(cache_dir=tmp_path)
        cache.put("https://x.example/", "user_url", b"original")
        # Find the file and corrupt the body.
        files = list(tmp_path.glob("*.json"))
        assert len(files) == 1
        doc = json.loads(files[0].read_text())
        import base64

        doc["body_b64"] = base64.b64encode(b"tampered").decode("ascii")
        files[0].write_text(json.dumps(doc))
        assert cache.get("https://x.example/", "user_url") is None

    def test_tampered_etag_invalidates(self, tmp_path: Path) -> None:
        cache = DiskCache(cache_dir=tmp_path)
        cache.put("https://y.example/", "user_url", b"x", etag='"1"')
        files = list(tmp_path.glob("*.json"))
        doc = json.loads(files[0].read_text())
        doc["etag"] = '"2"'
        files[0].write_text(json.dumps(doc))
        assert cache.get("https://y.example/", "user_url") is None

    def test_corrupt_json_invalidates(self, tmp_path: Path) -> None:
        cache = DiskCache(cache_dir=tmp_path)
        cache.put("https://z.example/", "user_url", b"x")
        files = list(tmp_path.glob("*.json"))
        files[0].write_text("not-json{{{")
        assert cache.get("https://z.example/", "user_url") is None


# ---------------------------------------------------------------------------
# Amendment 6 Theme D — domain separation
# ---------------------------------------------------------------------------


class TestDomainSeparation:
    def test_cache_key_differs_from_db_key(self) -> None:
        """K_cache and K_db must derive different bytes from the same root."""
        hmac_keys._reset_cache()
        k_cache = hmac_keys.derive_cache_key()
        k_db = hmac_keys.derive_db_row_key()
        assert k_cache != k_db
        assert len(k_cache) == 32
        assert len(k_db) == 32

    def test_keys_stable_across_calls(self) -> None:
        hmac_keys._reset_cache()
        a = hmac_keys.derive_cache_key()
        b = hmac_keys.derive_cache_key()
        assert a == b

    def test_sign_row_rejects_included_hmac_column(self) -> None:
        with pytest.raises(ValueError, match="row_hmac"):
            hmac_keys.sign_row("t", ("pk",), {"row_hmac": "x"})

    def test_verify_row_roundtrip(self) -> None:
        cols = {"a": 1, "b": "two"}
        sig = hmac_keys.sign_row("mytable", ("pk1",), cols)
        assert hmac_keys.verify_row("mytable", ("pk1",), cols, sig)

    def test_verify_row_fails_on_tamper(self) -> None:
        sig = hmac_keys.sign_row("mytable", ("pk",), {"a": 1})
        assert not hmac_keys.verify_row("mytable", ("pk",), {"a": 2}, sig)


# ---------------------------------------------------------------------------
# Atomic write
# ---------------------------------------------------------------------------


class TestAtomicWrite:
    def test_no_tmp_leftovers_on_success(self, tmp_path: Path) -> None:
        cache = DiskCache(cache_dir=tmp_path)
        cache.put("https://a.example/", "user_url", b"x")
        # No .tmp files should remain.
        leftovers = list(tmp_path.glob("*.tmp"))
        assert leftovers == []

    def test_tmp_cleaned_on_rename_failure(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        cache = DiskCache(cache_dir=tmp_path)

        def boom(*_a, **_kw):
            raise OSError("simulated rename failure")

        monkeypatch.setattr(os, "replace", boom)
        # put() should swallow the write error (logged) and leave no tmp.
        cache.put("https://a.example/", "user_url", b"x")
        leftovers = list(tmp_path.glob(".sentinel-cache-*.tmp"))
        assert leftovers == []


# ---------------------------------------------------------------------------
# In-memory fallback
# ---------------------------------------------------------------------------


class TestInMemoryFallback:
    def test_falls_back_when_dir_unwritable(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Simulate an OSError on mkdir and assert the fallback works."""
        bad = tmp_path / "unwritable"

        with patch.object(Path, "mkdir", side_effect=OSError("read-only")):
            cache = DiskCache(cache_dir=bad)
        # Should still function end-to-end via in-memory.
        cache.put("https://x.example/", "user_url", b"hello")
        entry = cache.get("https://x.example/", "user_url")
        assert entry is not None
        assert entry.body == b"hello"


# ---------------------------------------------------------------------------
# TTL expiry
# ---------------------------------------------------------------------------


class TestTtlExpiry:
    def test_expired_entry_evicted(self, tmp_path: Path) -> None:
        cache = DiskCache(cache_dir=tmp_path)
        cache.put(
            "https://e.example/",
            "user_url",
            b"stale",
            ttl_seconds=1,
        )
        # Advance time past TTL.
        with patch("time.time", return_value=time.time() + 10):
            assert cache.get("https://e.example/", "user_url") is None

    def test_fresh_entry_returned(self, tmp_path: Path) -> None:
        cache = DiskCache(cache_dir=tmp_path)
        cache.put("https://f.example/", "user_url", b"fresh", ttl_seconds=3600)
        entry = cache.get("https://f.example/", "user_url")
        assert entry is not None
        assert entry.body == b"fresh"

    def test_ttl_for_source(self, tmp_path: Path) -> None:
        cache = DiskCache(cache_dir=tmp_path)
        assert cache.ttl_for("github") == 24 * 3600
        assert cache.ttl_for("aws_docs") == 168 * 3600
        assert cache.ttl_for("unknown") == cache.ttl_for("user_url")


# ---------------------------------------------------------------------------
# rotate_key
# ---------------------------------------------------------------------------


class TestRotateKey:
    def test_rotate_key_purges_and_old_entries_vanish(self, tmp_path: Path) -> None:
        cache = DiskCache(cache_dir=tmp_path)
        cache.put("https://r.example/", "user_url", b"pre-rotate")
        assert cache.get("https://r.example/", "user_url") is not None

        cache.rotate_key()
        # After rotation, the cache is empty (purged) and future entries use new key.
        assert cache.get("https://r.example/", "user_url") is None

        # New writes still work under the new key.
        cache.put("https://r2.example/", "user_url", b"post-rotate")
        assert cache.get("https://r2.example/", "user_url") is not None

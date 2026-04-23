"""HMAC key derivation for Sentinel — domain-separated sub-keys (Theme D).

Amendment 6 Theme D / NIST SP 800-108 KDF pattern.  The root key at
``$SENTINEL_DATA_DIR/cache.key`` is NEVER used directly.  Two sub-keys:

* ``K_cache = HMAC-SHA256(root, b"sentinel-v1/cache")`` — cache integrity.
* ``K_db    = HMAC-SHA256(root, b"sentinel-v1/db-row")`` — DB row signing.

Rationale: without domain separation, compromise of ``K_cache`` (low-trust
cache poisoning surface) would also unlock ``K_db`` (high-trust ReDoS
injection surface).  Derivation happens once per process and is cached in
module-level globals.

Phase 3 may relocate this module to ``src/sentinel/net/cache.py::_derive_keys``
once the ``net/`` package exists; for Phase 2 it lives at the top level.
"""

from __future__ import annotations

import hashlib
import hmac
import os
import secrets
import stat
import sys
from collections.abc import Mapping
from pathlib import Path

_ROOT_KEY_FILENAME = "cache.key"
_ROOT_KEY_SIZE = 32  # 256 bits.


class HMACError(Exception):
    """Raised on HMAC key load/sign failures.

    Dedicated exception class (not OSError/ValueError) so callers can
    discriminate: a broad-perms refuse-to-load at startup requires a
    rotate-key recovery, while an OSError on the key file means the FS
    is read-only (graceful in-memory degradation path).
    """

# Domain-separation labels.  "sentinel-v1/..." versions the KDF contract —
# bump the v1 prefix if the scheme ever changes (e.g., HKDF upgrade).
_LABEL_CACHE = b"sentinel-v1/cache"
_LABEL_DB = b"sentinel-v1/db-row"

# Process-lifetime cache for derived sub-keys.  Reset via ``_reset_cache()``
# in tests that monkey-patch SENTINEL_DATA_DIR mid-run.
_cache_sub_key: bytes | None = None
_db_sub_key: bytes | None = None
_root_key_cached: bytes | None = None


def _data_dir() -> Path:
    """Resolve ``$SENTINEL_DATA_DIR`` per § 5.4.

    Defaults to ``$XDG_DATA_HOME/sentinel/`` on POSIX or
    ``%LOCALAPPDATA%\\sentinel\\`` on Windows.  Falls back to
    ``~/.sentinel`` if neither is set.
    """
    env = os.environ.get("SENTINEL_DATA_DIR")
    if env:
        return Path(env)
    xdg = os.environ.get("XDG_DATA_HOME")
    if xdg:
        return Path(xdg) / "sentinel"
    if sys.platform == "win32":
        local = os.environ.get("LOCALAPPDATA")
        if local:
            return Path(local) / "sentinel"
    return Path.home() / ".sentinel"


def _load_or_create_root_key() -> bytes:
    """Load the 32-byte root key from disk, generating on first run.

    File mode is 0o600 (owner read/write only).  On POSIX this prevents
    other local users from reading the key; on Windows the POSIX bits are
    advisory but ``secrets.token_bytes`` still produces a cryptographically
    unpredictable key.

    Raises:
        OSError: If the data dir cannot be created or the key file cannot
            be written (read-only filesystem — cache layer falls back to
            in-memory mode per § 8.5 "Graceful degradation").
    """
    global _root_key_cached
    if _root_key_cached is not None:
        return _root_key_cached

    data_dir = _data_dir()
    data_dir.mkdir(parents=True, exist_ok=True)
    key_path = data_dir / _ROOT_KEY_FILENAME

    if key_path.exists():
        # P2-13 β — refuse to load on broad POSIX perms.  If the key file
        # was copied out, chmod'd world-readable, or written by a prior
        # run on a filesystem that silently dropped chmod (then later
        # migrated to a proper POSIX fs), treat it as compromised.
        # Windows-carve-out matches the _write_key precedent — chmod may
        # silently no-op on non-POSIX filesystems so perm bits aren't a
        # security signal there.
        if sys.platform != "win32":
            mode = key_path.stat().st_mode & 0o777
            if mode & 0o077:
                raise HMACError(
                    f"Key file {key_path} has mode {oct(mode)}; must be 0o600. "
                    f"Run 'sentinel cache rotate-key' to regenerate."
                )
        key = key_path.read_bytes()
        if len(key) != _ROOT_KEY_SIZE:
            # Phase 7.1 silent-failure B2: truncated/corrupted key with
            # HMAC-signed DB rows present would be silently regenerated,
            # invalidating every signed row without an ERROR event.
            # Fail loudly if the DB has signed rows; auto-regenerate only
            # on a truly first-install state (no DB / no signed rows).
            if _db_has_signed_rows(data_dir):
                raise HMACError(
                    f"Root key at {key_path} has unexpected size ({len(key)} bytes) "
                    f"but DB has signed rows.  Either restore the key or run "
                    f"'sentinel cache rotate-key' to fully reset."
                )
            print(
                f"[WARN] {key_path} has unexpected size ({len(key)} bytes); "
                f"regenerating.  No signed DB rows detected.",
                file=sys.stderr,
            )
            key = secrets.token_bytes(_ROOT_KEY_SIZE)
            _write_key(key_path, key)
    else:
        # Phase 7.1 silent-failure B2: if the key is missing but the DB
        # already has HMAC-signed rows, a fresh key would invalidate them
        # all without warning.  Fail loudly with recovery instructions.
        # Auto-generate only on a genuinely first-install state.
        if _db_has_signed_rows(data_dir):
            raise HMACError(
                f"Root key at {key_path} is missing but DB has signed rows.  "
                f"Either restore the key or run 'sentinel cache rotate-key' "
                f"to fully reset."
            )
        key = secrets.token_bytes(_ROOT_KEY_SIZE)
        _write_key(key_path, key)

    _root_key_cached = key
    return key


def _db_has_signed_rows(data_dir: Path) -> bool:
    """Probe for HMAC-signed rows in the IAM DB co-located with the key.

    Returns True if any row in dangerous_actions / companion_rules /
    dangerous_combinations / managed_policies carries a non-null HMAC
    signature.  Returns False on a first-install state: no DB file, or
    DB exists but the signed tables haven't been created yet.

    Probes ONLY ``data_dir / iam_actions.db`` — the key's sibling DB.
    A DB at another location (e.g. a developer's repo checkout used by
    the test suite) is irrelevant: the key that signs it lives in the
    data_dir of whichever SENTINEL_DATA_DIR seeded it.  This scope match
    keeps the test-harness (fresh data_dir, external DB) working while
    still catching the real failure mode (persistent data_dir, key
    deleted, signed DB left behind).

    Never raises: the probe MUST NOT itself abort the key-load path on
    a missing-table or corrupt-DB error — the upstream caller will then
    fail-closed at DB use time with a clearer error.  A DB error here
    yields False (treat as "first install" for the auto-gen decision),
    and the downstream HMAC load will still detect tampering via the
    row_hmac check.
    """
    import sqlite3

    db_path = data_dir / "iam_actions.db"
    if not db_path.exists():
        return False
    try:
        # Read-only URI so we never lock or write.
        uri = f"file:{db_path}?mode=ro"
        with sqlite3.connect(uri, uri=True, timeout=0.5) as conn:
            # Tables with row_hmac / policy_document_hmac columns per
            # Theme D design.  Missing tables -> treat as first install.
            for table, hmac_col in (
                ("dangerous_actions", "row_hmac"),
                ("companion_rules", "row_hmac"),
                ("dangerous_combinations", "row_hmac"),
                ("managed_policies", "policy_document_hmac"),
            ):
                try:
                    cur = conn.execute(
                        f'SELECT 1 FROM "{table}" '
                        f'WHERE "{hmac_col}" IS NOT NULL LIMIT 1'
                    )
                    if cur.fetchone() is not None:
                        return True
                except sqlite3.Error:
                    # Missing table or missing column: not yet seeded.
                    continue
    except sqlite3.Error:
        # DB file exists but unreadable / corrupted: upstream will catch
        # this at use time.  Treat as first install for key auto-gen
        # purposes (the DB-load path will still fail-closed with a
        # clearer error if the key was recently regenerated).
        return False
    return False


def _write_key(path: Path, key: bytes) -> None:
    """Write ``key`` with mode 0o600.  POSIX-tight; Windows-best-effort."""
    path.write_bytes(key)
    try:
        os.chmod(path, stat.S_IRUSR | stat.S_IWUSR)
    except OSError:
        # Windows without ACL support — `chmod` may be a no-op.  Best-effort.
        pass


def _derive(label: bytes) -> bytes:
    """Derive a sub-key: ``HMAC-SHA256(root_key, label)``."""
    root = _load_or_create_root_key()
    return hmac.new(root, label, hashlib.sha256).digest()


def derive_cache_key() -> bytes:
    """Return ``K_cache`` (cached per-process)."""
    global _cache_sub_key
    if _cache_sub_key is None:
        _cache_sub_key = _derive(_LABEL_CACHE)
    return _cache_sub_key


def derive_db_row_key() -> bytes:
    """Return ``K_db`` (cached per-process)."""
    global _db_sub_key
    if _db_sub_key is None:
        _db_sub_key = _derive(_LABEL_DB)
    return _db_sub_key


def sign_row(table: str, pk: tuple[str, ...], columns: Mapping[str, object]) -> str:
    """Compute the HMAC-SHA256 hex digest for a DB row.

    Binds the table name + primary-key tuple + all signed columns so an
    attacker swapping rows between tables or rekeying fails verification.
    Excludes the ``row_hmac`` column itself from the signature input (it's
    the output).

    Args:
        table: SQL table name (e.g. ``"dangerous_actions"``).
        pk: Primary-key values in schema-declared order, stringified.
        columns: All OTHER columns (``row_hmac`` must NOT be present).

    Returns:
        Hex digest — 64 chars for SHA-256.
    """
    if "row_hmac" in columns:
        raise ValueError("columns must not include 'row_hmac' — it's the output")

    # Canonical serialization: sort keys, use \x1f (unit separator) and
    # \x1e (record separator) so no column value can collide with a
    # delimiter by accident.
    parts: list[bytes] = [table.encode("utf-8")]
    parts.extend(str(v).encode("utf-8") for v in pk)
    for k in sorted(columns.keys()):
        parts.append(k.encode("utf-8"))
        parts.append(b"\x1f")
        parts.append(str(columns[k]).encode("utf-8"))
        parts.append(b"\x1e")

    msg = b"\x1e".join(parts)
    key = derive_db_row_key()
    return hmac.new(key, msg, hashlib.sha256).hexdigest()


def verify_row(
    table: str,
    pk: tuple[str, ...],
    columns: Mapping[str, object],
    expected_hmac: str,
) -> bool:
    """Constant-time verify a row's HMAC.  False on any mismatch or error."""
    try:
        computed = sign_row(table, pk, columns)
    except ValueError:
        return False
    return hmac.compare_digest(computed, expected_hmac)


def regenerate_root_key() -> bytes:
    """Wipe and regenerate the root key on disk; reset in-memory derivations.

    Called by :meth:`sentinel.net.cache.DiskCache.rotate_key` — never
    call this without first purging any HMAC-dependent stores (cache
    entries, DB row signatures) that were signed with the OLD key, or
    they will all fail verification after rotation.

    Returns:
        The new 32-byte root key (mainly for test introspection).

    Raises:
        OSError: If the data dir / key file cannot be written — caller
            must not assume rotation succeeded.
    """
    global _root_key_cached, _cache_sub_key, _db_sub_key
    data_dir = _data_dir()
    data_dir.mkdir(parents=True, exist_ok=True)
    key_path = data_dir / _ROOT_KEY_FILENAME
    new_key = secrets.token_bytes(_ROOT_KEY_SIZE)
    _write_key(key_path, new_key)
    _root_key_cached = new_key
    _cache_sub_key = None
    _db_sub_key = None
    return new_key


def _reset_cache() -> None:
    """Test-only: clear memoized root key + derived sub-keys.

    Required when a fixture rotates ``SENTINEL_DATA_DIR`` mid-session —
    without this, the first-call derivation latches the wrong key.
    """
    global _root_key_cached, _cache_sub_key, _db_sub_key
    _root_key_cached = None
    _cache_sub_key = None
    _db_sub_key = None


__all__ = [
    "derive_cache_key",
    "derive_db_row_key",
    "regenerate_root_key",
    "sign_row",
    "verify_row",
]

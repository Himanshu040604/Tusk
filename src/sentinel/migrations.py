"""Alembic auto-upgrade + WAL activation for Sentinel CLI startup.

Implements § 6.3 of ``prod_imp.md``: the migration check runs at CLI entry
(not in ``Database.__init__``) so test fixtures and library users can
construct throw-away ``Database()`` instances without triggering migrations.

Key behaviors:

* **Dual-DB** (M18): processes ``iam_actions.db`` unconditionally; processes
  ``resource_inventory.db`` only if the file exists on disk (inventory is
  opt-in).
* **Safe-stamp branch** (§ 6.3): pre-Alembic DBs with data tables but no
  ``alembic_version`` table are stamped at HEAD instead of upgraded —
  one-time migration for existing users.
* **File locking** (C5): per-DB ``filelock.FileLock(<db>.migrate.lock)``
  with 60s timeout.  Inside the lock we double-check version before
  upgrading (another process may have upgraded while we waited).
* **Pre-migration backup** (H5/H27): ``PRAGMA wal_checkpoint(FULL)`` then
  ``shutil.copy2`` before ``upgrade``.  Delete on success, keep on
  failure with stderr restore instructions.
* **WAL activation** (H27): ``PRAGMA journal_mode=WAL`` +
  ``PRAGMA synchronous=NORMAL`` on first read-write open.  Persistent —
  no-op on subsequent runs.
* **Skip paths**: ``SENTINEL_SKIP_MIGRATIONS=1`` env var, ``--skip-migrations``
  CLI flag, or ``skip=True`` programmatic call emit a loud stderr ``[WARN]``
  and return.
"""

from __future__ import annotations

import logging
import os
import shutil
import sqlite3
import sys
from pathlib import Path

import sqlalchemy.exc
from alembic import command
from alembic.config import Config
from alembic.runtime.migration import MigrationContext
from alembic.script import ScriptDirectory

logger = logging.getLogger(__name__)

# 60s per § 6.3.  Exposed for test monkeypatching.
FILELOCK_TIMEOUT_SECONDS = 60


def _project_root() -> Path:
    """Repository root — where alembic.ini lives.

    Walks upward from this file so the module works both in a dev checkout
    (``src/sentinel/migrations.py``) and in a wheel install (``alembic.ini``
    shipped alongside).  Falls back to ``os.getcwd()`` if no ``alembic.ini``
    is found (defensive; shouldn't happen in practice because ``pyproject``
    declares it in sdist include).
    """
    here = Path(__file__).resolve()
    for parent in (here.parent, *here.parents):
        if (parent / "alembic.ini").exists():
            return parent
    return Path.cwd()


def _make_config(db_path: Path, config_section: str) -> Config:
    """Build an Alembic Config pointing at ``db_path`` with absolute URL.

    The ini-file's relative ``sqlalchemy.url`` is overridden so invocations
    work regardless of the caller's cwd.  ``config_section`` picks between
    ``iam`` and ``inventory`` sub-configs.
    """
    root = _project_root()
    ini_path = root / "alembic.ini"
    cfg = Config(str(ini_path), ini_section=f"alembic:{config_section}")
    # Override URL to absolute path so cwd doesn't matter.
    cfg.set_main_option("sqlalchemy.url", f"sqlite:///{db_path.resolve()}")
    # Override script_location to absolute path too.
    cfg.set_main_option("script_location", str(root / "migrations" / config_section))
    return cfg


def _current_revision(db_path: Path) -> str | None:
    """Return the current Alembic revision of ``db_path``, or None.

    None means either (a) the DB file is empty/missing, or (b) the DB has
    data tables but no ``alembic_version`` — triggering the safe-stamp
    branch in ``_upgrade_single_db``.

    Uses a SQLAlchemy engine (not raw ``sqlite3.Connection``) because
    Alembic's ``MigrationContext.configure`` requires a SQLAlchemy
    ``Connection`` with a ``.dialect`` attribute.  Passing a raw sqlite3
    connection raises ``AttributeError: 'sqlite3.Connection' object has
    no attribute 'dialect'`` at CLI startup.
    """
    if not db_path.exists():
        return None
    # Lazy import — SQLAlchemy is already a transitive dep via alembic.
    from sqlalchemy import create_engine

    # Read-only URI so we don't accidentally acquire a write lock.
    url = f"sqlite:///file:{db_path.resolve()}?mode=ro&uri=true"
    try:
        engine = create_engine(url)
    except (OSError, sqlalchemy.exc.OperationalError) as exc:
        # Narrow per Architect Concern 2 (v0.6.2): engine-creation failure
        # (DB absent or OS-level I/O) should not mask other runtime errors.
        logger.debug("_current_revision: create_engine failed for %s: %s", db_path, exc)
        return None
    try:
        with engine.connect() as conn:
            ctx = MigrationContext.configure(conn)
            return ctx.get_current_revision()
    except (sqlalchemy.exc.OperationalError, sqlalchemy.exc.DatabaseError) as exc:
        # Narrow per Architect Concern 2 (v0.6.2): MigrationContext.configure /
        # get_current_revision failure is logged so operators have forensic
        # signal instead of silently returning None.
        logger.debug(
            "_current_revision: failed to query revision for %s: %s", db_path, exc
        )
        return None
    finally:
        engine.dispose()


def _db_has_tables(db_path: Path) -> bool:
    """True if the DB file contains at least one user table."""
    if not db_path.exists():
        return False
    try:
        conn = sqlite3.connect(f"file:{db_path.resolve()}?mode=ro", uri=True)
    except sqlite3.Error:
        return False
    try:
        row = conn.execute(
            "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name != 'alembic_version'"
        ).fetchone()
        return bool(row and row[0] > 0)
    finally:
        conn.close()


# P0-2 γ — Fail-closed table verification.
#
# Phase 2 introduced 7 tables that the analyzer/rewriter bulk-load at startup.
# If the Alembic head says 0008+ but the DB was safe-stamped from a pre-Alembic
# install that only had Phase-1 tables, these tables will be missing silently.
# Combined with the previous fail-open bulk-load (`except Exception: return
# False`), the tool would produce zero findings on a broken DB.
#
# Option C (fail-closed): at startup, after migrations settle, verify the
# expected Phase-2 tables are present.  If any are missing, abort with a
# clear recovery message.
_PHASE2_EXPECTED_TABLES: frozenset[str] = frozenset({
    "dangerous_actions",
    "companion_rules",
    "dangerous_combinations",
    "action_resource_map",
    "arn_templates",
    "managed_policies",
    "verb_prefixes",
})


def _phase2_missing_tables(db_path: Path) -> list[str]:
    """Return the sorted list of expected Phase-2 tables absent from ``db_path``.

    Returns ``[]`` if all expected tables are present or the DB is not the
    IAM DB (Phase-2 tables only live on iam_actions.db — inventory DB has
    its own schema).  Uses a read-only URI so no WAL interaction.
    """
    if not db_path.exists():
        return []
    try:
        conn = sqlite3.connect(f"file:{db_path.resolve()}?mode=ro", uri=True)
    except sqlite3.Error:
        return []
    try:
        existing = {
            r[0] for r in conn.execute(
                "SELECT name FROM sqlite_master WHERE type='table'"
            ).fetchall()
        }
        return sorted(_PHASE2_EXPECTED_TABLES - existing)
    finally:
        conn.close()


def verify_phase2_tables(db_path: Path) -> None:
    """P0-2 γ — abort with recovery message if expected Phase-2 tables missing.

    Called from ``check_and_upgrade_all_dbs`` after the per-DB upgrade/stamp
    branches settle.  Only runs against the IAM DB (caller wires this only
    for ``iam_actions.db`` — inventory DB skips).

    Raises:
        DatabaseError: DB is stamped at Alembic head but is missing one or
            more Phase-2 tables.  Exit code EXIT_IO_ERROR (3) when the
            caller catches.
    """
    from .database import DatabaseError

    missing = _phase2_missing_tables(db_path)
    if not missing:
        return
    current = _current_revision(db_path) or "<unstamped>"
    raise DatabaseError(
        f"DB is stamped at {current} but missing expected tables: {missing}. "
        f"Recovery: delete {db_path} and re-run 'sentinel info' to rebuild from scratch."
    )


def _head_revision(cfg: Config) -> str | None:
    """Return Alembic HEAD revision for the given config."""
    script = ScriptDirectory.from_config(cfg)
    head = script.get_current_head()
    return head


def _activate_wal(db_path: Path) -> None:
    """Set WAL journal mode and NORMAL synchronous on first read-write open.

    These pragmas are persistent — SQLite writes them into the file header.
    Safe to call repeatedly; no-op on already-WAL databases.
    """
    conn = sqlite3.connect(str(db_path))
    try:
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA synchronous=NORMAL")
        conn.commit()
    finally:
        conn.close()


def _checkpoint_and_backup(db_path: Path) -> Path:
    """Checkpoint WAL into the main DB file, then snapshot via shutil.copy2.

    Returns the path to the backup file (``<db>.bak``).  H5/H27: checkpoint
    first so the backup actually contains the latest writes (WAL sidecar
    would otherwise hold uncommitted pages invisible to copy2).

    Raises:
        PermissionError: On read-only filesystems (Docker :ro).  Caller
            maps this to EXIT_IO_ERROR with SENTINEL_SKIP_MIGRATIONS hint.
    """
    conn = sqlite3.connect(str(db_path))
    try:
        conn.execute("PRAGMA wal_checkpoint(FULL)")
        conn.commit()
    finally:
        conn.close()
    bak = db_path.with_suffix(db_path.suffix + ".bak")
    shutil.copy2(db_path, bak)
    return bak


def _upgrade_single_db(
    db_path: Path,
    config_section: str,
) -> None:
    """Run the full upgrade flow for a single DB (acquires filelock)."""
    # Import filelock lazily — keeps module import cheap for `sentinel --version`.
    from filelock import FileLock, Timeout as FileLockTimeout

    lock_path = db_path.with_suffix(db_path.suffix + ".migrate.lock")
    lock = FileLock(str(lock_path), timeout=FILELOCK_TIMEOUT_SECONDS)

    try:
        with lock:
            _upgrade_locked(db_path, config_section)
    except FileLockTimeout:
        print(
            f"[ERROR] Another Sentinel migration is already in progress on {db_path}.\n"
            f"        If stuck, manually delete: {lock_path}",
            file=sys.stderr,
        )
        raise


def _upgrade_locked(db_path: Path, config_section: str) -> None:
    """Inside the filelock: probe revision, double-check, upgrade/stamp."""
    cfg = _make_config(db_path, config_section)
    head = _head_revision(cfg)
    current = _current_revision(db_path)

    # Branch 1: Up-to-date — return fast.
    if current is not None and current == head:
        return

    # Activate WAL mode BEFORE anything else writes to the DB.  Idempotent.
    # This must land before Task 4's BEGIN IMMEDIATE populate transactions
    # (see § 6.4 / M16 ordering fix).
    db_path.parent.mkdir(parents=True, exist_ok=True)
    _activate_wal(db_path)

    # Branch 2: Pre-Alembic DB with data tables — safe-stamp at head.
    if current is None and _db_has_tables(db_path):
        print(
            f"[INFO] Stamping pre-Alembic database at HEAD ({head}): {db_path}",
            file=sys.stderr,
        )
        command.stamp(cfg, "head")
        return

    # Branch 3: Empty DB or DB behind head — back up, upgrade.
    bak: Path | None = None
    if db_path.exists() and _db_has_tables(db_path):
        try:
            bak = _checkpoint_and_backup(db_path)
        except PermissionError as e:
            raise OSError(
                f"Cannot create pre-migration backup of {db_path} "
                f"(read-only filesystem?).  Set SENTINEL_SKIP_MIGRATIONS=1 to bypass."
            ) from e

    try:
        print(
            f"[INFO] Upgrading database from revision {current or '<empty>'} to {head}: {db_path}",
            file=sys.stderr,
        )
        command.upgrade(cfg, "head")
    except Exception:
        if bak is not None:
            print(
                f"[ERROR] Migration failed.  Restore via:\n        cp {bak} {db_path}",
                file=sys.stderr,
            )
        raise
    else:
        # Success — delete the backup.
        if bak is not None and bak.exists():
            bak.unlink()


def check_and_upgrade_all_dbs(
    iam_db_path: Path,
    inventory_db_path: Path | None = None,
    skip: bool = False,
) -> None:
    """Check both Sentinel DBs and upgrade to head if needed.

    Processes ``iam_actions.db`` unconditionally.  Processes
    ``resource_inventory.db`` only if ``inventory_db_path`` is provided AND
    the file exists on disk (inventory is an opt-in feature).

    Args:
        iam_db_path: Path to the IAM actions database.
        inventory_db_path: Optional path to the inventory database.
        skip: If True, emit loud ``[WARN]`` and return without checking.
            Also honored via ``SENTINEL_SKIP_MIGRATIONS=1`` env var (loud
            warn variant per Amendment 6 Theme F3).

    Raises:
        FileLockTimeout: If another process holds the migration lock longer
            than ``FILELOCK_TIMEOUT_SECONDS``.
        OSError: On read-only filesystems (pre-migration backup fails).
    """
    env_skip = os.environ.get("SENTINEL_SKIP_MIGRATIONS", "").strip() == "1"
    if skip or env_skip:
        reason = "SENTINEL_SKIP_MIGRATIONS=1" if env_skip else "--skip-migrations"
        print(
            f"[WARN] Skipping Alembic auto-upgrade ({reason}).  Schema may be behind HEAD.",
            file=sys.stderr,
        )
        return

    _upgrade_single_db(iam_db_path, "iam")

    # P0-2 γ — after migrations/stamp settle, verify Phase-2 tables exist.
    # Catches the mis-stamped-DB case (DB stamped at 0008+ but only has
    # Phase-1 tables) which the safe-stamp branch would otherwise let slide.
    # Only enforced on the IAM DB — inventory DB has its own schema.
    verify_phase2_tables(iam_db_path)

    if inventory_db_path is not None and inventory_db_path.exists():
        _upgrade_single_db(inventory_db_path, "inventory")


# Backwards-compat alias — some internal callers may still use the
# pre-M18 single-DB name.
def check_and_upgrade_db(db_path: Path, skip: bool = False) -> None:
    """Deprecated: call ``check_and_upgrade_all_dbs`` instead.

    Kept for demo.py and any single-DB library caller that lands before
    the full dual-DB wiring.  Forwards to the IAM-only path.
    """
    check_and_upgrade_all_dbs(db_path, None, skip=skip)


__all__ = [
    "FILELOCK_TIMEOUT_SECONDS",
    "check_and_upgrade_all_dbs",
    "check_and_upgrade_db",
    "verify_phase2_tables",
]

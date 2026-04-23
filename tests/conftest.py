"""Shared pytest fixtures and helpers for the IAM Policy Sentinel test suite.

This conftest implements Phase 1.5 test-infrastructure prep described in
``prod_imp.md`` § 12 Phase 1.5.  Goals:

* Make the suite safe for ``pytest-xdist`` parallel execution before Phase 2
  introduces ``.migrate.lock``, ``cache.key``, and WAL sidecar files that
  create per-worker shared-state contention.
* Provide shared fixture helpers (``make_test_db``, ``signed_db_row``)
  consumed by Phase 2 Task 0's large-scale test-site sweep.
* Provide the L6 ``_known_services()`` cache-clear autouse fixture (Task 5)
  that lands atomically with the parser.py lazy-loader refactor.

Phase 2 will extend this module with migration-aware fixtures and filelock
timeout handling.  See individual TODO markers for details.
"""

from __future__ import annotations

import os
import shutil
from pathlib import Path
from typing import Iterator, Optional

import pytest


# ---------------------------------------------------------------------------
# Task 1 — Per-worker SENTINEL_DATA_DIR
# ---------------------------------------------------------------------------


@pytest.fixture(autouse=True, scope="session")
def _sentinel_data_dir_per_worker(
    tmp_path_factory: pytest.TempPathFactory,
    worker_id: str,
) -> Iterator[Path]:
    """Set ``SENTINEL_DATA_DIR`` to a SHARED session-scoped temp directory.

    Post-P0-1 α / P0-2 γ note: after Group A, the shared
    ``data/iam_actions.db`` is HMAC-verified at bulk-load time.  Previously
    the fixture created a per-worker SENTINEL_DATA_DIR so each worker had
    its own ``cache.key``; but the IAM DB on disk is SHARED across workers.
    Under xdist parallelism that creates an unresolvable race: whichever
    worker seeded the DB first wins, and every other worker sees HMAC
    mismatch at bulk-load time (previously hidden by the fail-open
    ``except Exception: return False`` that P0-1 α removed).

    Fix: all workers now share a single SENTINEL_DATA_DIR rooted under the
    pytest session's tmp root.  ``tmp_path_factory.getbasetemp()`` resolves
    to ``pytest-NN`` (parent of per-worker ``popen-gwN``) under xdist, so
    every worker points at the same directory.  Per-worker isolation for
    the L6 ``_known_services`` cache remains intact (that's a module-level
    Python cache, not filesystem state).

    Under serial execution (``worker_id == "master"``) the base temp IS the
    worker temp — same file; semantics unchanged.

    The shared dir is ALSO seeded with a fresh ``data/iam_actions.db`` once
    at session start so the HMAC-signed rows match the shared key.  The
    first worker to acquire the filelock rebuilds; subsequent workers see
    HEAD revision and skip.
    """
    base = tmp_path_factory.getbasetemp()
    # getbasetemp() resolves differently per worker under xdist (each has
    # its own numbered subdir).  Walk up to the pytest-NN root.
    if base.name.startswith("popen-gw"):
        base = base.parent
    data_dir = base / "sentinel-shared"
    data_dir.mkdir(parents=True, exist_ok=True)
    prior = os.environ.get("SENTINEL_DATA_DIR")
    os.environ["SENTINEL_DATA_DIR"] = str(data_dir)
    # Clear any cached HMAC sub-keys that depend on the previous data dir.
    try:
        from sentinel.hmac_keys import _reset_cache as _hk_reset

        _hk_reset()
    except ImportError:
        pass  # Phase 1.5 pre-Phase-2 compatibility

    # Rebuild the default shared DB in-place so the row HMACs match the
    # shared key.  Filelock inside check_and_upgrade_all_dbs serializes
    # concurrent rebuilds; seed_all_baseline is idempotent (DELETE+INSERT).
    try:
        from pathlib import Path as _P

        from sentinel.migrations import check_and_upgrade_all_dbs
        from sentinel.seed_data import seed_all_baseline

        _default_db = _P(__file__).resolve().parent.parent / "data" / "iam_actions.db"
        _default_db.parent.mkdir(parents=True, exist_ok=True)
        check_and_upgrade_all_dbs(_default_db, None)
        seed_all_baseline(_default_db)
    except Exception:
        # Best-effort — tests that don't need the shared DB will still pass.
        # Tests that do will surface the error explicitly via their own path.
        pass

    try:
        yield data_dir
    finally:
        if prior is None:
            os.environ.pop("SENTINEL_DATA_DIR", None)
        else:
            os.environ["SENTINEL_DATA_DIR"] = prior


# ---------------------------------------------------------------------------
# Task 2 — Session-scoped migration fixture (STUB — see TODO for Phase 2)
# ---------------------------------------------------------------------------

# TODO(Phase 2): wrap check_and_upgrade_db() calls in try/except FileLockTimeout
# and fail the individual test with a clear stderr message rather than letting
# the xdist worker crash. Nothing to wire in Phase 1.5 because filelock usage
# starts in Phase 2.


@pytest.fixture(scope="session")
def migrated_db_template(
    tmp_path_factory: pytest.TempPathFactory,
    worker_id: str,
) -> Path:
    """Create one stamped-at-head DB template per xdist worker session.

    Individual tests get a fast ``shutil.copy2`` of this template into their
    own ``tmp_path``, avoiding N tests * 519 per-test migration cost once
    Alembic migrations land in Phase 2.

    Phase 1.5 stub: no migrations exist yet, so we only create a plain
    unstamped schema via ``Database(path).create_schema()``.  The Phase 2
    follow-up replaces the stub body with ``check_and_upgrade_db(path)``
    to stamp the template at the current Alembic HEAD revision.

    Returns:
        Path to the on-disk template DB (session-lived, per-worker).
    """
    # TODO(Phase 2 Task 5): once migrations.py exists, call
    # check_and_upgrade_db(path) here to stamp the template at the Alembic HEAD
    # revision. Then individual tests get a fast shutil.copy2 of the stamped
    # template, avoiding N × 519 per-test migration cost.
    from sentinel.database import Database

    template_dir = tmp_path_factory.mktemp(f"db-template-{worker_id}")
    path = template_dir / "template.db"
    Database(path).create_schema()
    return path


# ---------------------------------------------------------------------------
# Task 4 — Shared fixture helpers
# ---------------------------------------------------------------------------


def make_test_db(tmp_path: Path, *, seed: bool = True) -> Path:
    """Create a fresh Phase-2-ready test DB in ``tmp_path`` and return its path.

    Phase 2 Task 0 evolution of the original helper.  Beyond
    ``create_schema()`` it also:

    1. Runs ``check_and_upgrade_all_dbs(path)`` to stamp / upgrade to
       Alembic HEAD so the Phase 2 tables (``dangerous_actions``,
       ``companion_rules``, ``action_resource_map``, ``arn_templates``)
       exist.  Without this, tests that rely on the bulk-load path hit
       the "table missing" branch and silently fall through to the
       class-constant fallback — which Task 8 deletes.
    2. Calls ``seed_all_baseline(path)`` to populate shipped baseline
       rows.  Required because after Task 8 the fallback path is gone
       and ``RiskAnalyzer`` / ``CompanionPermissionDetector`` only
       find content via the DB.

    Args:
        tmp_path: per-test temp directory (pytest ``tmp_path`` fixture).
        seed: If False, skip ``seed_all_baseline`` — for tests that
            specifically exercise the empty-table bulk-load path.

    Returns:
        Absolute path to a migrated (+ optionally seeded) SQLite DB.
    """
    from sentinel.migrations import check_and_upgrade_all_dbs
    from sentinel.seed_data import seed_all_baseline

    path = tmp_path / "test.db"
    # IMPORTANT: do NOT call Database(path).create_schema() here.  That would
    # create Phase-1 tables first, which flips _db_has_tables() to True and
    # forces migrations.py into the safe-stamp branch (Branch 2) — stamping
    # HEAD without running any upgrade().  Phase 2 tables
    # (dangerous_actions, companion_rules, action_resource_map, arn_templates,
    # verb_prefixes, managed_policies) would never be created, causing
    # seed_all_baseline to crash with "no such table: dangerous_actions".
    #
    # Instead, leave the path empty.  check_and_upgrade_all_dbs falls into
    # Branch 3 (empty/behind-head), runs command.upgrade(cfg, "head") which
    # executes every IAM migration in order and builds the full schema
    # (Phase 1 + Phase 2 tables together).  Alembic's env.py handles creating
    # the SQLite file on first connection, so we don't need to touch() it.
    check_and_upgrade_all_dbs(path, None)
    if seed:
        seed_all_baseline(path)
    return path


def signed_db_row(*_args, **_kwargs) -> dict:  # type: ignore[no-untyped-def]
    """Return a dict containing a DB row plus a correct ``row_hmac`` column.

    Stub for Phase 2 Task 6a (HMAC row signing).  The eventual signature is::

        def signed_db_row(
            table: str,
            pk: tuple,
            data: Mapping[str, object],
            *,
            key: Optional[bytes] = None,
        ) -> dict

    — it will derive the per-install HMAC key from
    ``$SENTINEL_DATA_DIR/cache.key`` (or the ``key`` override) and return
    ``{**data, "row_hmac": <hex digest>}`` ready for ``INSERT`` in test
    fixtures.  Phase 1.5 ships only the import-surface stub so Phase 2 Task
    6a can land without churning every test file.

    Raises:
        NotImplementedError: always — implementation deferred to Phase 2
            Task 6a.  See ``prod_imp.md`` § 12 Phase 2 Task 6a.
    """
    raise NotImplementedError(
        "signed_db_row: pending Phase 2 Task 6a HMAC implementation — "
        "see prod_imp.md § 12 Phase 2 Task 6a"
    )


# ---------------------------------------------------------------------------
# Task 5 — L6 cache-isolation autouse fixture
# ---------------------------------------------------------------------------


@pytest.fixture(autouse=True)
def _clear_known_services_cache() -> Iterator[None]:
    """Clear ``parser._known_services.cache`` after every test.

    The ``@functools.cache`` on ``parser._known_services()`` reads
    ``Settings`` once at first call and caches the frozenset across the
    process lifetime (L6 lazy-loader pattern).  When a test monkey-patches
    ``get_settings()`` or mutates ``Settings.intent.known_services``, the
    cached frozenset must be invalidated — otherwise the NEXT test sees the
    previous test's stale Settings snapshot.  Function-scope `yield`-then-
    `cache_clear()` is exactly the right shape: teardown runs post-test,
    so the next test starts with a cold cache.

    This fixture MUST ship in the same commit as the lazy-loader replacement
    in ``parser.py`` — see ``prod_imp.md`` § 12 Phase 1 Task 10 atomic
    commit constraint.  Landing the loader alone causes silent test-isolation
    rot under pytest-xdist.
    """
    yield
    # Import inside the fixture so that collection-time errors here don't
    # cascade into every unrelated test failure.
    from sentinel.parser import _known_services

    _known_services.cache_clear()


__all__ = [
    "make_test_db",
    "signed_db_row",
    "migrated_db_template",
]

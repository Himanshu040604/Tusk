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
    """Set ``SENTINEL_DATA_DIR`` to a per-xdist-worker temp directory.

    Prevents D4 HMAC-key races and L6 cache-key contention when Phase 2
    introduces ``$SENTINEL_DATA_DIR/cache.key`` as a shared file.  Under
    serial execution (no xdist), ``worker_id`` falls back to ``"master"``
    per the standard pytest-xdist convention — the fixture still runs and
    isolates the data dir from the user's real ``~/.sentinel`` (or whatever
    the production default resolves to).

    The prior env-var value is captured and restored on teardown so that
    tests which explicitly override ``SENTINEL_DATA_DIR`` in a subprocess
    still see a clean pre-test state after the session ends.
    """
    data_dir = tmp_path_factory.mktemp(f"sentinel-{worker_id}")
    prior = os.environ.get("SENTINEL_DATA_DIR")
    os.environ["SENTINEL_DATA_DIR"] = str(data_dir)
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


def make_test_db(tmp_path: Path) -> Path:
    """Create a fresh test database in ``tmp_path`` and return its path.

    Drop-in replacement for the existing idiom::

        db = Database(tmp_path / "test.db")
        db.create_schema()

    Centralizes the pattern so that Phase 2 Task 0 can migrate the 99 call
    sites flagged by the D-investigation Agent 3 grep in one sweep.  Not a
    pytest fixture — a plain helper so existing tests can adopt it with a
    single ``from tests.conftest import make_test_db`` import change.

    Args:
        tmp_path: per-test temp directory (typically the pytest ``tmp_path``
            fixture).

    Returns:
        Absolute path to a freshly-schema'd SQLite DB at
        ``tmp_path / "test.db"``.
    """
    from sentinel.database import Database

    path = tmp_path / "test.db"
    Database(path).create_schema()
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


__all__ = [
    "make_test_db",
    "signed_db_row",
    "migrated_db_template",
]

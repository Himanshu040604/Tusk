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
from typing import Iterator

import pytest


# ---------------------------------------------------------------------------
# Task 1 — Per-worker SENTINEL_DATA_DIR
# ---------------------------------------------------------------------------


@pytest.fixture(autouse=True, scope="session")
def _sentinel_data_dir_per_worker(
    tmp_path_factory: pytest.TempPathFactory,
    worker_id: str,
) -> Iterator[Path]:
    """Set ``SENTINEL_DATA_DIR`` to a per-worker, session-scoped temp directory.

    **v0.7.0 (Phase 7.3) restructure — retires v0.6.1 Deviation 2.**

    Earlier versions (v0.6.1, v0.6.2) shared a single ``SENTINEL_DATA_DIR``
    across all xdist workers in a session because tests mutated a shared
    ``data/iam_actions.db`` at the repo root.  That workaround created two
    classes of fragility:

    * HMAC-cache pollution between tests on the same worker (mitigated but
      not fully fixed by the v0.6.2 ``_reset_hmac_cache_after_test`` autouse).
    * Shared on-disk DB state — serial-mode runs exhibited 11 failing CLI
      tests because a prior test rebuilt the shared DB under a monkey-patched
      K_db that didn't match the session K_db (see
      phase7_2_postship_review_tests.md).

    With the template-backed ``make_test_db`` adoption sweep in Phase 7.3,
    every CLI-path test now gets its OWN DB via fast-copy from
    ``migrated_db_template``.  No test writes to the shared
    ``data/iam_actions.db`` in the repo root.  We can therefore restore
    per-worker ``SENTINEL_DATA_DIR`` isolation as originally designed in
    ``prod_imp.md`` § 12 Phase 1.5 Task 1.

    Under serial execution ``worker_id == "master"`` — per-worker reduces
    to per-session, same as before.

    The per-worker directory gets a fresh ``cache.key`` the first time
    ``sentinel.hmac_keys`` derives a key.  Tests that use
    ``make_test_db(tmp_path, template=migrated_db_template)`` get rows
    signed with THIS worker's K_db, so runtime HMAC verification in the
    test matches cleanly.
    """
    # Per-worker via mktemp — xdist gives each worker a unique name
    # (``gw0``, ``gw1``, ...); serial returns ``master``.
    data_dir = tmp_path_factory.mktemp(f"sentinel-{worker_id}", numbered=False)
    prior = os.environ.get("SENTINEL_DATA_DIR")
    os.environ["SENTINEL_DATA_DIR"] = str(data_dir)
    # Clear any cached HMAC sub-keys that depend on the previous data dir.
    try:
        from sentinel.hmac_keys import _reset_cache as _hk_reset

        _hk_reset()
    except ImportError:
        pass  # Phase 1.5 pre-Phase-2 compatibility

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
    """Create one stamped-at-HEAD + seeded DB template per xdist worker session.

    Phase 7 P2-11 α (per prod_imp.md § 12 Phase 1.5 Task 2): runs
    ``check_and_upgrade_all_dbs(path, None)`` to stamp/upgrade the template
    to Alembic HEAD, then ``seed_all_baseline(path)`` to populate shipped
    baseline rows.  Individual tests that need a realistic DB call
    ``shutil.copy2(migrated_db_template, tmp_path / "test.db")`` for a
    fast per-test copy instead of paying the migration cost N times.

    Per-worker via ``tmp_path_factory.mktemp(f"sentinel-template-{worker_id}")``
    so xdist parallel runs don't race on the same template file.

    Returns:
        Path to the on-disk template DB (session-lived, per-worker).
    """
    from sentinel.migrations import check_and_upgrade_all_dbs
    from sentinel.seed_data import seed_all_baseline

    template_dir = tmp_path_factory.mktemp(f"sentinel-template-{worker_id}")
    path = template_dir / "template.db"
    check_and_upgrade_all_dbs(path, None)
    seed_all_baseline(path)
    return path


# ---------------------------------------------------------------------------
# Task 4 — Shared fixture helpers
# ---------------------------------------------------------------------------


def make_test_db(
    tmp_path: Path,
    *,
    seed: bool = True,
    template: Path | None = None,
) -> Path:
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

    **v0.7.0 (Phase 7.3) — template= adoption sweep**

    Callsite inventory (audit performed 2026-04-23, see
    phase7_3_implementation_report.md):

    | File | Count | Uses template= | Rationale |
    |------|-------|----------------|-----------|
    | test_rewriter.py | 1 | YES (via tmp_db fixture) | CLI-path — fast-copy |
    | test_analyzer.py | 2 | 1 YES / 1 (fixture) YES | CLI-path — fast-copy |
    | test_self_check.py | 1 | YES | CLI-path — fast-copy |
    | test_aws_examples.py | 1 | YES | CLI-path — fast-copy |
    | test_cli_subcommands_coverage.py | 4 | YES | CLI-path — fast-copy |
    | test_snapshots.py | 1 | YES | CLI-path — fast-copy |
    | test_fetchers/test_aws_managed.py | 1 | YES | CLI-path — fast-copy |
    | test_phase7_regressions.py | 4 | YES | Regression tests — fast-copy |
    | integration/test_pipeline.py | 1 | YES | Integration — fast-copy |
    | test_fixture_wiring.py | 3 | Mixed (tests the helper) | Helper test |

    All non-migration-testing callsites now pass ``template=``.
    Migration-specific tests (``test_migrations_coverage.py``,
    ``test_alembic_drift.py``, ``test_alembic_roundtrip.py``) do NOT
    use ``make_test_db`` at all — they call ``check_and_upgrade_all_dbs``
    directly to exercise the migration path itself.

    Args:
        tmp_path: per-test temp directory (pytest ``tmp_path`` fixture).
        seed: If False, skip ``seed_all_baseline`` — for tests that
            specifically exercise the empty-table bulk-load path.
        template: P2-11 α — optional session-scoped template DB
            (from the ``migrated_db_template`` fixture).  If provided,
            ``shutil.copy2`` the template instead of running migrations
            + seeding from scratch — one migration per session instead
            of one per test.  Respects ``seed=False`` by skipping the
            copy path and falling through to the cold-rebuild branch.

    Returns:
        Absolute path to a migrated (+ optionally seeded) SQLite DB.
    """
    path = tmp_path / "test.db"

    if template is not None and seed:
        # P2-11 α fast path — template already has HEAD schema + shipped
        # rows signed with the current K_db.  Copy takes ~1ms vs
        # ~200ms to run 8 migrations + re-seed.
        shutil.copy2(template, path)
        return path

    from sentinel.migrations import check_and_upgrade_all_dbs
    from sentinel.seed_data import seed_all_baseline

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


def signed_db_row(
    table: str,
    pk: tuple,
    row_data: dict,
    *,
    key: bytes | None = None,
) -> dict:
    """Return a dict of ``row_data`` plus a correct ``row_hmac`` column.

    Phase 7 P2-11 α (per prod_imp.md § 12 Phase 1.5 Task 4 + § 12 Phase 2
    Task 6a).  Computes the HMAC-SHA256 digest of
    ``(table, pk, row_data)`` using ``hmac_keys.sign_row`` and returns
    ``{**row_data, "row_hmac": <hex digest>}`` — directly insertable
    into the HMAC-signed Phase-2 tables (``dangerous_actions``,
    ``companion_rules``, etc.).

    Args:
        table: SQL table name (e.g. ``"dangerous_actions"``).
        pk: Primary-key tuple — stringified at sign time.
        row_data: All other columns, must NOT contain ``row_hmac``.
        key: Optional bytes override — if supplied, recomputes the HMAC
            with this key instead of the per-install K_db.  Used by
            tests that want to inject a known key without touching
            ``$SENTINEL_DATA_DIR``.

    Returns:
        Shallow copy of ``row_data`` with ``row_hmac`` added.
    """
    if key is None:
        from sentinel.hmac_keys import sign_row

        digest = sign_row(table, tuple(pk), row_data)
    else:
        # Custom-key variant — reimplement the same canonical serialization
        # as hmac_keys.sign_row so forgery tests can use a known K.
        import hashlib
        import hmac as _hmac

        if "row_hmac" in row_data:
            raise ValueError("row_data must not include 'row_hmac' — it's the output")
        parts: list[bytes] = [table.encode("utf-8")]
        parts.extend(str(v).encode("utf-8") for v in pk)
        for k in sorted(row_data.keys()):
            parts.append(k.encode("utf-8"))
            parts.append(b"\x1f")
            parts.append(str(row_data[k]).encode("utf-8"))
            parts.append(b"\x1e")
        msg = b"\x1e".join(parts)
        digest = _hmac.new(key, msg, hashlib.sha256).hexdigest()
    return {**row_data, "row_hmac": digest}


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


@pytest.fixture(autouse=True)
def _reset_hmac_cache_after_test() -> Iterator[None]:
    """v0.6.2 — Clear ``hmac_keys._root_key_cached`` after every test.

    Tests that monkey-patch ``SENTINEL_DATA_DIR`` can leave a K_db
    derived from the tmp-path cached in the process-lifetime globals
    (``_root_key_cached``, ``_cache_sub_key``, ``_db_sub_key``).  Under
    xdist, subsequent tests on the same worker may then try to verify
    rows signed with the SESSION-shared K_db against that leaked
    tmp-path K_db -- HMAC mismatch, cascading failures.

    Function-scope teardown after the test unwinds guarantees the
    next-starting test derives freshly from the live env var.  Must
    run AFTER any monkeypatch teardown so env-var restoration has
    happened; pytest's LIFO fixture teardown ordering handles this
    correctly because monkeypatch is requested implicitly (earlier in
    the resolution order).
    """
    yield
    try:
        from sentinel.hmac_keys import _reset_cache as _hk_reset

        _hk_reset()
    except ImportError:
        pass  # Phase 1.5 compatibility.


__all__ = [
    "make_test_db",
    "signed_db_row",
    "migrated_db_template",
]

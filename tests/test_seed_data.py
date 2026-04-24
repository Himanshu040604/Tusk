"""Coverage tests for ``sentinel.seed_data`` (U33).

The baseline seeder is the load-path that populates the four rule tables
(``dangerous_actions``, ``companion_rules``, ``action_resource_map``,
``arn_templates``) from code constants on first run.  The existing test
suite exercises these indirectly via ``_build_pipeline_db`` and
``make_test_db(seed=True)``, but there was no dedicated module-level
coverage — so ``seed_all_baseline``'s transactional / HMAC / idempotency
semantics were untested in isolation.

Prior audit: original claim was tests missing for 5 modules
(hmac_keys, migrations, seed_data, logging_setup, telemetry).
Investigation showed three already have dedicated files
(``test_hmac_keys_coverage.py``, ``test_logging_setup_coverage.py``,
``test_migrations_coverage.py``).  The genuine gaps were this module
and ``telemetry.py`` — the latter covered by ``test_telemetry.py``.
"""

from __future__ import annotations

import sqlite3
from pathlib import Path

import pytest

from sentinel.seed_data import (
    SOURCE_SHIPPED,
    seed_action_resource_map,
    seed_all_baseline,
    seed_arn_templates,
    seed_companion_rules,
    seed_dangerous_actions,
)
from tests.conftest import make_test_db


class TestSeedAllBaseline:
    """The top-level orchestrator that wraps all four seed functions."""

    def test_returns_expected_keys(self, tmp_path: Path) -> None:
        path = make_test_db(tmp_path, seed=False)
        counts = seed_all_baseline(path)
        assert set(counts) == {
            "dangerous_actions",
            "companion_rules",
            "action_resource_map",
            "arn_templates",
        }
        assert all(v > 0 for v in counts.values()), counts

    def test_idempotent_under_truncate_and_reload(self, tmp_path: Path) -> None:
        """Running twice yields identical row counts.

        ``dangerous_actions`` and ``companion_rules`` use
        truncate-and-reload semantics (DELETE FROM + INSERT);
        ``action_resource_map`` and ``arn_templates`` use
        INSERT OR IGNORE.  Both lead to stable row counts across
        repeated invocations.
        """
        path = make_test_db(tmp_path, seed=False)
        first = seed_all_baseline(path)
        second = seed_all_baseline(path)
        assert first == second
        # Cross-check by direct SQL on the resulting DB.
        with sqlite3.connect(str(path)) as conn:
            for table, expected in first.items():
                got = conn.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]
                assert got == expected, (
                    f"{table}: {got} rows after second seed, expected {expected}"
                )


class TestSeedIndividualTables:
    """Per-function tests focusing on the HMAC-signing contract."""

    def test_dangerous_actions_rows_are_hmac_signed(self, tmp_path: Path) -> None:
        """Every seeded ``dangerous_actions`` row must carry row_hmac."""
        path = make_test_db(tmp_path, seed=False)
        with sqlite3.connect(str(path)) as conn:
            n = seed_dangerous_actions(conn)
            conn.commit()
            rows = conn.execute(
                "SELECT row_hmac FROM dangerous_actions WHERE source = ?",
                (SOURCE_SHIPPED,),
            ).fetchall()
        assert n > 0
        assert len(rows) == n
        # SHA-256 hex = 64 chars; every row must have one.
        assert all(r[0] and len(r[0]) == 64 for r in rows)

    def test_companion_rules_rows_are_hmac_signed(self, tmp_path: Path) -> None:
        path = make_test_db(tmp_path, seed=False)
        with sqlite3.connect(str(path)) as conn:
            n = seed_companion_rules(conn)
            conn.commit()
            rows = conn.execute(
                "SELECT row_hmac FROM companion_rules WHERE source = ?",
                (SOURCE_SHIPPED,),
            ).fetchall()
        assert n > 0
        assert len(rows) == n
        assert all(r[0] and len(r[0]) == 64 for r in rows)

    def test_unsigned_tables_populated(self, tmp_path: Path) -> None:
        """Theme G1: ``action_resource_map`` and ``arn_templates`` are NOT
        HMAC-signed — they are simple membership lookups, not trust-
        bearing classification inputs.  Just confirm they populate.
        """
        path = make_test_db(tmp_path, seed=False)
        with sqlite3.connect(str(path)) as conn:
            n_map = seed_action_resource_map(conn)
            n_arn = seed_arn_templates(conn)
            conn.commit()
        assert n_map > 0
        assert n_arn > 0

    def test_rollback_on_mid_run_failure(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """BEGIN IMMEDIATE + rollback: a failure in any seed step should
        leave NO partial rows visible — the whole batch rolls back.

        Simulates by monkeypatching ``seed_companion_rules`` (the second
        step inside ``seed_all_baseline``) to raise; confirms that the
        rows written by the earlier ``seed_dangerous_actions`` step are
        discarded.
        """
        path = make_test_db(tmp_path, seed=False)
        import sentinel.seed_data as sd

        def _boom(conn: sqlite3.Connection) -> int:  # noqa: ARG001
            raise RuntimeError("boom")

        monkeypatch.setattr(sd, "seed_companion_rules", _boom)
        with pytest.raises(RuntimeError, match="boom"):
            seed_all_baseline(path)
        with sqlite3.connect(str(path)) as conn:
            remaining = conn.execute("SELECT COUNT(*) FROM dangerous_actions").fetchone()[0]
        assert remaining == 0, (
            "Baseline seeder must roll the transaction back on a "
            "mid-batch failure; found partial writes."
        )

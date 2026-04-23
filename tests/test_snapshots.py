"""Regression snapshot tests (Phase 2 Task 8).

For each fixture in ``tests/fixtures/test_policies/`` we maintain a
canonical pipeline output JSON in ``tests/fixtures/snapshots/``.  A
snapshot mismatch means a behavioural change has landed — the delta
must be either (a) intentional (developer refreshes the snapshot
deliberately), or (b) a regression to investigate.

Snapshots use stable JSON ordering: every list is ``sorted(...)`` and
every dict is dumped with ``sort_keys=True``.

To regenerate a snapshot after an intentional change::

    SENTINEL_REGEN_SNAPSHOTS=1 uv run pytest tests/test_snapshots.py
"""

from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

FIXTURES = Path(__file__).parent / "fixtures" / "test_policies"
SNAPSHOTS = Path(__file__).parent / "fixtures" / "snapshots"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _canonicalise(obj: object) -> object:
    """Recursively sort lists and dict keys so diffs are stable.

    Lists of dicts are sorted by their JSON repr — good enough for
    snapshot-equality but deterministic across runs.
    """
    if isinstance(obj, dict):
        return {k: _canonicalise(obj[k]) for k in sorted(obj)}
    if isinstance(obj, list):
        canonical_children = [_canonicalise(x) for x in obj]
        if all(isinstance(c, (int, float, str, bool)) or c is None for c in canonical_children):
            return sorted(canonical_children, key=lambda x: str(x))
        return sorted(canonical_children, key=lambda x: json.dumps(x, sort_keys=True))
    return obj


def _run_pipeline(fixture_path: Path, tmp_path: Path) -> dict:
    """Return a canonicalised pipeline summary dict for ``fixture_path``."""
    from tests.conftest import make_test_db
    from sentinel.database import Database
    from sentinel.self_check import Pipeline

    db_path = make_test_db(tmp_path)
    db = Database(db_path)
    pipeline = Pipeline(database=db)
    policy_json = fixture_path.read_text()
    result = pipeline.run_text(policy_json)

    # Extract only the stable, business-logic fields — skip timestamps,
    # object ids, and other transient state.
    summary: dict[str, object] = {
        "final_verdict": str(result.final_verdict),
        "iterations": result.iterations,
        "validation_result_count": len(result.validation_results),
        "rewritten_statement_count": len(result.rewritten_policy.statements),
        "rewritten_actions": [
            a for stmt in result.rewritten_policy.statements for a in stmt.actions
        ],
    }
    return dict(_canonicalise(summary))  # type: ignore[arg-type]


def _snapshot_assert(name: str, actual: dict) -> None:
    snap_file = SNAPSHOTS / f"{name}.snapshot"
    payload = json.dumps(actual, indent=2, sort_keys=True) + "\n"

    if os.environ.get("SENTINEL_REGEN_SNAPSHOTS") == "1":
        snap_file.write_text(payload)
        pytest.skip(f"snapshot {name} regenerated — rerun without env to assert")

    if not snap_file.exists():
        snap_file.write_text(payload)
        pytest.skip(
            f"snapshot {name} did not exist — created.  Re-run the test to assert stability."
        )

    expected = snap_file.read_text()
    assert payload == expected, (
        f"\nSnapshot drift for {name!r}.  To accept the new output:\n"
        f"    SENTINEL_REGEN_SNAPSHOTS=1 uv run pytest "
        f"tests/test_snapshots.py::test_{name}\n\n"
        f"--- expected ---\n{expected}\n"
        f"--- actual ---\n{payload}\n"
    )


# ---------------------------------------------------------------------------
# Per-fixture snapshot tests
# ---------------------------------------------------------------------------


def test_wildcard_overuse(tmp_path: Path) -> None:
    fixture = FIXTURES / "wildcard_overuse.json"
    actual = _run_pipeline(fixture, tmp_path)
    _snapshot_assert("wildcard_overuse", actual)


def test_missing_companions(tmp_path: Path) -> None:
    fixture = FIXTURES / "missing_companions.json"
    actual = _run_pipeline(fixture, tmp_path)
    _snapshot_assert("missing_companions", actual)

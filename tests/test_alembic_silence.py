"""Tests for Issue 4 (v0.8.0): Alembic logging silenced at import.

The Alembic ``fileConfig()`` call in each ``migrations/*/env.py`` plus the
``[loggers]`` sections in ``alembic.ini`` used to hijack the root logger,
producing noisy stderr lines like ``setup plugin``,
``Context impl SQLiteImpl``, and ``Will assume non-transactional DDL`` on
every ``sentinel`` invocation. v0.8.0 removes the fileConfig call and the
logger sections from ``alembic.ini``.

This test invokes ``sentinel info`` via subprocess and asserts that none
of the Alembic-specific noise strings appear on stderr.
"""

from __future__ import annotations

import subprocess
import sys


_ALEMBIC_NOISE_SUBSTRINGS = (
    "setup plugin",
    "Context impl SQLiteImpl",
    "Will assume non-transactional DDL",
)


def test_sentinel_info_no_alembic_noise(tmp_path, monkeypatch):
    """``sentinel info`` stderr must be free of Alembic-hijacked log noise.

    Runs the CLI in a fresh subprocess (simulating a cold-start operator
    invocation) and scans stderr for the three strings Alembic emits when
    ``fileConfig()`` activates the default [loggers] sections.
    """
    result = subprocess.run(
        [sys.executable, "-m", "sentinel", "info"],
        capture_output=True,
        text=True,
        cwd=str(tmp_path),
        timeout=60,
    )
    stderr = result.stderr
    for noise in _ALEMBIC_NOISE_SUBSTRINGS:
        assert noise not in stderr, (
            f"Alembic noise leaked to stderr: {noise!r} present in:\n{stderr}"
        )

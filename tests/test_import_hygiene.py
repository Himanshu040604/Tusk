"""Static-text guard against ``from src.sentinel.*`` imports inside the
sentinel package itself (PE7).

These work in pytest (``pyproject.toml [tool.pytest.ini_options]
pythonpath = ["src"]`` makes ``src.sentinel.X`` resolvable) but break
at normal CLI runtime — under ``uv run sentinel``, ``src`` is not an
importable package, only ``sentinel`` is.  A function-body
``from src.sentinel.X import Y`` is invisible to import-time tests
because the module imports successfully; the failure only surfaces
when the function is actually invoked at runtime — which is exactly
how the v0.8.2 ``sentinel refresh --source policy-sentry`` crash
shipped past the existing test suite.

The audit cycle's U18 (``5fa3f53`` + ``d9f863a``), U31 (``070384c``)
and PE7 swept the package clean of this anti-pattern.  This test
prevents the pattern from creeping back in.
"""

from __future__ import annotations

import pathlib
import re

_PATTERN = re.compile(r"^\s*(from|import)\s+src\.sentinel", re.MULTILINE)


def test_no_absolute_src_sentinel_imports_in_package() -> None:
    """Every .py file under ``src/sentinel/`` must use relative imports.

    Scope is intentionally limited to the package itself; tests under
    ``tests/`` legitimately use ``from src.sentinel.*`` because pytest
    sets ``pythonpath = ["src"]`` and that absolute form works there.
    """
    pkg_root = (
        pathlib.Path(__file__).resolve().parent.parent / "src" / "sentinel"
    )
    offenders: list[str] = []
    for path in pkg_root.rglob("*.py"):
        text = path.read_text(encoding="utf-8")
        for i, line in enumerate(text.splitlines(), start=1):
            if _PATTERN.match(line):
                offenders.append(
                    f"{path.relative_to(pkg_root.parent.parent)}:{i}: "
                    f"{line.strip()}"
                )
    assert not offenders, (
        "Absolute ``from src.sentinel.*`` imports break runtime under "
        "``uv run sentinel`` because ``src`` is not a package — only "
        "``sentinel`` is.  Use relative imports (``from ..X import Y``).\n"
        "Offenders:\n  " + "\n  ".join(offenders)
    )

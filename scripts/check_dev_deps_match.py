#!/usr/bin/env python3
"""Dev-dependency drift check (H18).

Asserts that the two dev-dependency lists in ``pyproject.toml`` stay
in sync:

* ``[project.optional-dependencies].dev`` — legacy PEP 621 extras, for
  pip < 23.1 users who still rely on ``pip install -e .[dev]``.
* ``[dependency-groups].dev`` — modern PEP 735 group, uv-native.

Any drift between these two sets produces a non-zero exit and a
human-readable diff on stderr.  Wired into the PR-gate CI so the lists
can't silently diverge.

Exit codes:
    0 — lists match
    1 — drift detected
    2 — file missing or malformed
"""

from __future__ import annotations

import sys
from pathlib import Path

try:
    import tomllib  # type: ignore[import-not-found]
except ModuleNotFoundError:  # pragma: no cover  (Py < 3.11)
    import tomli as tomllib  # type: ignore[import-not-found,no-redef]


PYPROJECT = Path(__file__).resolve().parent.parent / "pyproject.toml"


def _extract_dev_deps(doc: dict) -> tuple[set[str], set[str]]:
    """Return ``(optional_dev, group_dev)`` sets of requirement strings."""
    opt = doc.get("project", {}).get("optional-dependencies", {}).get("dev", [])
    grp = doc.get("dependency-groups", {}).get("dev", [])
    return set(opt), set(grp)


def main() -> int:
    if not PYPROJECT.exists():
        print(f"[drift-check] {PYPROJECT} not found", file=sys.stderr)
        return 2

    try:
        doc = tomllib.loads(PYPROJECT.read_text(encoding="utf-8"))
    except tomllib.TOMLDecodeError as exc:
        print(f"[drift-check] failed to parse pyproject.toml: {exc}", file=sys.stderr)
        return 2

    opt, grp = _extract_dev_deps(doc)
    if opt == grp:
        print("[drift-check] optional-dependencies.dev == dependency-groups.dev (OK)")
        return 0

    only_opt = sorted(opt - grp)
    only_grp = sorted(grp - opt)
    print("[drift-check] DRIFT DETECTED:", file=sys.stderr)
    if only_opt:
        print("  only in [project.optional-dependencies].dev:", file=sys.stderr)
        for item in only_opt:
            print(f"    + {item}", file=sys.stderr)
    if only_grp:
        print("  only in [dependency-groups].dev:", file=sys.stderr)
        for item in only_grp:
            print(f"    + {item}", file=sys.stderr)
    return 1


if __name__ == "__main__":
    sys.exit(main())

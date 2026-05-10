#!/usr/bin/env python3
"""Pre-commit hook vs uv-lock version drift check (Bundle B.10).

Asserts that hook revs in ``.pre-commit-config.yaml`` track the installed
versions in ``uv.lock`` for tools that exist in both surfaces:

* ruff (``ruff-pre-commit`` rev vs uv.lock ``ruff``)
* mypy (``mirrors-mypy`` rev vs uv.lock ``mypy``)
* detect-secrets (``Yelp/detect-secrets`` rev vs uv.lock ``detect-secrets``)

Bundle K's root cause was 10-minor-version drift between these surfaces —
hook ruff at v0.5.5 vs uv-lock ruff at 0.15.11. The hook env then died
on `pyproject.toml`'s rule selectors that the older ruff didn't recognize.
This check catches that class of drift before it reaches the CI failure.

Exit codes:
    0 — all tracked tools match between surfaces
    1 — drift detected (specific tools listed on stderr)
    2 — file missing or malformed
"""

from __future__ import annotations

import re
import sys
import tomllib
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
PRECOMMIT_CONFIG = REPO_ROOT / ".pre-commit-config.yaml"
UV_LOCK = REPO_ROOT / "uv.lock"

# (uv-lock package name, pre-commit repo URL substring) — the hook-rev
# extraction regex is generic across these because pre-commit revs are
# all `vX.Y.Z` shape on their respective tools' tag conventions.
TRACKED_TOOLS: tuple[tuple[str, str], ...] = (
    ("ruff", "astral-sh/ruff-pre-commit"),
    ("mypy", "pre-commit/mirrors-mypy"),
    ("detect-secrets", "Yelp/detect-secrets"),
)


def _read_precommit_revs() -> dict[str, str]:
    """Extract `rev:` per repo URL from .pre-commit-config.yaml.

    Hand-parses to avoid taking a yaml dependency just for this script
    (PyYAML isn't a runtime dep of sentinel; uv has it transitively but
    pre-commit's own runner shouldn't need it for this check).

    Returns a dict of {repo_url_substring: version_without_v_prefix}.
    """
    if not PRECOMMIT_CONFIG.exists():
        print(f"ERROR: {PRECOMMIT_CONFIG} missing", file=sys.stderr)
        sys.exit(2)
    text = PRECOMMIT_CONFIG.read_text(encoding="utf-8")
    # Match each `- repo: <url>` followed by `    rev: <version>` (next non-blank).
    # The pre-commit format is structured: every repo block has exactly one rev.
    pattern = re.compile(
        r"-\s+repo:\s*(?P<url>\S+)\s*\n\s+rev:\s*v?(?P<rev>\S+)",
        re.MULTILINE,
    )
    return {m.group("url"): m.group("rev") for m in pattern.finditer(text)}


def _read_uv_lock_versions() -> dict[str, str]:
    """Extract installed package versions from uv.lock."""
    if not UV_LOCK.exists():
        print(f"ERROR: {UV_LOCK} missing", file=sys.stderr)
        sys.exit(2)
    with UV_LOCK.open("rb") as f:
        lock = tomllib.load(f)
    # Skip the project package itself (no version key in uv.lock for editable
    # local sources like sentinel). Only registry-resolved packages carry a
    # version field.
    return {
        pkg["name"]: pkg["version"]
        for pkg in lock.get("package", [])
        if "version" in pkg
    }


def main() -> int:
    precommit_revs = _read_precommit_revs()
    uv_versions = _read_uv_lock_versions()

    drift: list[str] = []
    for pkg_name, repo_substring in TRACKED_TOOLS:
        # Find the rev for the matching repo substring.
        hook_rev = next(
            (rev for url, rev in precommit_revs.items() if repo_substring in url),
            None,
        )
        if hook_rev is None:
            drift.append(f"  ! {pkg_name}: no hook entry matching '{repo_substring}'")
            continue
        uv_version = uv_versions.get(pkg_name)
        if uv_version is None:
            drift.append(f"  ! {pkg_name}: not in uv.lock (was hook expected?)")
            continue
        if hook_rev != uv_version:
            drift.append(
                f"  X {pkg_name}: hook=v{hook_rev}  uv.lock={uv_version}  "
                f"(bump .pre-commit-config.yaml: rev: v{uv_version})"
            )

    if not drift:
        print("OK: pre-commit hook revs match uv.lock for all tracked tools.")
        return 0

    print(
        "ERROR: pre-commit hook vs uv.lock drift detected for tracked tools:",
        file=sys.stderr,
    )
    for line in drift:
        print(line, file=sys.stderr)
    print(
        "\nBundle K context: 10-minor-version drift here caused 5 hooks to fail "
        "in CI on every push. Bumping the hook revs to match uv.lock keeps the "
        "two surfaces aligned. See scripts/check_precommit_uv_drift.py.",
        file=sys.stderr,
    )
    return 1


if __name__ == "__main__":
    sys.exit(main())

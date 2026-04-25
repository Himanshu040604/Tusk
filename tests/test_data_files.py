"""Regression guards for shipped data artifacts.

The package depends on a small number of static data files that travel
with the source tree (as opposed to being generated on first run by
``sentinel refresh``).  If any of these files are accidentally removed
or excluded from version control, the test suite cascades into many
confusing failures (see commit 444ba57 + the v0.8.x CI break for the
canonical example: 18 unrelated tests failed because one ~8 KB JSON
file was inadvertently added to ``.gitignore``).

This module catches that class of mistake in a single sub-second test
so the *signal* is clear: "the shipped data file is missing", not
"every parser test in the suite is broken".

Add a new check here whenever a new file under ``data/`` (or any other
package-relative path) becomes load-bearing for production code rather
than being purely user-generated.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

# Resolve the project root the same way src/sentinel/constants.py does
# (this file lives at <root>/tests/, so go up one level).
PROJECT_ROOT = Path(__file__).resolve().parent.parent
KNOWN_SERVICES_JSON = PROJECT_ROOT / "data" / "known_services.json"


def test_known_services_json_is_shipped() -> None:
    """The Layer 2 parser fallback file must exist in the source tree.

    If this fails, someone removed ``data/known_services.json`` from
    version control or moved it.  The parser's Layer 2 fallback path
    (``src/sentinel/parser.py:183``) and the loader at
    ``src/sentinel/constants.py:145`` both resolve to this exact path.

    Without this file:
      * ``parser.known_services`` is the empty set on a no-DB init
      * ``parser._services_source`` reports ``"none"`` instead of
        ``"json_cache"``
      * Tier-2/Tier-3 classification flips for every recognized
        service prefix
      * 18 downstream tests fail with confusing AssertionErrors

    Fix: ``git add data/known_services.json`` and confirm it is not
    listed in ``.gitignore``.
    """
    if not KNOWN_SERVICES_JSON.exists():
        pytest.fail(
            f"{KNOWN_SERVICES_JSON} is missing.  The parser's Layer 2 "
            f"fallback (parser.py:183) requires this shipped artifact.  "
            f"Check .gitignore — it must NOT list 'data/known_services.json' "
            f"(see commit 444ba57 for the canonical regression)."
        )

    try:
        payload = json.loads(KNOWN_SERVICES_JSON.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        pytest.fail(f"{KNOWN_SERVICES_JSON} is not valid JSON: {exc}")

    services = payload.get("services")
    if not isinstance(services, list) or not services:
        pytest.fail(
            f"{KNOWN_SERVICES_JSON} has no non-empty 'services' list.  "
            f"load_known_services() requires data['services']: list[str].  "
            f"Re-run `sentinel refresh --source policy-sentry --live` to repopulate."
        )

    # Foundational, decade-old AWS prefixes — stable enough to encode here
    # without making the test brittle to upstream service renames.
    required_core = {"s3", "ec2", "iam", "lambda", "kms", "sts"}
    missing = required_core - set(services)
    if missing:
        pytest.fail(
            f"Core services missing from known_services.json: {sorted(missing)}.  "
            f"File exists but looks truncated or corrupted."
        )

"""Shared lookups for IAM Policy Sentinel (Phase 2 Task 8 reshape).

This module is now a thin config-facade.  Before Task 8 it carried a
dozen value-bearing literals (action lists, service sets, keyword
tuples, companion rule tables).  Those lived in config (``defaults.toml``
tables ``[intent.keywords.*]``, ``[intent.verb_prefixes]``, ``[security]``,
``[service_name_mappings]``) and the DB (``companion_rules``,
``action_resource_map``, ``arn_templates``) as well — two sources of
truth.

Task 8 deletes the literals here and replaces each exported name with a
module-level ``__getattr__`` accessor that reads live ``Settings`` at
call time.  The public import surface (``from .constants import X``)
stays unchanged so callers don't churn, but the underlying values now
resolve from TOML.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Optional, Set, Tuple

# ---------------------------------------------------------------------------
# CLI exit codes — canonical definitions live in :mod:`sentinel.exit_codes`.
# Duplicate constants were removed here in Phase 7 (P2-10); importers
# should read from ``exit_codes`` directly.
# ---------------------------------------------------------------------------


# ---------------------------------------------------------------------------
# Default file paths (pure constants)
# ---------------------------------------------------------------------------

DEFAULT_DB_PATH: str = "data/iam_actions.db"
DEFAULT_INVENTORY_PATH: str = "data/resource_inventory.db"

# ---------------------------------------------------------------------------
# Schema & default placeholders (pure constants)
# ---------------------------------------------------------------------------

SCHEMA_VERSION: str = "1.0"
DEFAULT_ACCOUNT_ID: str = "123456789012"
DEFAULT_REGION: str = "us-east-1"


# ---------------------------------------------------------------------------
# Dynamic lookups — resolved from Settings each access.  The module-level
# __getattr__ below preserves the ``from .constants import X`` surface.
# ---------------------------------------------------------------------------


def _settings() -> Any:
    # Local import avoids circular dependency at module-load time.
    from .config import get_settings

    return get_settings()


def _verb_prefix(bucket: str) -> Tuple[str, ...]:
    """Return one of the ``[intent.verb_prefixes]`` TOML lists as a tuple."""
    vp = _settings().intent.verb_prefixes
    return tuple(getattr(vp, bucket, ()) or ())


def _intent_keyword_bucket_values(bucket: str) -> Tuple[str, ...]:
    """Flatten one ``[intent.keywords.<bucket>]`` values list to a tuple."""
    kw = _settings().intent.keywords.get(bucket)
    if kw is None:
        return ()
    return tuple(kw.values)


def _read_intent_keywords() -> Tuple[str, ...]:
    """Union of the ``read``, ``read_write`` and ``list`` keyword buckets.

    Matches the legacy ``READ_INTENT_KEYWORDS`` semantics: any synonym that
    implied a read-only or read-write intent.
    """
    seen: list[str] = []
    for bucket in ("read", "read_write", "list"):
        for val in _intent_keyword_bucket_values(bucket):
            if val not in seen:
                seen.append(val)
    return tuple(seen)


def _write_intent_keywords() -> Tuple[str, ...]:
    """Union of the ``write``, ``read_write`` and ``admin`` buckets."""
    seen: list[str] = []
    for bucket in ("write", "read_write", "admin", "deploy"):
        for val in _intent_keyword_bucket_values(bucket):
            if val not in seen:
                seen.append(val)
    return tuple(seen)


_DYNAMIC_ATTRS = {
    "READ_PREFIXES": lambda: _verb_prefix("read"),
    "WRITE_PREFIXES": lambda: _verb_prefix("write"),
    "ADMIN_PREFIXES": lambda: _verb_prefix("admin"),
    "READ_INTENT_KEYWORDS": _read_intent_keywords,
    "WRITE_INTENT_KEYWORDS": _write_intent_keywords,
    "SECURITY_CRITICAL_SERVICES": lambda: set(_settings().security.critical_services),
    "REGION_LESS_GLOBAL_SERVICES": lambda: set(_settings().security.region_less_global_services),
    "SERVICE_NAME_MAPPINGS": lambda: dict(_settings().service_name_mappings),
}


def __getattr__(name: str) -> Any:
    """Resolve the deprecated value-bearing names from live Settings.

    Raises :class:`AttributeError` for anything that wasn't on the Phase 1
    public surface, so typos still fail loudly.
    """
    fn = _DYNAMIC_ATTRS.get(name)
    if fn is None:
        raise AttributeError(f"module 'sentinel.constants' has no attribute {name!r}")
    return fn()


def __dir__() -> list[str]:
    return sorted(
        list(_DYNAMIC_ATTRS.keys())
        + [
            "DEFAULT_DB_PATH",
            "DEFAULT_INVENTORY_PATH",
            "SCHEMA_VERSION",
            "DEFAULT_ACCOUNT_ID",
            "DEFAULT_REGION",
            "load_known_services",
        ]
    )


# Path to JSON data file (project root / data / known_services.json)
_JSON_PATH: Path = Path(__file__).resolve().parent.parent.parent / "data" / "known_services.json"


def load_known_services(json_path: Path | None = None) -> Set[str]:
    """Load known AWS service prefixes from JSON cache file.

    Args:
        json_path: Override path to JSON file (for testing). Defaults to
            ``data/known_services.json`` relative to project root.

    Returns:
        Set of service prefix strings. Empty set if JSON is missing or invalid.
    """
    path = json_path or _JSON_PATH
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        services = data.get("services", [])
        if not isinstance(services, list) or not services:
            return set()
        return set(services)
    except (FileNotFoundError, json.JSONDecodeError, OSError, KeyError, TypeError):
        return set()

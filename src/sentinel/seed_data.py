"""Seed classification tables from shipped baseline constants (Task 4).

Populates the tables introduced in migrations 0002–0008 from the Python
constants that previously lived in ``analyzer.py`` / ``rewriter.py`` /
``constants.py``.  Invoked in two contexts:

1. **First run of a newly-migrated DB** — bootstrap so ``RiskAnalyzer``
   finds rows to bulk-load at ``__init__`` time.
2. **``sentinel refresh --source shipped``** — re-seeds baseline rows
   (source-partitioned truncate-and-reload per § 6.4).

All rows are HMAC-signed via ``hmac_keys.sign_row()`` with the K_db
sub-key.  All writes happen inside a ``BEGIN IMMEDIATE`` transaction —
safe because WAL mode is already active by Task 5.

``source`` column values must match the CHECK constraints in § 6.1:
``'policy_sentry' | 'aws-docs' | 'shipped' | 'managed-policies' |
'cloudsplaining'``.  This module uses ``'shipped'`` for the baseline
content that ships with the source tree.
"""

from __future__ import annotations

import re
import sqlite3
from datetime import datetime, timezone
from pathlib import Path

from .hmac_keys import sign_row

SOURCE_SHIPPED = "shipped"


def _now_iso() -> str:
    """Return a CURRENT_TIMESTAMP-comparable ISO-8601 UTC string."""
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")


def _validate_regex(pattern: str, where: str) -> None:
    """Fail-fast regex validation (H1 ReDoS mitigation for DB-stored patterns)."""
    try:
        re.compile(pattern)
    except re.error as e:
        raise ValueError(f"Invalid regex at {where}: {pattern!r}: {e}") from e


def seed_dangerous_actions(conn: sqlite3.Connection) -> int:
    """Truncate-and-reload ``dangerous_actions`` from shipped constants.

    Source rows derive from analyzer.py's four class-level constants:
    PRIVILEGE_ESCALATION_ACTIONS (literal action set),
    DATA_EXFILTRATION_PATTERNS, DESTRUCTION_PATTERNS, PERMISSIONS_MGMT_PATTERNS
    (regex → description tuples).

    Returns:
        Number of rows inserted.
    """
    from .analyzer import RiskAnalyzer

    now = _now_iso()
    rows: list[tuple] = []

    # Category 1: privilege_escalation (literal action list)
    for action in RiskAnalyzer.PRIVILEGE_ESCALATION_ACTIONS:
        data = {
            "severity": "HIGH",
            "description": "Known privilege escalation vector",
            "source": SOURCE_SHIPPED,
            "refreshed_at": now,
        }
        row_hmac = sign_row(
            "dangerous_actions",
            (action, "privilege_escalation"),
            data,
        )
        rows.append(
            (
                action,
                "privilege_escalation",
                data["severity"],
                data["description"],
                data["source"],
                now,
                row_hmac,
            )
        )

    # Categories 2–4: regex patterns stored as the action_name key
    # (bulk-load pattern: RiskAnalyzer.__init__ compiles + matches).
    pattern_groups = (
        ("exfiltration", RiskAnalyzer.DATA_EXFILTRATION_PATTERNS),
        ("destruction", RiskAnalyzer.DESTRUCTION_PATTERNS),
        ("permissions_mgmt", RiskAnalyzer.PERMISSIONS_MGMT_PATTERNS),
    )
    for category, patterns in pattern_groups:
        for pattern, description in patterns:
            _validate_regex(pattern, f"dangerous_actions[{category}]")
            severity = "HIGH" if category != "destruction" else "MEDIUM"
            data = {
                "severity": severity,
                "description": description,
                "source": SOURCE_SHIPPED,
                "refreshed_at": now,
            }
            row_hmac = sign_row(
                "dangerous_actions", (pattern, category), data
            )
            rows.append(
                (pattern, category, severity, description, SOURCE_SHIPPED, now, row_hmac)
            )

    conn.execute(
        "DELETE FROM dangerous_actions WHERE source = ?",
        (SOURCE_SHIPPED,),
    )
    conn.executemany(
        "INSERT OR IGNORE INTO dangerous_actions "
        "(action_name, category, severity, description, source, refreshed_at, row_hmac) "
        "VALUES (?, ?, ?, ?, ?, ?, ?)",
        rows,
    )
    return len(rows)


def seed_companion_rules(conn: sqlite3.Connection) -> int:
    """Truncate-and-reload ``companion_rules`` from COMPANION_PERMISSION_RULES."""
    from .constants import COMPANION_PERMISSION_RULES

    now = _now_iso()
    rows: list[tuple] = []
    for primary, (companions, reason, severity) in COMPANION_PERMISSION_RULES.items():
        for companion in companions:
            data = {
                "reason": reason,
                "severity": severity,
                "source": SOURCE_SHIPPED,
                "refreshed_at": now,
            }
            row_hmac = sign_row(
                "companion_rules", (primary, companion), data
            )
            rows.append(
                (primary, companion, reason, severity, SOURCE_SHIPPED, now, row_hmac)
            )

    conn.execute(
        "DELETE FROM companion_rules WHERE source = ?", (SOURCE_SHIPPED,)
    )
    conn.executemany(
        "INSERT OR IGNORE INTO companion_rules "
        "(primary_action, companion_action, reason, severity, source, refreshed_at, row_hmac) "
        "VALUES (?, ?, ?, ?, ?, ?, ?)",
        rows,
    )
    return len(rows)


def seed_action_resource_map(conn: sqlite3.Connection) -> int:
    """Seed ``action_resource_map`` from ResourceInventory.ACTION_RESOURCE_MAP.

    NOT HMAC-signed (Theme G1 — simple membership lookup).  Reads from
    the shipped baseline constant (migrated from inventory.py); Task 8
    deletes the source dict in the same release and future seed sources
    move to AWS Service Auth scraped data.
    """
    # Lazy import avoids circular dependency at module-load time
    # (inventory imports constants, constants is self-contained).
    from .inventory import ResourceInventory

    mapping = getattr(ResourceInventory, "ACTION_RESOURCE_MAP", {})
    rows: list[tuple] = []
    for action, resource_types in mapping.items():
        if isinstance(resource_types, (list, tuple, set)):
            for rt in resource_types:
                rows.append((action, rt))
        else:
            rows.append((action, str(resource_types)))

    conn.executemany(
        "INSERT OR IGNORE INTO action_resource_map (action_name, resource_type) "
        "VALUES (?, ?)",
        rows,
    )
    return len(rows)


def seed_arn_templates(conn: sqlite3.Connection) -> int:
    """Seed ``arn_templates`` from ResourceInventory.ARN_TEMPLATES.

    NOT HMAC-signed.  ARN templates are keyed by service_prefix in the
    shipped dict; the DB schema uses a (service_prefix, resource_type)
    composite PK, so rows here have an empty resource_type — the
    PolicyRewriter bulk-load prefers service-only templates as the
    fallback when no (service, rt) row matches.
    """
    from .inventory import ResourceInventory

    templates = getattr(ResourceInventory, "ARN_TEMPLATES", {})
    rows: list[tuple] = []
    for key, template in templates.items():
        if ":" in str(key):
            svc, rt = str(key).split(":", 1)
        else:
            svc, rt = str(key), ""
        rows.append((svc, rt, str(template)))

    conn.executemany(
        "INSERT OR IGNORE INTO arn_templates "
        "(service_prefix, resource_type, arn_template) VALUES (?, ?, ?)",
        rows,
    )
    return len(rows)


def seed_all_baseline(db_path: Path) -> dict[str, int]:
    """Seed every baseline table from shipped constants.

    Executes inside a single ``BEGIN IMMEDIATE`` transaction (M16 — safe
    because WAL mode is active by Task 5).  On failure, the transaction
    rolls back and no partial state is visible.

    Returns:
        Dict mapping table name to row count inserted.
    """
    conn = sqlite3.connect(str(db_path))
    try:
        conn.execute("BEGIN IMMEDIATE")
        counts = {
            "dangerous_actions": seed_dangerous_actions(conn),
            "companion_rules": seed_companion_rules(conn),
            "action_resource_map": seed_action_resource_map(conn),
            "arn_templates": seed_arn_templates(conn),
        }
        conn.commit()
        return counts
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


__all__ = [
    "SOURCE_SHIPPED",
    "seed_all_baseline",
    "seed_dangerous_actions",
    "seed_companion_rules",
    "seed_action_resource_map",
    "seed_arn_templates",
]

"""CloudSplaining ruleset loader + live fetcher.

The CloudSplaining project publishes opinionated IAM rule categories
(e.g., ``iam_privilege_escalation``, ``data_exfiltration``) as JSON in
``salesforce/cloudsplaining/examples/`` on GitHub.  Phase 4 ingests
the rules into three existing tables with ``source='cloudsplaining'``:

* ``dangerous_actions`` — single-action dangerous-permission rules.
* ``dangerous_combinations`` — action-pair rules (e.g. iam:PutRolePolicy
  + sts:AssumeRole).

The full mapping is a Phase 5 concern; Phase 4 ships the plumbing so
the CLI's ``refresh --source cloudsplaining`` dispatch compiles and
the table ``source`` CHECK constraints are hit with the new value.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING

import structlog

if TYPE_CHECKING:  # pragma: no cover
    from sentinel.database import Database
    from sentinel.net.client import SentinelHTTPClient


@dataclass
class CloudSplainingStats:
    """Counters for a CloudSplaining refresh run."""

    actions_added: int = 0
    combinations_added: int = 0
    skipped: int = 0
    errors: list[str] = field(default_factory=list)


class CloudSplainingLoader:
    """Offline loader — reads pre-fetched CloudSplaining rules JSON."""

    def __init__(self, database: "Database") -> None:
        self._db = database
        self._log = structlog.get_logger("sentinel.refresh.cloudsplaining")

    def load_from_file(self, path: Path) -> CloudSplainingStats:
        """Load from a single CloudSplaining-format JSON file."""
        raw = json.loads(path.read_text(encoding="utf-8"))
        return self._ingest(raw)

    def load_from_directory(self, root: Path) -> CloudSplainingStats:
        stats = CloudSplainingStats()
        for json_file in sorted(root.glob("*.json")):
            try:
                partial = self.load_from_file(json_file)
            except (OSError, ValueError) as exc:
                stats.errors.append(f"{json_file.name}: {exc}")
                continue
            stats.actions_added += partial.actions_added
            stats.combinations_added += partial.combinations_added
            stats.skipped += partial.skipped
            stats.errors.extend(partial.errors)
        return stats

    def _ingest(self, raw: dict | list) -> CloudSplainingStats:
        stats = CloudSplainingStats()
        actions = raw.get("dangerous_actions", []) if isinstance(raw, dict) else []
        combos = raw.get("dangerous_combinations", []) if isinstance(raw, dict) else []
        with self._db.get_connection() as conn:
            for entry in actions:
                try:
                    conn.execute(
                        "INSERT OR IGNORE INTO dangerous_actions "
                        "(action_name, severity, reason, source) "
                        "VALUES (?, ?, ?, 'cloudsplaining')",
                        (
                            entry["action"],
                            entry.get("severity", "WARNING"),
                            entry.get("reason", "CloudSplaining rule"),
                        ),
                    )
                    stats.actions_added += 1
                except (KeyError, TypeError) as exc:
                    stats.errors.append(f"action {entry!r}: {exc}")
                    stats.skipped += 1
            for entry in combos:
                try:
                    conn.execute(
                        "INSERT OR IGNORE INTO dangerous_combinations "
                        "(action_a, action_b, severity, reason, source) "
                        "VALUES (?, ?, ?, ?, 'cloudsplaining')",
                        (
                            entry["action_a"], entry["action_b"],
                            entry.get("severity", "WARNING"),
                            entry.get("reason", "CloudSplaining combination"),
                        ),
                    )
                    stats.combinations_added += 1
                except (KeyError, TypeError) as exc:
                    stats.errors.append(f"combo {entry!r}: {exc}")
                    stats.skipped += 1
        return stats


class CloudSplainingLiveFetcher:
    """Live HTTP variant — pulls the ruleset via SentinelHTTPClient."""

    def __init__(
        self,
        database: "Database",
        client: "SentinelHTTPClient",
    ) -> None:
        self._db = database
        self._client = client
        self._loader = CloudSplainingLoader(database)

    def fetch_and_load(self, url: str) -> CloudSplainingStats:
        """GET ``url`` through the hardened client, then :meth:`_ingest`."""
        resp = self._client.get(url, source="github")
        raw = json.loads(resp.text)
        return self._loader._ingest(raw)


__all__ = [
    "CloudSplainingLiveFetcher",
    "CloudSplainingLoader",
    "CloudSplainingStats",
]

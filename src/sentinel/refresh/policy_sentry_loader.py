"""Load IAM actions data from policy_sentry JSON exports.

Parses per-service JSON files (or a combined multi-service file) and
inserts services, actions, resource types, and condition keys into the
IAM actions SQLite database.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Tuple, Dict, Any, TYPE_CHECKING

if TYPE_CHECKING:
    from src.sentinel.database import Database


@dataclass
class RefreshStats:
    """Counters for a refresh operation.

    Attributes:
        services_added: Number of services inserted or updated.
        actions_added: Number of actions inserted or updated.
        resource_types_added: Number of resource types inserted or updated.
        condition_keys_added: Number of condition keys inserted or updated.
        errors: List of non-fatal error messages.
    """

    services_added: int = 0
    actions_added: int = 0
    resource_types_added: int = 0
    condition_keys_added: int = 0
    errors: list[str] = field(default_factory=list)


@dataclass
class ChangelogEntry:
    """Single change record from a refresh operation.

    Attributes:
        change_type: ADD or UPDATE.
        entity_type: service, action, resource_type, or condition_key.
        entity_name: Identifier of the entity.
        detail: Human-readable description of the change.
    """

    change_type: str
    entity_type: str
    entity_name: str
    detail: str


# Mapping from policy_sentry access_level strings to boolean flag columns.
_ACCESS_LEVEL_MAP: dict[str, str] = {
    "List": "is_list",
    "Read": "is_read",
    "Write": "is_write",
    "Permissions management": "is_permissions_management",
    "Tagging": "is_tagging_only",
}


class PolicySentryLoader:
    """Load data from policy_sentry JSON into the IAM actions database.

    Expected per-service JSON format::

        {
            "prefix": "s3",
            "service_name": "Amazon S3",
            "privileges": [
                {"privilege": "GetObject", "access_level": "Read", ...}
            ],
            "resources": [
                {"resource": "bucket", "arn": "arn:aws:s3:::*"}
            ],
            "conditions": [
                {"condition": "s3:authType", "type": "String"}
            ]
        }
    """

    def __init__(self, database: Database) -> None:
        """Initialize loader.

        Args:
            database: Database instance to write into.
        """
        self.database = database

    def load_from_directory(
        self,
        data_dir: Path,
    ) -> tuple[RefreshStats, list[ChangelogEntry]]:
        """Load all ``*.json`` files from a directory.

        Args:
            data_dir: Directory containing per-service JSON files.

        Returns:
            Tuple of aggregate stats and changelog entries.
        """
        stats = RefreshStats()
        changelog: list[ChangelogEntry] = []

        for json_file in sorted(data_dir.glob("*.json")):
            try:
                data = json.loads(json_file.read_text(encoding="utf-8"))
            except (json.JSONDecodeError, OSError) as e:
                stats.errors.append(f"Skipping {json_file.name}: {e}")
                continue

            file_stats, file_log = self._process_service_data(data)
            stats.services_added += file_stats.services_added
            stats.actions_added += file_stats.actions_added
            stats.resource_types_added += file_stats.resource_types_added
            stats.condition_keys_added += file_stats.condition_keys_added
            stats.errors.extend(file_stats.errors)
            changelog.extend(file_log)

        self._update_metadata()
        return stats, changelog

    def load_from_file(
        self,
        data_file: Path,
    ) -> tuple[RefreshStats, list[ChangelogEntry]]:
        """Load from a single JSON file.

        The file may contain a single service object or a dict of
        ``{"prefix": {...}, ...}`` keyed by service prefix.

        Args:
            data_file: Path to JSON file.

        Returns:
            Tuple of aggregate stats and changelog entries.
        """
        stats = RefreshStats()
        changelog: list[ChangelogEntry] = []

        raw = json.loads(data_file.read_text(encoding="utf-8"))

        # Detect format: single service vs multi-service dict
        if isinstance(raw, dict) and "prefix" in raw:
            file_stats, file_log = self._process_service_data(raw)
            stats.services_added += file_stats.services_added
            stats.actions_added += file_stats.actions_added
            stats.resource_types_added += file_stats.resource_types_added
            stats.condition_keys_added += file_stats.condition_keys_added
            stats.errors.extend(file_stats.errors)
            changelog.extend(file_log)
        elif isinstance(raw, dict):
            for key, value in raw.items():
                if isinstance(value, dict):
                    if "prefix" not in value:
                        value["prefix"] = key
                    file_stats, file_log = self._process_service_data(value)
                    stats.services_added += file_stats.services_added
                    stats.actions_added += file_stats.actions_added
                    stats.resource_types_added += file_stats.resource_types_added
                    stats.condition_keys_added += file_stats.condition_keys_added
                    stats.errors.extend(file_stats.errors)
                    changelog.extend(file_log)

        self._update_metadata()
        return stats, changelog

    def validate_data(self, data_path: Path) -> list[str]:
        """Dry-run: parse data without writing to database.

        Args:
            data_path: Path to file or directory.

        Returns:
            List of validation error strings (empty = valid).
        """
        errors: list[str] = []

        if data_path.is_dir():
            files = list(data_path.glob("*.json"))
            if not files:
                errors.append(f"No JSON files found in {data_path}")
            for json_file in files:
                try:
                    data = json.loads(json_file.read_text(encoding="utf-8"))
                    self._validate_service_data(data, json_file.name, errors)
                except json.JSONDecodeError as e:
                    errors.append(f"{json_file.name}: Invalid JSON - {e}")
        else:
            try:
                data = json.loads(data_path.read_text(encoding="utf-8"))
                if isinstance(data, dict) and "prefix" in data:
                    self._validate_service_data(data, data_path.name, errors)
                elif isinstance(data, dict):
                    for key, value in data.items():
                        if isinstance(value, dict):
                            self._validate_service_data(value, f"{data_path.name}:{key}", errors)
            except json.JSONDecodeError as e:
                errors.append(f"{data_path.name}: Invalid JSON - {e}")

        return errors

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _process_service_data(
        self,
        data: dict[str, Any],
    ) -> tuple[RefreshStats, list[ChangelogEntry]]:
        """Process a single service data object.

        Args:
            data: Service data dictionary.

        Returns:
            Tuple of stats and changelog.
        """
        stats = RefreshStats()
        changelog: list[ChangelogEntry] = []

        prefix = data.get("prefix", "")
        service_name = data.get("service_name", prefix)

        if not prefix:
            stats.errors.append("Missing 'prefix' in service data")
            return stats, changelog

        # Insert service
        from src.sentinel.database import Service

        self.database.insert_service(Service(service_prefix=prefix, service_name=service_name))
        stats.services_added += 1
        changelog.append(
            ChangelogEntry(
                change_type="ADD",
                entity_type="service",
                entity_name=prefix,
                detail=f"Service '{service_name}'",
            )
        )

        # Insert privileges (actions)
        for priv in data.get("privileges", []):
            try:
                self._insert_action(prefix, priv, stats, changelog)
            except Exception as e:
                stats.errors.append(
                    f"Error inserting action {prefix}:{priv.get('privilege', '?')}: {e}"
                )

        # Insert resource types
        for rt in data.get("resources", []):
            try:
                self._insert_resource_type(prefix, rt, stats, changelog)
            except Exception as e:
                stats.errors.append(
                    f"Error inserting resource type {prefix}/{rt.get('resource', '?')}: {e}"
                )

        # Insert condition keys
        for ck in data.get("conditions", []):
            try:
                self._insert_condition_key(prefix, ck, stats, changelog)
            except Exception as e:
                stats.errors.append(
                    f"Error inserting condition key {ck.get('condition', '?')}: {e}"
                )

        return stats, changelog

    def _insert_action(
        self,
        service_prefix: str,
        priv_data: dict[str, Any],
        stats: RefreshStats,
        changelog: list[ChangelogEntry],
    ) -> None:
        """Insert a single action from privilege data.

        Args:
            service_prefix: AWS service prefix.
            priv_data: Privilege dict from policy_sentry.
            stats: Stats counter to update.
            changelog: Changelog list to append to.
        """
        from src.sentinel.database import Action

        action_name = priv_data.get("privilege", "")
        access_level = priv_data.get("access_level", "Read")
        description = priv_data.get("description", "")

        # Map access_level to boolean flags
        flags = {v: False for v in _ACCESS_LEVEL_MAP.values()}
        flag_col = _ACCESS_LEVEL_MAP.get(access_level)
        if flag_col:
            flags[flag_col] = True

        action = Action(
            action_id=None,
            service_prefix=service_prefix,
            action_name=action_name,
            full_action=f"{service_prefix}:{action_name}",
            description=description,
            access_level=access_level,
            is_list=flags["is_list"],
            is_read=flags["is_read"],
            is_write=flags["is_write"],
            is_permissions_management=flags["is_permissions_management"],
            is_tagging_only=flags["is_tagging_only"],
        )
        self.database.insert_action(action)
        stats.actions_added += 1
        changelog.append(
            ChangelogEntry(
                change_type="ADD",
                entity_type="action",
                entity_name=f"{service_prefix}:{action_name}",
                detail=f"Access level: {access_level}",
            )
        )

    def _insert_resource_type(
        self,
        service_prefix: str,
        rt_data: dict[str, Any],
        stats: RefreshStats,
        changelog: list[ChangelogEntry],
    ) -> None:
        """Insert a resource type via raw SQL.

        Args:
            service_prefix: AWS service prefix.
            rt_data: Resource type dict from policy_sentry.
            stats: Stats counter to update.
            changelog: Changelog list to append to.
        """
        resource_name = rt_data.get("resource", "")
        arn_pattern = rt_data.get("arn", "")

        if not resource_name or not arn_pattern:
            return

        with self.database.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                "INSERT OR REPLACE INTO resource_types "
                "(service_prefix, resource_name, arn_pattern) VALUES (?, ?, ?)",
                (service_prefix, resource_name, arn_pattern),
            )

        stats.resource_types_added += 1
        changelog.append(
            ChangelogEntry(
                change_type="ADD",
                entity_type="resource_type",
                entity_name=f"{service_prefix}/{resource_name}",
                detail=f"ARN: {arn_pattern}",
            )
        )

    def _insert_condition_key(
        self,
        service_prefix: str,
        ck_data: dict[str, Any],
        stats: RefreshStats,
        changelog: list[ChangelogEntry],
    ) -> None:
        """Insert a condition key via raw SQL.

        Args:
            service_prefix: AWS service prefix.
            ck_data: Condition key dict from policy_sentry.
            stats: Stats counter to update.
            changelog: Changelog list to append to.
        """
        condition_name = ck_data.get("condition", "")
        condition_type = ck_data.get("type", "String")

        if not condition_name:
            return

        # Determine if global key (aws:*)
        is_global = condition_name.startswith("aws:")

        # Extract short name after last colon
        short_name = condition_name.split(":")[-1] if ":" in condition_name else condition_name

        with self.database.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                "INSERT OR REPLACE INTO condition_keys "
                "(service_prefix, condition_key_name, description, "
                "condition_type, is_global) VALUES (?, ?, ?, ?, ?)",
                (
                    service_prefix,
                    short_name,
                    ck_data.get("description", ""),
                    condition_type,
                    is_global,
                ),
            )

        stats.condition_keys_added += 1
        changelog.append(
            ChangelogEntry(
                change_type="ADD",
                entity_type="condition_key",
                entity_name=condition_name,
                detail=f"Type: {condition_type}",
            )
        )

    def _update_metadata(self) -> None:
        """Update database metadata timestamps."""
        from datetime import datetime, timezone

        self.database.set_metadata("data_source", "policy_sentry")
        self.database.set_metadata(
            "last_full_update",
            datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        )

    def _validate_service_data(
        self,
        data: dict[str, Any],
        source_name: str,
        errors: list[str],
    ) -> None:
        """Validate a service data dict without writing.

        Args:
            data: Service data dictionary.
            source_name: Name for error reporting.
            errors: List to append errors to.
        """
        if not isinstance(data, dict):
            errors.append(f"{source_name}: Expected dict, got {type(data).__name__}")
            return

        prefix = data.get("prefix")
        if not prefix:
            errors.append(f"{source_name}: Missing 'prefix' field")

        for priv in data.get("privileges", []):
            if not priv.get("privilege"):
                errors.append(f"{source_name}: Privilege entry missing 'privilege' field")
            al = priv.get("access_level", "")
            if al and al not in _ACCESS_LEVEL_MAP:
                errors.append(
                    f"{source_name}: Unknown access_level '{al}' for {priv.get('privilege', '?')}"
                )

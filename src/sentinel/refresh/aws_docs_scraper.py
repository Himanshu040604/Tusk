"""Parse locally saved AWS Service Authorization HTML pages.

Extracts actions, resource types, and condition keys from the three tables
present on each AWS Service Authorization Reference page.  Operates on
saved HTML files -- no network calls.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from html.parser import HTMLParser
from pathlib import Path
from typing import List, Tuple, Dict, Any, Optional, TYPE_CHECKING

if TYPE_CHECKING:
    from ..database import Database

from .policy_sentry_loader import RefreshStats, ChangelogEntry


class ServiceAuthorizationParser(HTMLParser):
    """Parse the three tables on an AWS Service Authorization page.

    Tables expected (in order):
    1. Actions table -- columns: Actions, Description, Access level, Resource types, Condition keys, Dependent actions
    2. Resource types table -- columns: Resource types, ARN, Condition keys
    3. Condition keys table -- columns: Condition keys, Description, Type

    Only basic structure is captured; edge-cases in real AWS docs
    (footnotes, nested links) are handled defensively.
    """

    def __init__(self) -> None:
        """Initialize parser state."""
        super().__init__()
        self.in_table: bool = False
        self.in_thead: bool = False
        self.in_tbody: bool = False
        self.in_row: bool = False
        self.in_cell: bool = False
        self.cell_text: str = ""
        self.current_row: list[str] = []
        self.current_headers: list[str] = []

        self.actions: list[dict[str, str]] = []
        self.resource_types: list[dict[str, str]] = []
        self.condition_keys: list[dict[str, str]] = []

        self._table_index: int = -1

    def handle_starttag(self, tag: str, attrs: list) -> None:
        """Handle opening HTML tags."""
        if tag == "table":
            self.in_table = True
            self._table_index += 1
            self.current_headers = []
        elif tag == "thead":
            self.in_thead = True
        elif tag == "tbody":
            self.in_tbody = True
        elif tag == "tr":
            self.in_row = True
            self.current_row = []
        elif tag in ("td", "th"):
            self.in_cell = True
            self.cell_text = ""

    def handle_endtag(self, tag: str) -> None:
        """Handle closing HTML tags."""
        if tag == "table":
            self.in_table = False
            self.in_thead = False
            self.in_tbody = False
        elif tag == "thead":
            self.in_thead = False
        elif tag == "tbody":
            self.in_tbody = False
        elif tag == "tr":
            self.in_row = False
            if self.in_thead:
                self.current_headers = [c.strip().lower() for c in self.current_row]
            elif self.in_tbody:
                self._process_row(self.current_row)
        elif tag in ("td", "th"):
            self.in_cell = False
            self.current_row.append(self.cell_text.strip())

    def handle_data(self, data: str) -> None:
        """Handle text content inside tags."""
        if self.in_cell:
            self.cell_text += data

    def _process_row(self, cells: list[str]) -> None:
        """Route a data row to the appropriate table handler.

        Args:
            cells: List of cell text values.
        """
        if not cells or not self.current_headers:
            return

        if self._table_index == 0:
            self._process_actions_row(cells)
        elif self._table_index == 1:
            self._process_resource_types_row(cells)
        elif self._table_index == 2:
            self._process_condition_keys_row(cells)

    def _process_actions_row(self, cells: list[str]) -> None:
        """Parse a row from the Actions table.

        Args:
            cells: Cell values.
        """
        if len(cells) < 3:
            return

        action_name = cells[0].strip()
        if not action_name:
            return

        # Clean brackets, footnote markers, whitespace
        action_name = re.sub(r"\s*\[.*?\]", "", action_name).strip()

        entry: dict[str, str] = {
            "privilege": action_name,
            "description": cells[1].strip() if len(cells) > 1 else "",
            "access_level": cells[2].strip() if len(cells) > 2 else "Read",
        }
        self.actions.append(entry)

    def _process_resource_types_row(self, cells: list[str]) -> None:
        """Parse a row from the Resource types table.

        Args:
            cells: Cell values.
        """
        if len(cells) < 2:
            return

        resource_name = cells[0].strip()
        arn = cells[1].strip() if len(cells) > 1 else ""

        if not resource_name:
            return

        self.resource_types.append(
            {
                "resource": resource_name,
                "arn": arn,
            }
        )

    def _process_condition_keys_row(self, cells: list[str]) -> None:
        """Parse a row from the Condition keys table.

        Args:
            cells: Cell values.
        """
        if len(cells) < 1:
            return

        condition = cells[0].strip()
        if not condition:
            return

        self.condition_keys.append(
            {
                "condition": condition,
                "description": cells[1].strip() if len(cells) > 1 else "",
                "type": cells[2].strip() if len(cells) > 2 else "String",
            }
        )


class AwsDocsScraper:
    """Load IAM data from locally saved AWS Service Authorization HTML pages.

    Operates entirely offline. Users must download the HTML pages first.
    """

    def __init__(self, database: "Database") -> None:
        """Initialize scraper.

        Args:
            database: Database instance to write into.
        """
        self.database = database

    def load_from_directory(
        self,
        html_dir: Path,
    ) -> tuple[RefreshStats, list[ChangelogEntry]]:
        """Load all ``*.html`` files from a directory.

        Args:
            html_dir: Directory containing saved HTML files.

        Returns:
            Tuple of aggregate stats and changelog entries.
        """
        stats = RefreshStats()
        changelog: list[ChangelogEntry] = []

        for html_file in sorted(html_dir.glob("*.html")):
            try:
                file_stats, file_log = self.load_from_file(html_file)
                stats.services_added += file_stats.services_added
                stats.actions_added += file_stats.actions_added
                stats.resource_types_added += file_stats.resource_types_added
                stats.condition_keys_added += file_stats.condition_keys_added
                stats.errors.extend(file_stats.errors)
                changelog.extend(file_log)
            except Exception as e:
                stats.errors.append(f"Error processing {html_file.name}: {e}")

        self._update_metadata()
        return stats, changelog

    def load_from_file(
        self,
        html_file: Path,
    ) -> tuple[RefreshStats, list[ChangelogEntry]]:
        """Load from a single HTML file.

        Args:
            html_file: Path to saved HTML file.

        Returns:
            Tuple of stats and changelog.
        """
        stats = RefreshStats()
        changelog: list[ChangelogEntry] = []

        content = html_file.read_text(encoding="utf-8", errors="replace")
        service_prefix = self._infer_service_prefix(html_file.name, content)

        if not service_prefix:
            stats.errors.append(f"Could not infer service prefix from {html_file.name}")
            return stats, changelog

        parser = ServiceAuthorizationParser()
        parser.feed(content)

        # Build service data dict matching policy_sentry format
        service_data: dict[str, Any] = {
            "prefix": service_prefix,
            "service_name": service_prefix,
            "privileges": parser.actions,
            "resources": parser.resource_types,
            "conditions": parser.condition_keys,
        }

        # Reuse policy_sentry loader logic
        from .policy_sentry_loader import PolicySentryLoader

        loader = PolicySentryLoader(self.database)
        file_stats, file_log = loader._process_service_data(service_data)

        stats.services_added += file_stats.services_added
        stats.actions_added += file_stats.actions_added
        stats.resource_types_added += file_stats.resource_types_added
        stats.condition_keys_added += file_stats.condition_keys_added
        stats.errors.extend(file_stats.errors)
        changelog.extend(file_log)

        return stats, changelog

    def validate_data(self, data_path: Path) -> list[str]:
        """Dry-run: parse HTML without writing to database.

        Args:
            data_path: Path to file or directory.

        Returns:
            List of validation error strings (empty = valid).
        """
        errors: list[str] = []

        if data_path.is_dir():
            files = list(data_path.glob("*.html"))
            if not files:
                errors.append(f"No HTML files found in {data_path}")
            for html_file in files:
                try:
                    content = html_file.read_text(encoding="utf-8", errors="replace")
                    prefix = self._infer_service_prefix(html_file.name, content)
                    if not prefix:
                        errors.append(f"Could not infer service prefix from {html_file.name}")
                    parser = ServiceAuthorizationParser()
                    parser.feed(content)
                    if not parser.actions:
                        errors.append(f"{html_file.name}: No actions found")
                except Exception as e:
                    errors.append(f"{html_file.name}: {e}")
        else:
            try:
                content = data_path.read_text(encoding="utf-8", errors="replace")
                prefix = self._infer_service_prefix(data_path.name, content)
                if not prefix:
                    errors.append(f"Could not infer service prefix from {data_path.name}")
                parser = ServiceAuthorizationParser()
                parser.feed(content)
                if not parser.actions:
                    errors.append(f"{data_path.name}: No actions found")
            except Exception as e:
                errors.append(f"{data_path.name}: {e}")

        return errors

    def _infer_service_prefix(
        self,
        filename: str,
        content: str,
    ) -> str:
        """Infer AWS service prefix from filename or HTML content.

        Tries several strategies:
        1. Filename pattern ``list_amazons3.html`` -> ``s3``
        2. Filename pattern ``s3.html`` -> ``s3``
        3. ``<code>`` block with ``service-prefix`` content
        4. Title tag containing service name

        Args:
            filename: HTML filename.
            content: HTML content string.

        Returns:
            Inferred service prefix (empty string if not found).
        """
        stem = Path(filename).stem.lower()

        # Pattern: list_amazons3, list_awslambda, etc.
        m = re.match(r"list_(?:amazon|aws)?(.+)", stem)
        if m:
            return m.group(1).replace("_", "-")

        # Pattern: s3.html, ec2.html
        if re.match(r"^[a-z0-9\-]+$", stem):
            return stem

        # Try HTML content: look for service prefix in code block
        m = re.search(r"service prefix[:\s]*<code>([a-z0-9\-]+)</code>", content, re.I)
        if m:
            return m.group(1)

        return ""

    def _update_metadata(self) -> None:
        """Update database metadata timestamps."""
        from datetime import datetime, timezone

        self.database.set_metadata("data_source", "aws_docs")
        self.database.set_metadata(
            "last_full_update",
            datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        )

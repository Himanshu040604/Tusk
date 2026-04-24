"""Shared CLI helpers used across the ``cli*`` satellite modules.

Extracted in U13 to close the architectural smell flagged by the
post-v0.8.1 architect review: ``cli_managed`` and ``cli_fetch`` were
reaching into ``cli.py``'s underscore-prefixed "private" helpers
(``_get_formatter``, ``_write_output``, ``_verdict_to_exit_code``),
creating a tight coupling to what the naming convention claimed was
internal API.

This module is a leaf — it imports only from :mod:`exit_codes` and
:mod:`formatters`, both of which are themselves leaves — so it
cannot participate in import cycles.  Every CLI subcommand module
(``cli.py``, ``cli_managed.py``, ``cli_fetch.py``) can import from
here at module top-level.

Public API:
  - :func:`get_formatter`       — select a formatter from argparse.Namespace
  - :func:`write_output`        — write formatted content to file or stdout
  - :func:`verdict_to_exit_code` — map a finding list to the 5-level exit code

``_finding_severity`` stays private: it is an internal helper for
``verdict_to_exit_code`` and a reach-in caller in ``cli._cmd_run_batch``.
"""

from __future__ import annotations

import argparse
from pathlib import Path

from .exit_codes import EXIT_CRITICAL_FINDING, EXIT_ISSUES_FOUND, EXIT_SUCCESS
from .formatters import JsonFormatter, MarkdownFormatter, TextFormatter

__all__ = [
    "get_formatter",
    "write_output",
    "verdict_to_exit_code",
]


def _finding_severity(f: object) -> str:
    """Return the severity string for a finding (dataclass or dict).

    Handles both attribute-style (``f.severity``) and dict-style
    (``f["severity"]``) access.  Enum values are unwrapped via ``.value``.
    """
    sev = f.get("severity", "") if isinstance(f, dict) else getattr(f, "severity", "")
    sev = getattr(sev, "value", sev)
    return str(sev or "").upper()


def verdict_to_exit_code(findings: list) -> int:
    """Map a finding list to the 5-level exit code scheme (Section 7.4).

    Returns EXIT_CRITICAL_FINDING (4) if any finding has severity
    'CRITICAL' or 'HIGH'; EXIT_ISSUES_FOUND (1) if any lower-severity
    findings exist; EXIT_SUCCESS (0) otherwise.
    """
    if not findings:
        return EXIT_SUCCESS
    if any(_finding_severity(f) in {"CRITICAL", "HIGH"} for f in findings):
        return EXIT_CRITICAL_FINDING
    return EXIT_ISSUES_FOUND


def get_formatter(
    args: argparse.Namespace,
) -> TextFormatter | JsonFormatter | MarkdownFormatter:
    """Get the appropriate formatter based on args.

    Args:
        args: Parsed arguments.

    Returns:
        Formatter instance.
    """
    fmt = getattr(args, "output_format", "text")
    if fmt == "json":
        return JsonFormatter()
    if fmt == "markdown":
        return MarkdownFormatter()
    return TextFormatter()


def write_output(args: argparse.Namespace, content: str) -> None:
    """Write formatted output to file or stdout.

    Args:
        args: Parsed arguments.
        content: Formatted output string.
    """
    output_path = getattr(args, "output", None)
    if output_path:
        Path(output_path).write_text(content, encoding="utf-8")
    else:
        print(content)

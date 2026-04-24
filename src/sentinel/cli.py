"""Command-line interface for IAM Policy Sentinel.

Provides argparse-based CLI with subcommands: validate, analyze, rewrite,
run, refresh, and info.
"""

from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import TYPE_CHECKING

from .constants import (
    DEFAULT_DB_PATH,
    DEFAULT_INVENTORY_PATH,
)

if TYPE_CHECKING:  # pragma: no cover
    from .database import Database
    from .inventory import ResourceInventory
from .exit_codes import (
    EXIT_SUCCESS,
    EXIT_ISSUES_FOUND,
    EXIT_INVALID_ARGS,
    EXIT_IO_ERROR,
    EXIT_CRITICAL_FINDING,
)
from .formatters import TextFormatter, JsonFormatter, MarkdownFormatter


def _finding_severity(f: object) -> str:
    """Return the severity string for a finding (dataclass or dict).

    Handles both attribute-style (``f.severity``) and dict-style
    (``f["severity"]``) access.  Enum values are unwrapped via ``.value``.
    """
    sev = f.get("severity", "") if isinstance(f, dict) else getattr(f, "severity", "")
    sev = getattr(sev, "value", sev)
    return str(sev or "").upper()


def _verdict_to_exit_code(findings: list) -> int:
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


def export_services_json(
    database: "Database",
    output_path: Path | None = None,
) -> Path:
    """Export service prefixes from DB to JSON file.

    Args:
        database: Database to query services from.
        output_path: Destination path. Defaults to
            ``data/known_services.json`` relative to project root.

    Returns:
        Path to the written JSON file.
    """
    if output_path is None:
        output_path = Path(__file__).resolve().parent.parent.parent / "data" / "known_services.json"

    services = sorted(s.service_prefix for s in database.get_services())

    data = {
        "_generated": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "_source": str(database.db_path),
        "services": services,
    }

    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
    return output_path


def build_parser() -> argparse.ArgumentParser:
    """Build the argument parser with all subcommands.

    Returns:
        Configured ArgumentParser.
    """
    # Shared parent for common flags
    parent = argparse.ArgumentParser(add_help=False)
    parent.add_argument(
        "-d",
        "--database",
        default=None,
        help="Path to IAM actions SQLite database",
    )
    parent.add_argument(
        "-i",
        "--inventory",
        default=None,
        help="Path to resource inventory SQLite database",
    )
    parent.add_argument(
        "-f",
        "--output-format",
        choices=["text", "json", "markdown"],
        default="text",
        help="Output format (default: text)",
    )
    parent.add_argument(
        "-o",
        "--output",
        default=None,
        help="Write output to file instead of stdout",
    )
    # Issue 5 (v0.8.0): `--force-emit-rewrite` threads through EVERY
    # subcommand that invokes ``format_pipeline_result`` (cmd_run,
    # cmd_fetch, cmd_managed_analyze). Lives on the shared parent so a
    # single definition covers all three callsites. By default (flag
    # absent) a FAIL verdict suppresses the rewrite block to prevent
    # operators piping corrupted output into production.
    parent.add_argument(
        "--force-emit-rewrite",
        action="store_true",
        default=False,
        help=(
            "Emit rewritten policy even when self-check FAILs "
            "(NOT recommended for deployment)"
        ),
    )

    parser = argparse.ArgumentParser(
        prog="sentinel",
        description="IAM Policy Sentinel - Offline IAM policy validation and least-privilege enforcement",
    )
    parser.add_argument(
        "--version",
        action="store_true",
        help="Show version and exit",
    )

    # Root-level flags (§ 7.3).  Parsed before subcommand dispatch; passed
    # down to every handler via the argparse Namespace.  Persistable flags
    # may also be set via config file / env var; ephemeral flags (marked
    # CLI-only per § 5.2) are HARD-FAILED if they appear elsewhere.
    parser.add_argument(
        "--profile",
        default=None,
        help="Activate named profile from config file",
    )
    parser.add_argument(
        "--config",
        default=None,
        help="Override config file path (loaded after system/user/project TOMLs)",
    )
    parser.add_argument(
        "--log-format",
        choices=["human", "json"],
        default=None,
        help="Log output format (default: 'human')",
    )
    parser.add_argument(
        "--log-level",
        choices=["DEBUG", "INFO", "WARNING", "ERROR"],
        default=None,
        help="Log verbosity threshold (default: 'INFO')",
    )
    # Ephemeral flags (§ 5.2) — CLI-only; HARD-FAIL elsewhere.
    parser.add_argument(
        "--insecure",
        action="store_true",
        help="Disable TLS verification (ephemeral; not persistable in config)",
    )
    parser.add_argument(
        "--allow-domain",
        action="append",
        default=[],
        metavar="DOMAIN",
        help="Extend allow-list with DOMAIN (ephemeral; may be repeated)",
    )
    parser.add_argument(
        "--skip-migrations",
        action="store_true",
        help="Bypass Alembic auto-upgrade on startup (ephemeral)",
    )
    parser.add_argument(
        "--cache-dir",
        default=None,
        help="Override cache directory for this run (§ 8.5)",
    )

    subparsers = parser.add_subparsers(dest="command")

    # validate
    p_validate = subparsers.add_parser(
        "validate",
        parents=[parent],
        help="Validate an IAM policy",
    )
    p_validate.add_argument("policy_file", help="Policy file (use - for stdin)")
    p_validate.add_argument(
        "--input-format",
        choices=["auto", "json", "yaml"],
        default="auto",
        help="Input format (default: auto-detect from extension)",
    )

    # analyze
    p_analyze = subparsers.add_parser(
        "analyze",
        parents=[parent],
        help="Analyze an IAM policy for risks",
    )
    p_analyze.add_argument("policy_file", help="Policy file (use - for stdin)")
    p_analyze.add_argument(
        "--input-format",
        choices=["auto", "json", "yaml"],
        default="auto",
        help="Input format (default: auto-detect from extension)",
    )
    p_analyze.add_argument(
        "--intent",
        default=None,
        help="Developer intent description (e.g. 'read-only s3')",
    )

    # rewrite
    p_rewrite = subparsers.add_parser(
        "rewrite",
        parents=[parent],
        help="Rewrite an IAM policy for least privilege",
    )
    p_rewrite.add_argument("policy_file", help="Policy file (use - for stdin)")
    p_rewrite.add_argument(
        "--input-format",
        choices=["auto", "json", "yaml"],
        default="auto",
        help="Input format (default: auto-detect from extension)",
    )
    p_rewrite.add_argument("--intent", default=None, help="Developer intent description")
    p_rewrite.add_argument("--account-id", default=None, help="AWS account ID for ARN generation")
    p_rewrite.add_argument("--region", default=None, help="AWS region for ARN generation")
    p_rewrite.add_argument(
        "--no-companions",
        action="store_true",
        help="Skip adding companion permissions",
    )
    p_rewrite.add_argument(
        "--no-conditions",
        action="store_true",
        help="Skip adding condition keys",
    )
    p_rewrite.add_argument(
        "--policy-type",
        choices=["identity", "resource", "scp", "boundary"],
        default=None,
        help="Policy type (default: auto-detect from structure)",
    )
    p_rewrite.add_argument(
        "--condition-profile",
        choices=["strict", "moderate", "none"],
        default="moderate",
        help="Condition injection profile (default: moderate)",
    )
    p_rewrite.add_argument(
        "--allow-wildcard-actions",
        action="store_true",
        default=False,
        help="Downgrade wildcard action errors to warnings",
    )
    p_rewrite.add_argument(
        "--allow-wildcard-resources",
        action="store_true",
        default=False,
        help="Downgrade wildcard resource errors to warnings",
    )

    # run (full pipeline)
    p_run = subparsers.add_parser(
        "run",
        parents=[parent],
        help="Run the full Validate-Analyze-Rewrite-SelfCheck pipeline",
    )
    p_run.add_argument("policy_file", help="Policy file (use - for stdin)")
    p_run.add_argument(
        "--input-format",
        choices=["auto", "json", "yaml"],
        default="auto",
        help="Input format (default: auto-detect from extension)",
    )
    p_run.add_argument("--intent", default=None, help="Developer intent description")
    p_run.add_argument("--account-id", default=None, help="AWS account ID")
    p_run.add_argument("--region", default=None, help="AWS region")
    p_run.add_argument(
        "--strict",
        action="store_true",
        help="Treat warnings as failures",
    )
    p_run.add_argument(
        "--max-retries",
        type=int,
        default=3,
        help="Maximum self-check loop-back iterations (default: 3)",
    )
    p_run.add_argument(
        "--no-companions",
        action="store_true",
        help="Skip adding companion permissions",
    )
    p_run.add_argument(
        "--no-conditions",
        action="store_true",
        help="Skip adding condition keys",
    )
    p_run.add_argument(
        "--interactive",
        action="store_true",
        default=False,
        help="Prompt for approval of Tier 2 (unknown) actions before rewriting",
    )
    p_run.add_argument(
        "--policy-type",
        choices=["identity", "resource", "scp", "boundary"],
        default=None,
        help="Policy type (default: auto-detect from structure)",
    )
    p_run.add_argument(
        "--condition-profile",
        choices=["strict", "moderate", "none"],
        default="moderate",
        help="Condition injection profile (default: moderate)",
    )
    p_run.add_argument(
        "--allow-wildcard-actions",
        action="store_true",
        default=False,
        help="Downgrade wildcard action errors to warnings",
    )
    p_run.add_argument(
        "--allow-wildcard-resources",
        action="store_true",
        default=False,
        help="Downgrade wildcard resource errors to warnings",
    )

    # refresh
    p_refresh = subparsers.add_parser(
        "refresh",
        parents=[parent],
        help="Refresh IAM actions database from local data files or live sources",
    )
    # M3: --source and --all are mutually exclusive (Amendment 4).
    # One of them must be supplied, but argparse enforces that via
    # required=True on the group.
    refresh_group = p_refresh.add_mutually_exclusive_group(required=True)
    refresh_group.add_argument(
        "--source",
        choices=[
            "policy-sentry",
            "aws-docs",
            "managed-policies",
            "cloudsplaining",
        ],
        help="Data source to refresh",
    )
    refresh_group.add_argument(
        "--all",
        action="store_true",
        help="Refresh all known sources in sequence",
    )
    p_refresh.add_argument(
        "--data-path",
        default=None,
        help=("Path to data file or directory (required for offline refresh; ignored with --live)"),
    )
    p_refresh.add_argument(
        "--live",
        action="store_true",
        help=(
            "Fetch live from network via the hardened HTTP client "
            "(default: read-only from existing DB / local data)"
        ),
    )
    p_refresh.add_argument(
        "--dry-run",
        action="store_true",
        help="Parse and validate without writing to database",
    )
    p_refresh.add_argument(
        "--changelog",
        default=None,
        help="Write changelog to file",
    )

    # info
    subparsers.add_parser(
        "info",
        parents=[parent],
        help="Show database metadata and statistics",
    )

    # export-services
    p_export = subparsers.add_parser(
        "export-services",
        parents=[parent],
        help="Export service prefixes from DB to JSON file",
    )
    p_export.add_argument(
        "--export-output",
        default=None,
        help="Output JSON file path (default: data/known_services.json)",
    )

    # cache (Phase 5 Task 6)
    p_cache = subparsers.add_parser(
        "cache",
        parents=[parent],
        help="Inspect and manage the on-disk HTTP response cache",
    )
    cache_sub = p_cache.add_subparsers(dest="cache_cmd", required=True)
    cache_sub.add_parser("stats", parents=[parent], help="Show cache count + total size")
    cache_sub.add_parser("ls", parents=[parent], help="List cached entries (metadata only)")
    cache_sub.add_parser("purge", parents=[parent], help="Delete every cached entry")
    p_rotate = cache_sub.add_parser(
        "rotate-key",
        parents=[parent],
        help="Regenerate the cache HMAC key (purges all entries)",
    )
    p_rotate.add_argument(
        "--yes",
        action="store_true",
        help="Skip the confirmation prompt",
    )

    # managed (Phase 5 Task 7)
    p_managed = subparsers.add_parser(
        "managed",
        parents=[parent],
        help="Access AWS managed policies stored in the local DB",
    )
    managed_sub = p_managed.add_subparsers(dest="managed_cmd", required=True)
    managed_sub.add_parser("list", parents=[parent], help="List managed policy names")
    p_m_show = managed_sub.add_parser(
        "show",
        parents=[parent],
        help="Print the policy_document for a managed policy",
    )
    p_m_show.add_argument("name", help="Managed policy name")
    p_m_analyze = managed_sub.add_parser(
        "analyze",
        parents=[parent],
        help="Fetch + run the full pipeline on a managed policy",
    )
    p_m_analyze.add_argument("name", help="Managed policy name")

    # config (Phase 5 Task 8)
    p_config = subparsers.add_parser(
        "config",
        parents=[parent],
        help="Inspect and scaffold Sentinel configuration",
    )
    config_sub = p_config.add_subparsers(dest="config_cmd", required=True)
    config_sub.add_parser(
        "show", parents=[parent], help="Dump resolved settings (secrets redacted)"
    )
    config_sub.add_parser("path", parents=[parent], help="Print resolved config file path")
    config_sub.add_parser("init", parents=[parent], help="Scaffold a starter config.toml")

    # fetch (Phase 5 Task 1)
    p_net_fetch = subparsers.add_parser(
        "fetch",
        parents=[parent],
        help="Fetch a policy from a remote source and run the full pipeline",
    )
    source_group = p_net_fetch.add_mutually_exclusive_group(required=True)
    source_group.add_argument("--url", help="HTTPS URL to fetch")
    source_group.add_argument("--github", help="GitHub spec (owner/repo/path)")
    source_group.add_argument("--aws-sample", help="AWS documentation sample policy name")
    source_group.add_argument("--aws-managed", help="AWS managed policy name (DB-backed)")
    source_group.add_argument("--cloudsplaining", help="Cloudsplaining example filename")
    source_group.add_argument(
        "--from-clipboard", action="store_true", help="Read policy JSON from clipboard"
    )
    p_net_fetch.add_argument(
        "--alert-on-new",
        action="store_true",
        help="Hash-compare vs. last fetch; emit WARN on diff",
    )
    p_net_fetch.add_argument("--intent", default=None)
    p_net_fetch.add_argument("--account-id", default=None)
    p_net_fetch.add_argument("--region", default=None)

    # watch (Phase 5 Task 2 — M6)
    p_watch = subparsers.add_parser(
        "watch",
        parents=[parent],
        help="Re-validate policy files on change via watchfiles",
    )
    p_watch.add_argument("path", help="File or directory to watch")

    # wizard (Phase 5 Task 3)
    subparsers.add_parser(
        "wizard",
        parents=[parent],
        help="Interactive intent-to-policy builder",
    )

    # compare (Phase 5 Task 4)
    p_compare = subparsers.add_parser(
        "compare",
        parents=[parent],
        help="Diff two policies' risk profiles",
    )
    p_compare.add_argument("policy_a")
    p_compare.add_argument("policy_b")

    # search (Phase 5 Task 5)
    p_search = subparsers.add_parser(
        "search",
        parents=[parent],
        help="Search GitHub for public IAM policies",
    )
    p_search.add_argument("query")
    p_search.add_argument(
        "--on-github",
        action="store_true",
        default=True,
        help="Run on GitHub (currently the only backend)",
    )
    p_search.add_argument(
        "--limit",
        type=int,
        default=20,
        help="Max results to return (default: 20)",
    )

    # run --batch (Phase 5 Task 9) — extend p_run with batch flags
    p_run.add_argument(
        "--batch",
        default=None,
        metavar="DIR",
        help="Run the pipeline over every policy under DIR",
    )
    p_run.add_argument(
        "--fail-fast",
        action="store_true",
        help="Stop on first failure in batch mode (default: continue)",
    )

    # fetch-examples
    p_fetch = subparsers.add_parser(
        "fetch-examples",
        parents=[parent],
        help="Fetch AWS IAM policy examples, normalize, and benchmark",
    )
    p_fetch.add_argument(
        "--output-dir",
        default=None,
        help="Directory for downloaded examples (default: data/aws_examples)",
    )
    p_fetch.add_argument(
        "--normalize-only",
        action="store_true",
        help="Normalize previously downloaded files without re-fetching",
    )
    p_fetch.add_argument(
        "--benchmark",
        action="store_true",
        help="Run benchmark after normalizing",
    )
    p_fetch.add_argument(
        "--report",
        default=None,
        help="Write benchmark report to file (JSON)",
    )

    return parser


def _detect_format(policy_file: str, input_format: str) -> str:
    """Detect the input format for a policy file.

    Args:
        policy_file: File path or '-' for stdin.
        input_format: Explicit format ('json', 'yaml') or 'auto'.

    Returns:
        Resolved format string: 'json' or 'yaml'.
    """
    if input_format != "auto":
        return input_format

    if policy_file == "-":
        return "json"

    suffix = Path(policy_file).suffix.lower()
    if suffix in (".yaml", ".yml"):
        return "yaml"
    return "json"


def read_policy_input(
    policy_file: str,
    input_format: str = "auto",
) -> tuple[str, str]:
    """Read policy content from file or stdin.

    Args:
        policy_file: File path or '-' for stdin.
        input_format: Explicit format or 'auto' for extension-based detection.

    Returns:
        tuple of (content_string, resolved_format).

    Raises:
        FileNotFoundError: If file cannot be read.
    """
    fmt = _detect_format(policy_file, input_format)

    if policy_file == "-":
        return sys.stdin.read(), fmt

    path = Path(policy_file)
    if not path.exists():
        raise FileNotFoundError(f"Policy file not found: {policy_file}")

    return path.read_text(encoding="utf-8"), fmt


def _get_formatter(
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


def _write_output(args: argparse.Namespace, content: str) -> None:
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


def _resolve_db_path_for_migration(args: argparse.Namespace) -> Path:
    """Return an absolute path to the IAM DB for migration purposes.

    Unlike ``resolve_database`` which only returns a handle if the DB
    exists, this always returns a path (migrations may need to create the
    DB or stamp an empty file).
    """
    explicit = getattr(args, "database", None)
    if explicit:
        return Path(explicit).resolve()
    pkg_dir = Path(__file__).resolve().parent.parent.parent
    pkg_path = pkg_dir / DEFAULT_DB_PATH
    if pkg_path.exists():
        return pkg_path.resolve()
    return (Path.cwd() / DEFAULT_DB_PATH).resolve()


def _resolve_inventory_path_for_migration(
    args: argparse.Namespace,
) -> Path | None:
    """Return an absolute path to the inventory DB, or None if no inventory.

    Migrations only process the inventory DB when the file already exists
    on disk — inventory is opt-in per M18.  Explicit ``--inventory`` flag
    always returns a path (may not exist yet).
    """
    explicit = getattr(args, "inventory", None)
    if explicit:
        return Path(explicit).resolve()
    pkg_dir = Path(__file__).resolve().parent.parent.parent
    pkg_path = pkg_dir / DEFAULT_INVENTORY_PATH
    if pkg_path.exists():
        return pkg_path.resolve()
    cwd_path = Path.cwd() / DEFAULT_INVENTORY_PATH
    if cwd_path.exists():
        return cwd_path.resolve()
    return None


def resolve_database(args: argparse.Namespace) -> "Database | None":
    """Resolve and open the IAM actions database.

    Search order: explicit --database flag, DEFAULT_DB_PATH relative to
    package dir, DEFAULT_DB_PATH relative to cwd.

    Args:
        args: Parsed arguments.

    Returns:
        Database instance or None if not found.
    """
    from .database import Database, DatabaseError

    explicit = getattr(args, "database", None)
    if explicit:
        path = Path(explicit)
        if path.exists():
            return Database(path, read_only=True)
        return None

    # Try relative to package directory
    pkg_dir = Path(__file__).resolve().parent.parent.parent
    pkg_path = pkg_dir / DEFAULT_DB_PATH
    if pkg_path.exists():
        return Database(pkg_path, read_only=True)

    # Try relative to cwd
    cwd_path = Path.cwd() / DEFAULT_DB_PATH
    if cwd_path.exists():
        return Database(cwd_path, read_only=True)

    return None


def resolve_inventory(
    args: argparse.Namespace,
) -> "ResourceInventory | None":
    """Resolve and open the resource inventory database.

    Same search order as resolve_database.

    Args:
        args: Parsed arguments.

    Returns:
        ResourceInventory instance or None if not found.
    """
    from .inventory import ResourceInventory

    explicit = getattr(args, "inventory", None)
    if explicit:
        path = Path(explicit)
        if path.exists():
            return ResourceInventory(path, read_only=True)
        return None

    pkg_dir = Path(__file__).resolve().parent.parent.parent
    pkg_path = pkg_dir / DEFAULT_INVENTORY_PATH
    if pkg_path.exists():
        return ResourceInventory(pkg_path, read_only=True)

    cwd_path = Path.cwd() / DEFAULT_INVENTORY_PATH
    if cwd_path.exists():
        return ResourceInventory(cwd_path, read_only=True)

    return None


def cmd_validate(args: argparse.Namespace) -> int:
    """Execute the validate subcommand.

    Args:
        args: Parsed arguments.

    Returns:
        Exit code.
    """
    from .parser import PolicyParser, PolicyParserError, ValidationError
    from .parser import ValidationTier

    try:
        content, fmt = read_policy_input(args.policy_file, args.input_format)
    except FileNotFoundError as e:
        print(f"Error: {e}", file=sys.stderr)
        return EXIT_IO_ERROR

    db = resolve_database(args)
    parser = PolicyParser(db)

    try:
        policy = parser.parse_policy_auto(content, fmt)
    except ValidationError as e:
        print(f"Error: {e}", file=sys.stderr)
        return EXIT_IO_ERROR
    except PolicyParserError as e:
        print(f"Error: {e}", file=sys.stderr)
        return EXIT_INVALID_ARGS

    try:
        results = parser.validate_policy(policy)
    except ValidationError as e:
        print(f"Error: {e}", file=sys.stderr)
        return EXIT_IO_ERROR

    formatter = _get_formatter(args)
    output = formatter.format_validation(results, policy)
    _write_output(args, output)

    has_invalid = any(r.tier == ValidationTier.TIER_3_INVALID for r in results)
    return EXIT_ISSUES_FOUND if has_invalid else EXIT_SUCCESS


def cmd_analyze(args: argparse.Namespace) -> int:
    """Execute the analyze subcommand.

    Args:
        args: Parsed arguments.

    Returns:
        Exit code.
    """
    from .parser import PolicyParser, PolicyParserError
    from .analyzer import RiskAnalyzer, CompanionPermissionDetector

    try:
        content, fmt = read_policy_input(args.policy_file, args.input_format)
    except FileNotFoundError as e:
        print(f"Error: {e}", file=sys.stderr)
        return EXIT_IO_ERROR

    db = resolve_database(args)
    parser = PolicyParser(db)

    try:
        policy = parser.parse_policy_auto(content, fmt)
    except PolicyParserError as e:
        print(f"Error: {e}", file=sys.stderr)
        return EXIT_INVALID_ARGS

    all_actions = []
    for stmt in policy.statements:
        all_actions.extend(stmt.actions)
        if stmt.not_actions:
            all_actions.extend(stmt.not_actions)

    try:
        risk_analyzer = RiskAnalyzer(db)
    except Exception as e:  # noqa: BLE001 — maps DatabaseError + ConfigError.
        from .database import DatabaseError
        from .config import ConfigError

        if isinstance(e, (DatabaseError, ConfigError)):
            print(f"Error: {e}", file=sys.stderr)
            return EXIT_IO_ERROR
        raise
    findings = risk_analyzer.analyze_actions(all_actions)

    formatter = _get_formatter(args)
    output = formatter.format_risk_findings(findings)
    _write_output(args, output)

    return _verdict_to_exit_code(findings)


def cmd_rewrite(args: argparse.Namespace) -> int:
    """Execute the rewrite subcommand.

    Args:
        args: Parsed arguments.

    Returns:
        Exit code.
    """
    from .parser import PolicyParser, PolicyParserError
    from .rewriter import PolicyRewriter, RewriteConfig

    try:
        content, fmt = read_policy_input(args.policy_file, args.input_format)
    except FileNotFoundError as e:
        print(f"Error: {e}", file=sys.stderr)
        return EXIT_IO_ERROR

    db = resolve_database(args)
    inv = resolve_inventory(args)
    parser = PolicyParser(db)

    try:
        policy = parser.parse_policy_auto(content, fmt)
    except PolicyParserError as e:
        print(f"Error: {e}", file=sys.stderr)
        return EXIT_INVALID_ARGS

    config = RewriteConfig(
        intent=args.intent,
        account_id=args.account_id,
        region=args.region,
        add_companions=not args.no_companions,
        add_conditions=not args.no_conditions,
        policy_type=getattr(args, "policy_type", None),
        condition_profile=getattr(args, "condition_profile", "moderate"),
    )

    try:
        rewriter = PolicyRewriter(db, inv)
    except Exception as e:  # noqa: BLE001 — maps DatabaseError + ConfigError.
        from .database import DatabaseError
        from .config import ConfigError

        if isinstance(e, (DatabaseError, ConfigError)):
            print(f"Error: {e}", file=sys.stderr)
            return EXIT_IO_ERROR
        raise
    result = rewriter.rewrite_policy(policy, config)

    formatter = _get_formatter(args)
    output = formatter.format_rewrite_result(result)
    _write_output(args, output)

    return EXIT_SUCCESS


def cmd_run(args: argparse.Namespace) -> int:
    """Execute the run subcommand (full pipeline).

    Args:
        args: Parsed arguments.

    Returns:
        Exit code.
    """
    from .parser import PolicyParser, PolicyParserError, ValidationError
    from .self_check import Pipeline, PipelineConfig
    from .models import PolicyInput, PolicyOrigin
    from .fetchers.local import LocalFileFetcher, StdinFetcher
    from .fetchers.base import PolicyNotFoundError

    # Phase 5 Task 9: batch fan-out.  When --batch is supplied, iterate
    # BatchFetcher.iter_fetch and run the pipeline per file; honour
    # --fail-fast.  Aggregates into a per-file JSON report when -o is set.
    if getattr(args, "batch", None):
        return _cmd_run_batch(args)

    # Detect format up front so we can decide whether YAML→JSON
    # conversion is needed after fetching.
    fmt = _detect_format(args.policy_file, args.input_format)

    # Fetch raw bytes via the appropriate fetcher so we get a proper
    # PolicyOrigin (sha256, source_type, source_spec) attached to the
    # PolicyInput handed to Pipeline.run — avoids the deprecated
    # raw-string path.
    try:
        if args.policy_file == "-":
            fetch_result = StdinFetcher().fetch("-")
        else:
            fetch_result = LocalFileFetcher().fetch(args.policy_file)
    except PolicyNotFoundError as e:
        print(f"Error: {e}", file=sys.stderr)
        return EXIT_IO_ERROR

    body_bytes = fetch_result.body
    origin = fetch_result.origin

    # Pipeline.run() expects a JSON string internally.
    # If the input is YAML, deserialize then re-serialize to JSON —
    # preserving the fetcher's origin (sha256 of the original bytes,
    # source_type) but annotating source_spec so the origin badge
    # records the round-trip.
    if fmt == "yaml":
        try:
            import yaml
        except ImportError:
            print(
                "Error: PyYAML is required for YAML input. Install it with: pip install pyyaml",
                file=sys.stderr,
            )
            return EXIT_INVALID_ARGS
        try:
            data = yaml.safe_load(body_bytes.decode("utf-8"))
        except yaml.YAMLError as e:
            print(f"Error: Invalid YAML: {e}", file=sys.stderr)
            return EXIT_INVALID_ARGS
        if not isinstance(data, dict):
            print(
                f"Error: YAML content must be a mapping, got {type(data).__name__}",
                file=sys.stderr,
            )
            return EXIT_INVALID_ARGS
        body_bytes = json.dumps(data).encode("utf-8")
        origin = PolicyOrigin(
            source_type=origin.source_type,
            source_spec=f"{origin.source_spec} (yaml->json)",
            sha256=origin.sha256,
            fetched_at=origin.fetched_at,
            cache_status=origin.cache_status,
        )

    policy_input = PolicyInput(body_bytes=body_bytes, origin=origin)

    db = resolve_database(args)
    inv = resolve_inventory(args)

    config = PipelineConfig(
        intent=args.intent,
        account_id=args.account_id,
        region=args.region,
        strict_mode=args.strict,
        max_self_check_retries=args.max_retries,
        add_companions=not args.no_companions,
        add_conditions=not args.no_conditions,
        interactive=args.interactive,
        policy_type=getattr(args, "policy_type", None),
        condition_profile=getattr(args, "condition_profile", "moderate"),
        allow_wildcard_actions=getattr(args, "allow_wildcard_actions", False),
        allow_wildcard_resources=getattr(args, "allow_wildcard_resources", False),
    )

    try:
        pipeline = Pipeline(db, inv)
    except Exception as e:  # noqa: BLE001 — maps DatabaseError + subtypes.
        from .database import DatabaseError

        if isinstance(e, DatabaseError):
            print(f"Error: {e}", file=sys.stderr)
            return EXIT_IO_ERROR
        raise

    try:
        result = pipeline.run(policy_input, config=config)
    except ValidationError as e:
        print(f"Error: {e}", file=sys.stderr)
        return EXIT_IO_ERROR
    except PolicyParserError as e:
        print(f"Error: {e}", file=sys.stderr)
        return EXIT_INVALID_ARGS

    formatter = _get_formatter(args)
    # Issue 5 (v0.8.0): thread --force-emit-rewrite through to the formatter
    # so FAIL verdicts suppress rewrite output unless the operator bypassed.
    force_emit = getattr(args, "force_emit_rewrite", False)
    # v0.8.1 (M2): when bypass is active AND self-check would have FAILed,
    # emit a structlog audit trail entry so downstream log aggregators /
    # SIEMs can alert on bypass events (OWASP A09 — Security Logging &
    # Monitoring Failure closure).
    from .self_check import CheckVerdict

    if force_emit and result.self_check_result.verdict == CheckVerdict.FAIL:
        import structlog

        structlog.get_logger("sentinel.safety").warning(
            "force_emit_rewrite_bypass",
            verdict="FAIL",
            subcommand="run",
        )
    output = formatter.format_pipeline_result(result, force_emit=force_emit)
    _write_output(args, output)

    findings = list(result.risk_findings) + list(getattr(result.self_check_result, "findings", []))
    return _verdict_to_exit_code(findings)


def _cmd_run_batch(args: argparse.Namespace) -> int:
    """Fan-out ``sentinel run --batch <dir>`` (Phase 5 Task 9).

    Iterates :meth:`BatchFetcher.iter_fetch` and invokes the Pipeline
    per file.  ``--fail-fast`` stops at the first non-success exit code;
    otherwise every file is processed and the worst exit code is
    returned.  A per-file JSON report is written to ``-o`` when set.
    """
    from .fetchers.batch import BatchFetcher
    from .fetchers.base import PolicyNotFoundError
    from .models import PolicyInput
    from .self_check import Pipeline, PipelineConfig

    db = resolve_database(args)
    inv = resolve_inventory(args)
    config = PipelineConfig(
        intent=args.intent,
        account_id=args.account_id,
        region=args.region,
        strict_mode=args.strict,
        max_self_check_retries=args.max_retries,
        add_companions=not args.no_companions,
        add_conditions=not args.no_conditions,
        interactive=False,
        policy_type=getattr(args, "policy_type", None),
        condition_profile=getattr(args, "condition_profile", "moderate"),
    )
    try:
        pipeline = Pipeline(db, inv)
    except Exception as exc:  # noqa: BLE001
        print(f"Error: {exc}", file=sys.stderr)
        return EXIT_IO_ERROR

    worst = EXIT_SUCCESS
    tally = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    entries: list[dict] = []
    try:
        results = list(BatchFetcher().iter_fetch(args.batch))
    except PolicyNotFoundError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return EXIT_IO_ERROR

    for fr in results:
        policy_input = PolicyInput(body_bytes=fr.body, origin=fr.origin)
        try:
            result = pipeline.run(policy_input, config=config)
        except Exception as exc:  # noqa: BLE001 — per-file resilience.
            print(f"[WARN] {fr.origin.source_spec}: {exc}", file=sys.stderr)
            entries.append(
                {
                    "source": fr.origin.source_spec,
                    "error": str(exc),
                    "exit_code": EXIT_IO_ERROR,
                }
            )
            worst = max(worst, EXIT_IO_ERROR)
            if getattr(args, "fail_fast", False):
                break
            continue
        findings = list(result.risk_findings) + list(
            getattr(result.self_check_result, "findings", [])
        )
        for f in findings:
            sev = _finding_severity(f).lower()
            if sev in tally:
                tally[sev] += 1
        rc = _verdict_to_exit_code(findings)
        entries.append(
            {
                "source": fr.origin.source_spec,
                "sha256": fr.origin.sha256,
                "findings": len(findings),
                "exit_code": rc,
            }
        )
        if rc != EXIT_SUCCESS:
            worst = max(worst, rc)
            if getattr(args, "fail_fast", False):
                break

    print(
        f"Processed {len(entries)} policies: "
        f"{tally['critical']} CRITICAL, {tally['high']} HIGH, "
        f"{tally['medium']} MEDIUM, {tally['low']} LOW, "
        f"{tally['info']} INFO"
    )
    out = getattr(args, "output", None)
    if out:
        payload = {"summary": tally, "entries": entries}
        Path(out).write_text(json.dumps(payload, indent=2), encoding="utf-8")
        print(f"Batch report written to {out}")
    return worst


_LEGACY_SOURCES = frozenset({"policy-sentry", "aws-docs"})
_NEW_SOURCES = frozenset({"managed-policies", "cloudsplaining"})


def cmd_refresh(args: argparse.Namespace) -> int:
    """Execute the refresh subcommand.

    Lazy-imports from the refresh package to avoid loading scraper
    dependencies for normal validation.

    Args:
        args: Parsed arguments.

    Returns:
        Exit code.
    """
    from .database import Database, DatabaseError

    db_path = getattr(args, "database", None) or DEFAULT_DB_PATH

    # --all unfolds into a loop over every known source; recurse on a
    # per-source namespace so each path uses the normal single-source
    # dispatcher below.
    if getattr(args, "all", False):
        return _cmd_refresh_all(args)

    source = args.source
    if source in _NEW_SOURCES:
        return _cmd_refresh_new_source(args, source, db_path)

    # Legacy sources (policy-sentry, aws-docs) require --data-path.
    if args.data_path is None:
        print(
            "Error: --data-path is required for source "
            f"{source!r} (no --live path wired in Phase 4).",
            file=sys.stderr,
        )
        return EXIT_INVALID_ARGS
    data_path = Path(args.data_path)

    if not data_path.exists():
        print(f"Error: Data path not found: {data_path}", file=sys.stderr)
        return EXIT_IO_ERROR

    if args.dry_run:
        # Dry-run: validate data using in-memory DB (no disk writes)
        if args.source == "policy-sentry":
            from .refresh.policy_sentry_loader import PolicySentryLoader

            db = Database(Path(":memory:"))
            db.create_schema()
            loader = PolicySentryLoader(db)
            errors = loader.validate_data(data_path)
        else:
            from .refresh.aws_docs_scraper import AwsDocsScraper

            db = Database(Path(":memory:"))
            db.create_schema()
            scraper = AwsDocsScraper(db)
            errors = scraper.validate_data(data_path)

        if errors:
            for err in errors:
                print(f"[WARN] {err}", file=sys.stderr)
            return EXIT_ISSUES_FOUND
        print("Dry-run: data is valid.")
        return EXIT_SUCCESS

    try:
        db = Database(Path(db_path))
        db.create_schema()
    except DatabaseError as e:
        print(f"Error: {e}", file=sys.stderr)
        return EXIT_IO_ERROR

    if args.source == "policy-sentry":
        from .refresh.policy_sentry_loader import PolicySentryLoader

        loader = PolicySentryLoader(db)
        if data_path.is_dir():
            stats, changelog = loader.load_from_directory(data_path)
        else:
            stats, changelog = loader.load_from_file(data_path)
    else:
        from .refresh.aws_docs_scraper import AwsDocsScraper

        scraper = AwsDocsScraper(db)
        if data_path.is_dir():
            stats, changelog = scraper.load_from_directory(data_path)
        else:
            stats, changelog = scraper.load_from_file(data_path)

    print(
        f"Refresh complete: "
        f"{stats.services_added} services, "
        f"{stats.actions_added} actions, "
        f"{stats.resource_types_added} resource types, "
        f"{stats.condition_keys_added} condition keys"
    )

    if stats.errors:
        for err in stats.errors:
            print(f"[WARN] {err}", file=sys.stderr)

    if args.changelog and changelog:
        changelog_lines = []
        for entry in changelog:
            changelog_lines.append(
                f"[{entry.change_type}] {entry.entity_type}: {entry.entity_name} - {entry.detail}"
            )
        Path(args.changelog).write_text("\n".join(changelog_lines), encoding="utf-8")
        print(f"Changelog written to {args.changelog}")

    # Auto-export known_services.json after successful refresh
    try:
        written = export_services_json(db)
        print(f"Auto-exported services to {written}")
    except Exception as e:
        print(f"[WARN] Auto-export failed: {e}", file=sys.stderr)

    return EXIT_SUCCESS


def _cmd_refresh_new_source(
    args: argparse.Namespace,
    source: str,
    db_path: str,
) -> int:
    """Dispatch Phase 4 refresh sources (managed-policies, cloudsplaining).

    Supports ``--live`` (fetch via SentinelHTTPClient) and offline
    (``--data-path`` local JSON file/dir).  ``--dry-run`` treats the
    work as a validation-only pass using an in-memory database.
    """
    from .database import Database, DatabaseError

    try:
        target_path = Path(":memory:") if args.dry_run else Path(db_path)
        db = Database(target_path)
        db.create_schema()
    except DatabaseError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return EXIT_IO_ERROR

    if args.live:
        return _refresh_live(db, source)

    if args.data_path is None:
        print(
            f"Error: --data-path is required for source {source!r} (offline mode).",
            file=sys.stderr,
        )
        return EXIT_INVALID_ARGS
    data_path = Path(args.data_path)
    if not data_path.exists():
        print(f"Error: Data path not found: {data_path}", file=sys.stderr)
        return EXIT_IO_ERROR

    stats: object
    if source == "managed-policies":
        from .refresh.aws_managed_policies import ManagedPoliciesLoader

        mp_loader = ManagedPoliciesLoader(db)
        mp_stats = (
            mp_loader.load_from_directory(data_path)
            if data_path.is_dir()
            else mp_loader.load_from_file(data_path)
        )
        print(
            f"Refresh complete: {mp_stats.policies_added} added, "
            f"{mp_stats.policies_updated} updated."
        )
        stats = mp_stats
    else:  # cloudsplaining
        from .refresh.cloudsplaining import CloudSplainingLoader

        cs_loader = CloudSplainingLoader(db)
        cs_stats = (
            cs_loader.load_from_directory(data_path)
            if data_path.is_dir()
            else cs_loader.load_from_file(data_path)
        )
        print(
            f"Refresh complete: {cs_stats.actions_added} dangerous actions, "
            f"{cs_stats.combinations_added} combinations, "
            f"{cs_stats.skipped} skipped."
        )
        stats = cs_stats
    for err in stats.errors:
        print(f"[WARN] {err}", file=sys.stderr)
    return EXIT_SUCCESS


_MANAGED_POLICY_SEEDS: tuple[tuple[str, str, str], ...] = (
    # (policy_name, arn, url) — minimal curated seed so --live has something
    # to enumerate before a full index scraper lands.
    (
        "AdministratorAccess",
        "arn:aws:iam::aws:policy/AdministratorAccess",
        "https://docs.aws.amazon.com/IAM/latest/UserGuide/"
        "policy-reference/aws-managed/AdministratorAccess.json",
    ),
    (
        "ReadOnlyAccess",
        "arn:aws:iam::aws:policy/ReadOnlyAccess",
        "https://docs.aws.amazon.com/IAM/latest/UserGuide/"
        "policy-reference/aws-managed/ReadOnlyAccess.json",
    ),
)


_CLOUDSPLAINING_RULESET_URL = (
    "https://raw.githubusercontent.com/"
    "salesforce/cloudsplaining/main/"
    "cloudsplaining/shared/iam_definition.json"
)


def _build_live_client():
    """Share one client builder between fetch and refresh paths."""
    from .cli_fetch import _build_http_client

    return _build_http_client()


def _refresh_live(db, source: str) -> int:
    """Run the live scraper for Phase 4 sources (Task 11).

    ``managed-policies`` enumerates :data:`_MANAGED_POLICY_SEEDS` and
    upserts each.  ``cloudsplaining`` fetches the full ruleset JSON
    and ingests it.  Errors per-source aggregate into the stats block.
    """
    if source == "managed-policies":
        from .refresh.aws_managed_policies import ManagedPoliciesLiveScraper

        client = _build_live_client()
        try:
            scraper = ManagedPoliciesLiveScraper(db, client)
            added = 0
            updated = 0
            errors: list[str] = []
            for name, arn, url in _MANAGED_POLICY_SEEDS:
                try:
                    change = scraper.scrape_one(name=name, arn=arn, url=url)
                    if change == "ADD":
                        added += 1
                    else:
                        updated += 1
                except Exception as exc:  # noqa: BLE001
                    errors.append(f"{name}: {exc}")
        finally:
            client.close()
        print(f"Refresh complete: {added} added, {updated} updated.")
        for err in errors:
            print(f"[WARN] {err}", file=sys.stderr)
        return EXIT_SUCCESS if not errors else EXIT_ISSUES_FOUND

    if source == "cloudsplaining":
        from .refresh.cloudsplaining import CloudSplainingLiveFetcher

        # Architect Concern 3 (v0.6.2): use context manager so the client is
        # closed even if an exception fires between _build_live_client() and
        # the try-block.  SentinelHTTPClient.__enter__/__exit__ is defined
        # in net/client.py.
        with _build_live_client() as client:
            try:
                fetcher = CloudSplainingLiveFetcher(db, client)
                stats = fetcher.fetch_and_load(_CLOUDSPLAINING_RULESET_URL)
            except Exception as exc:  # noqa: BLE001
                print(f"Error: cloudsplaining live fetch failed: {exc}", file=sys.stderr)
                return EXIT_IO_ERROR
        print(
            f"Refresh complete: {stats.actions_added} dangerous actions, "
            f"{stats.combinations_added} combinations, "
            f"{stats.skipped} skipped."
        )
        for err in stats.errors:
            print(f"[WARN] {err}", file=sys.stderr)
        return EXIT_SUCCESS

    print(f"Error: --live not supported for source {source!r}", file=sys.stderr)
    return EXIT_INVALID_ARGS


def _cmd_refresh_all(args: argparse.Namespace) -> int:
    """Run every known refresh source in sequence (Task 10).

    Each source is invoked via a synthetic ``argparse.Namespace`` so the
    single-source dispatcher does the heavy lifting.  When ``--live`` is
    set on the parent call, it's propagated to every child; the per-source
    exit codes are aggregated and the worst is returned.
    """
    all_sources = ("policy-sentry", "aws-docs", "managed-policies", "cloudsplaining")
    worst = EXIT_SUCCESS
    for src in all_sources:
        print(f"\n=== refresh: {src} ===", file=sys.stderr)
        sub = argparse.Namespace(**vars(args))
        sub.source = src
        sub.all = False
        # Legacy sources NEED --data-path; skip them when --live is on
        # without a fallback — operators should run them explicitly.
        if src in _LEGACY_SOURCES and not args.data_path:
            print(
                f"[WARN] skipping {src}: --data-path required "
                "(legacy source has no live CLI wiring)",
                file=sys.stderr,
            )
            continue
        try:
            rc = cmd_refresh(sub)
        except Exception as exc:  # noqa: BLE001
            print(f"[ERROR] {src}: {exc}", file=sys.stderr)
            rc = EXIT_IO_ERROR
        if rc != EXIT_SUCCESS:
            worst = max(worst, rc)
    return worst


def cmd_info(args: argparse.Namespace) -> int:
    """Execute the info subcommand.

    Args:
        args: Parsed arguments.

    Returns:
        Exit code.
    """
    db = resolve_database(args)
    if db is None:
        print("No database found. Use --database to specify path.", file=sys.stderr)
        return EXIT_IO_ERROR

    with db.get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT COUNT(*) as c FROM services")
        service_count = cursor.fetchone()["c"]
        cursor.execute("SELECT COUNT(*) as c FROM actions")
        action_count = cursor.fetchone()["c"]
        cursor.execute("SELECT key, value FROM metadata")
        metadata = {row["key"]: row["value"] for row in cursor.fetchall()}

    # Phase 5 Task 12: surface the current Alembic revision.  Uses the
    # read-only helper from :mod:`sentinel.migrations` — defensive so a
    # pre-Alembic DB still renders the rest of the info block.
    try:
        from .migrations import _current_revision

        rev = _current_revision(db.db_path)
        if rev is not None:
            metadata.setdefault("alembic_revision", rev)
    except Exception as exc:  # noqa: BLE001
        metadata.setdefault("alembic_revision", f"<error: {exc}>")

    formatter = _get_formatter(args)
    output = formatter.format_db_info(metadata, service_count, action_count)
    _write_output(args, output)

    # Issue 3 (v0.8.0): also surface the empty-corpus banner from `sentinel
    # info` so operators see it even when they're diagnosing DB state.
    if service_count == 0 or action_count == 0:
        print(
            "[WARN] AWS action corpus is empty (services: 0, actions: 0). "
            "Run: sentinel refresh --source policy-sentry --data-path <path-to-policy_sentry-json> "
            "to populate it. Without this, all actions classify as Tier 2 (unknown) "
            "and the rewriter operates in degraded mode.",
            file=sys.stderr,
        )

    return EXIT_SUCCESS


def cmd_export_services(args: argparse.Namespace) -> int:
    """Execute the export-services subcommand.

    Args:
        args: Parsed arguments.

    Returns:
        Exit code.
    """
    db = resolve_database(args)
    if db is None:
        print(
            "No database found. Use --database to specify path.",
            file=sys.stderr,
        )
        return EXIT_IO_ERROR

    output_path = None
    output_arg = getattr(args, "export_output", None)
    if output_arg:
        output_path = Path(output_arg)

    written = export_services_json(db, output_path)
    print(f"Exported services to {written}")
    return EXIT_SUCCESS


def cmd_fetch_examples(args: argparse.Namespace) -> int:
    """Execute the fetch-examples subcommand.

    Args:
        args: Parsed arguments.

    Returns:
        Exit code.
    """
    from .refresh.aws_examples import (
        ExampleFetcher,
        PolicyNormalizer,
        BenchmarkRunner,
        BenchmarkReporter,
    )

    pkg_dir = Path(__file__).resolve().parent.parent.parent
    output_arg = getattr(args, "output_dir", None)
    base_dir = Path(output_arg) if output_arg else pkg_dir / "data" / "aws_examples"
    raw_dir = base_dir / "raw"
    norm_dir = base_dir / "normalized"

    if not getattr(args, "normalize_only", False):
        try:
            fetcher = ExampleFetcher(raw_dir)
            files = fetcher.fetch_all()
            print(f"Downloaded {len(files)} JSON files to {raw_dir}")
        except RuntimeError as e:
            print(f"Error: {e}", file=sys.stderr)
            return EXIT_IO_ERROR

    normalizer = PolicyNormalizer(raw_dir, norm_dir)
    policies = normalizer.normalize_all()
    print(f"Normalized {len(policies)} IAM policies to {norm_dir}")

    if not getattr(args, "benchmark", False):
        return EXIT_SUCCESS

    db = resolve_database(args)
    inv = resolve_inventory(args)
    runner = BenchmarkRunner(db, inv)
    entries = runner.run_benchmark(policies)

    reporter = BenchmarkReporter()
    report = reporter.generate_report(entries)
    print(reporter.format_text(report))

    report_path = getattr(args, "report", None)
    if report_path:
        Path(report_path).write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
        print(f"Report written to {report_path}")

    return EXIT_SUCCESS


def _bootstrap_config_and_logging(args: argparse.Namespace) -> None:
    """Resolve Settings and configure structlog BEFORE subcommand dispatch.

    Runs the Amendment 6 Theme F3 ``SENTINEL_SKIP_MIGRATIONS`` loud-warn
    check, builds the Settings via :func:`sentinel.config.load_settings`,
    installs it as the process-wide singleton for downstream modules,
    configures structlog per the resolved log-level/log-format, and emits
    the M15 ``SSL_CERT_FILE`` audit WARN (post-configure, pre-dispatch).

    CLI override dict passed to load_settings is restricted to ephemeral
    keys + the persistable root flags; argparse defaults of ``None`` /
    ``False`` / ``[]`` are dropped so they don't stomp TOML / env values.
    """
    # Local imports keep `import sentinel.cli` light — pydantic + structlog
    # are paid for only when the CLI actually runs.
    from .config import ConfigError, load_settings, set_settings, warn_if_skip_migrations_env
    from .logging_setup import configure as configure_logging
    from .logging_setup import ssl_cert_file_audit

    # SENTINEL_SKIP_MIGRATIONS env-var carve-out.  Fires BEFORE logging is
    # configured so it goes straight to raw stderr via print().
    env_skip = warn_if_skip_migrations_env()

    # Assemble CLI override dict.  Only include values the user actually
    # supplied (non-default) so TOML / env values aren't masked.
    cli_overrides: dict = {}
    if args.log_level is not None:
        cli_overrides.setdefault("logging", {})["level"] = args.log_level
    if args.log_format is not None:
        cli_overrides.setdefault("logging", {})["format"] = args.log_format
    if args.insecure:
        cli_overrides["insecure"] = True
    if args.allow_domain:
        cli_overrides["allow_domain"] = list(args.allow_domain)
    # skip_migrations arrives EITHER from the CLI flag OR from the env.
    if args.skip_migrations or env_skip:
        cli_overrides["skip_migrations"] = True

    config_path = Path(args.config) if args.config else None

    try:
        settings = load_settings(
            cli_overrides=cli_overrides or None,
            config_path_override=config_path,
            profile_override=args.profile,
        )
    except ConfigError as exc:
        # Logging not yet configured — go straight to stderr.
        print(str(exc), file=sys.stderr)
        sys.exit(EXIT_INVALID_ARGS)

    set_settings(settings)

    configure_logging(
        level=settings.logging.level,
        fmt=settings.logging.format,
    )

    # M15 audit WARN — AFTER configure so the redact_sensitive processor
    # is active, BEFORE any subcommand fires a network call.
    ssl_cert_file_audit()


def main() -> None:
    """CLI entry point. Dispatches to subcommand handlers."""
    from . import __version__

    parser = build_parser()
    args = parser.parse_args()

    if args.version:
        print(f"IAM Policy Sentinel v{__version__}")
        sys.exit(EXIT_SUCCESS)

    # Bootstrap config + logging unless the user only asked for --help /
    # --version.  Handlers see the resolved Settings via the singleton
    # (sentinel.config.get_settings()).
    _bootstrap_config_and_logging(args)

    if args.command is None:
        parser.print_help()
        sys.exit(EXIT_INVALID_ARGS)

    # Alembic auto-upgrade (§ 6.3).  Skip for commands that don't touch the
    # DB (`config path` — opt-in skip list).  Runs AFTER argparse, BEFORE
    # subcommand dispatch so every DB-touching handler sees a migrated
    # schema.  Honors --skip-migrations and SENTINEL_SKIP_MIGRATIONS=1.
    _MIGRATION_SKIP_COMMANDS: frozenset[str] = frozenset()  # reserved for `config path` etc.
    if args.command not in _MIGRATION_SKIP_COMMANDS:
        try:
            from .migrations import check_and_upgrade_all_dbs

            iam_db = _resolve_db_path_for_migration(args)
            inv_db = _resolve_inventory_path_for_migration(args)
            check_and_upgrade_all_dbs(
                iam_db,
                inv_db,
                skip=getattr(args, "skip_migrations", False),
            )
        except OSError as e:
            print(f"[ERROR] Migration I/O error: {e}", file=sys.stderr)
            sys.exit(EXIT_IO_ERROR)
        except Exception as e:  # noqa: BLE001 — migrations either work or abort.
            print(f"[ERROR] Migration failed: {e}", file=sys.stderr)
            sys.exit(EXIT_IO_ERROR)

        # § 12 Phase 2 Task 4 / Step 1: seed baseline classification rows
        # on first run.  Idempotent — empty-table probe skips the call on
        # every subsequent invocation.  Runs ONLY for the IAM DB; inventory
        # DB has no shipped-baseline rows.
        #
        # Phase 7.1 silent-failure B3: previously this swallowed any seed
        # failure as `[WARN] Baseline seed skipped` and continued with an
        # empty dangerous_actions table.  That composes with parser-layer
        # silent demotions to produce fail-open: analyzer finds zero risks
        # on admin-privilege policies because its classification tables
        # are empty.  Abort instead.
        try:
            from .database import Database as _SeedDB
            from .seed_data import seed_all_baseline

            _probe_db = _SeedDB(iam_db)
            if _probe_db.is_empty("dangerous_actions"):
                counts = seed_all_baseline(iam_db)
                print(
                    f"[INFO] Seeded baseline classification rows: {counts}",
                    file=sys.stderr,
                )
        except Exception as exc:  # noqa: BLE001 — loud abort replaces silent warn.
            print(f"[ERROR] Baseline seed failed: {exc}", file=sys.stderr)
            print(
                "[ERROR] Sentinel requires seeded classification data to operate correctly.",
                file=sys.stderr,
            )
            print(
                "[ERROR] Recovery: delete data/iam_actions.db and re-run 'sentinel info'.",
                file=sys.stderr,
            )
            sys.exit(EXIT_IO_ERROR)

        # Issue 3 (v0.8.0): warn when the AWS action corpus is empty.
        # Without populated services + actions tables, every policy action
        # classifies as Tier 2 (unknown) and the rewriter degrades — under
        # Issue 2's preservation semantics the rewrite still emits, but the
        # self-check verdict will be WARNING regardless. Prompt the operator
        # to populate the corpus via `sentinel refresh --source policy-sentry`.
        _CORPUS_DEPENDENT: frozenset[str] = frozenset(
            {"validate", "analyze", "rewrite", "run", "fetch"}
        )
        if args.command in _CORPUS_DEPENDENT and not _probe_db.is_corpus_populated():
            print(
                "[WARN] AWS action corpus is empty (services: 0, actions: 0). "
                "Run: sentinel refresh --source policy-sentry --data-path <path-to-policy_sentry-json> "
                "to populate it. Without this, all actions classify as Tier 2 (unknown) "
                "and the rewriter operates in degraded mode.",
                file=sys.stderr,
            )

    from .cli_cache import cmd_cache
    from .cli_managed import cmd_managed
    from .cli_config import cmd_config
    from .cli_fetch import cmd_fetch
    from .cli_misc import (
        cmd_watch,
        cmd_wizard,
        cmd_compare,
        cmd_search,
    )

    handlers = {
        "validate": cmd_validate,
        "analyze": cmd_analyze,
        "rewrite": cmd_rewrite,
        "run": cmd_run,
        "refresh": cmd_refresh,
        "info": cmd_info,
        "export-services": cmd_export_services,
        "fetch-examples": cmd_fetch_examples,
        "cache": cmd_cache,
        "managed": cmd_managed,
        "config": cmd_config,
        "fetch": cmd_fetch,
        "watch": cmd_watch,
        "wizard": cmd_wizard,
        "compare": cmd_compare,
        "search": cmd_search,
    }

    handler = handlers.get(args.command)
    if handler is None:
        parser.print_help()
        sys.exit(EXIT_INVALID_ARGS)

    exit_code = handler(args)
    sys.exit(exit_code)

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
from typing import Optional, Tuple, Union

from .constants import (
    EXIT_SUCCESS,
    EXIT_ISSUES_FOUND,
    EXIT_INVALID_ARGS,
    EXIT_IO_ERROR,
    DEFAULT_DB_PATH,
    DEFAULT_INVENTORY_PATH,
)
from .formatters import TextFormatter, JsonFormatter, MarkdownFormatter


def export_services_json(
    database: "Database",
    output_path: Optional[Path] = None,
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
        output_path = (
            Path(__file__).resolve().parent.parent.parent
            / "data"
            / "known_services.json"
        )

    services = sorted(s.service_prefix for s in database.get_services())

    data = {
        "_generated": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "_source": str(database.db_path),
        "services": services,
    }

    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(
        json.dumps(data, indent=2) + "\n", encoding="utf-8"
    )
    return output_path


def build_parser() -> argparse.ArgumentParser:
    """Build the argument parser with all subcommands.

    Returns:
        Configured ArgumentParser.
    """
    # Shared parent for common flags
    parent = argparse.ArgumentParser(add_help=False)
    parent.add_argument(
        "-d", "--database",
        default=None,
        help="Path to IAM actions SQLite database",
    )
    parent.add_argument(
        "-i", "--inventory",
        default=None,
        help="Path to resource inventory SQLite database",
    )
    parent.add_argument(
        "-f", "--output-format",
        choices=["text", "json", "markdown"],
        default="text",
        help="Output format (default: text)",
    )
    parent.add_argument(
        "-o", "--output",
        default=None,
        help="Write output to file instead of stdout",
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

    # refresh
    p_refresh = subparsers.add_parser(
        "refresh",
        parents=[parent],
        help="Refresh IAM actions database from local data files",
    )
    p_refresh.add_argument(
        "--source",
        required=True,
        choices=["policy-sentry", "aws-docs"],
        help="Data source format",
    )
    p_refresh.add_argument(
        "--data-path",
        required=True,
        help="Path to data file or directory",
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
) -> Tuple[str, str]:
    """Read policy content from file or stdin.

    Args:
        policy_file: File path or '-' for stdin.
        input_format: Explicit format or 'auto' for extension-based detection.

    Returns:
        Tuple of (content_string, resolved_format).

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
) -> Union[TextFormatter, JsonFormatter, MarkdownFormatter]:
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


def resolve_database(args: argparse.Namespace) -> Optional["Database"]:
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
) -> Optional["ResourceInventory"]:
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
    from .parser import PolicyParser, PolicyParserError
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
    except PolicyParserError as e:
        print(f"Error: {e}", file=sys.stderr)
        return EXIT_INVALID_ARGS

    results = parser.validate_policy(policy)

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

    risk_analyzer = RiskAnalyzer(db)
    findings = risk_analyzer.analyze_actions(all_actions)

    formatter = _get_formatter(args)
    output = formatter.format_risk_findings(findings)
    _write_output(args, output)

    has_critical = any(
        f.severity.value in ("CRITICAL", "HIGH") for f in findings
    )
    return EXIT_ISSUES_FOUND if has_critical else EXIT_SUCCESS


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
    )

    rewriter = PolicyRewriter(db, inv)
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
    from .parser import PolicyParser, PolicyParserError
    from .self_check import Pipeline, PipelineConfig, CheckVerdict

    try:
        content, fmt = read_policy_input(args.policy_file, args.input_format)
    except FileNotFoundError as e:
        print(f"Error: {e}", file=sys.stderr)
        return EXIT_IO_ERROR

    # Pipeline.run() expects a JSON string internally.
    # If the input is YAML, deserialize then re-serialize to JSON.
    if fmt == "yaml":
        try:
            import yaml
        except ImportError:
            print(
                "Error: PyYAML is required for YAML input. "
                "Install it with: pip install pyyaml",
                file=sys.stderr,
            )
            return EXIT_INVALID_ARGS
        try:
            data = yaml.safe_load(content)
        except yaml.YAMLError as e:
            print(f"Error: Invalid YAML: {e}", file=sys.stderr)
            return EXIT_INVALID_ARGS
        if not isinstance(data, dict):
            print(
                f"Error: YAML content must be a mapping, "
                f"got {type(data).__name__}",
                file=sys.stderr,
            )
            return EXIT_INVALID_ARGS
        content = json.dumps(data)
    policy_json = content

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
    )

    pipeline = Pipeline(db, inv)

    try:
        result = pipeline.run(policy_json, config)
    except PolicyParserError as e:
        print(f"Error: {e}", file=sys.stderr)
        return EXIT_INVALID_ARGS

    formatter = _get_formatter(args)
    output = formatter.format_pipeline_result(result)
    _write_output(args, output)

    if result.final_verdict == CheckVerdict.PASS:
        return EXIT_SUCCESS
    return EXIT_ISSUES_FOUND


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
    data_path = Path(args.data_path)

    if not data_path.exists():
        print(f"Error: Data path not found: {data_path}", file=sys.stderr)
        return EXIT_IO_ERROR

    if args.dry_run:
        # Dry-run: validate data using in-memory DB (no disk writes)
        if args.source == "policy-sentry":
            from ..refresh.policy_sentry_loader import PolicySentryLoader

            db = Database(Path(":memory:"))
            db.create_schema()
            loader = PolicySentryLoader(db)
            errors = loader.validate_data(data_path)
        else:
            from ..refresh.aws_docs_scraper import AwsDocsScraper

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
        from ..refresh.policy_sentry_loader import PolicySentryLoader

        loader = PolicySentryLoader(db)
        if data_path.is_dir():
            stats, changelog = loader.load_from_directory(data_path)
        else:
            stats, changelog = loader.load_from_file(data_path)
    else:
        from ..refresh.aws_docs_scraper import AwsDocsScraper

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
                f"[{entry.change_type}] {entry.entity_type}: "
                f"{entry.entity_name} - {entry.detail}"
            )
        Path(args.changelog).write_text(
            "\n".join(changelog_lines), encoding="utf-8"
        )
        print(f"Changelog written to {args.changelog}")

    # Auto-export known_services.json after successful refresh
    try:
        written = export_services_json(db)
        print(f"Auto-exported services to {written}")
    except Exception as e:
        print(f"[WARN] Auto-export failed: {e}", file=sys.stderr)

    return EXIT_SUCCESS


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

    formatter = _get_formatter(args)
    output = formatter.format_db_info(metadata, service_count, action_count)
    _write_output(args, output)

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
    from src.refresh.aws_examples import (
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
        Path(report_path).write_text(
            json.dumps(report, indent=2) + "\n", encoding="utf-8"
        )
        print(f"Report written to {report_path}")

    return EXIT_SUCCESS


def main() -> None:
    """CLI entry point. Dispatches to subcommand handlers."""
    from . import __version__

    parser = build_parser()
    args = parser.parse_args()

    if args.version:
        print(f"IAM Policy Sentinel v{__version__}")
        sys.exit(EXIT_SUCCESS)

    if args.command is None:
        parser.print_help()
        sys.exit(EXIT_INVALID_ARGS)

    handlers = {
        "validate": cmd_validate,
        "analyze": cmd_analyze,
        "rewrite": cmd_rewrite,
        "run": cmd_run,
        "refresh": cmd_refresh,
        "info": cmd_info,
        "export-services": cmd_export_services,
        "fetch-examples": cmd_fetch_examples,
    }

    handler = handlers.get(args.command)
    if handler is None:
        parser.print_help()
        sys.exit(EXIT_INVALID_ARGS)

    exit_code = handler(args)
    sys.exit(exit_code)

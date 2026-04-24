"""``sentinel managed`` subcommand handlers — Phase 5 Task 7.

Wrappers around :class:`fetchers.aws_managed.AWSManagedFetcher` for the
``list``, ``show``, and ``analyze`` sub-subcommands.

* ``list``    — all policy names in alphabetic order.
* ``show``    — JSON policy_document bytes printed verbatim.
* ``analyze`` — fetch via AWSManagedFetcher then run the full Pipeline.
"""

from __future__ import annotations

import argparse
import json
import sys

from .exit_codes import EXIT_INVALID_ARGS, EXIT_IO_ERROR, EXIT_SUCCESS


def cmd_managed(args: argparse.Namespace) -> int:
    """Dispatch to ``list`` / ``show`` / ``analyze``."""
    from .fetchers.aws_managed import AWSManagedFetcher
    from .fetchers.base import PolicyNotFoundError
    from .cli import (
        resolve_database,
        resolve_inventory,
        _get_formatter,
        _write_output,
        _verdict_to_exit_code,
    )

    sub = getattr(args, "managed_cmd", None)
    db = resolve_database(args)
    if db is None:
        print("No database found. Use --database to specify path.", file=sys.stderr)
        return EXIT_IO_ERROR

    fetcher = AWSManagedFetcher(db)

    if sub == "list":
        names = fetcher.list_names()
        fmt = getattr(args, "output_format", "text")
        if fmt == "json":
            print(json.dumps(names, indent=2))
        else:
            if not names:
                print(
                    "(no managed policies loaded; run `sentinel refresh --source managed-policies`)"
                )
                return EXIT_SUCCESS
            for n in names:
                print(n)
        return EXIT_SUCCESS

    if sub == "show":
        try:
            body = fetcher.show(args.name)
        except PolicyNotFoundError as exc:
            print(f"Error: {exc}", file=sys.stderr)
            return EXIT_IO_ERROR
        print(body.decode("utf-8"))
        return EXIT_SUCCESS

    if sub == "analyze":
        from .self_check import Pipeline, PipelineConfig
        from .models import PolicyInput

        try:
            fetch_result = fetcher.fetch(args.name)
        except PolicyNotFoundError as exc:
            print(f"Error: {exc}", file=sys.stderr)
            return EXIT_IO_ERROR
        policy_input = PolicyInput(
            body_bytes=fetch_result.body,
            origin=fetch_result.origin,
        )
        inv = resolve_inventory(args)
        try:
            pipeline = Pipeline(db, inv)
            result = pipeline.run(policy_input, config=PipelineConfig())
        except Exception as exc:  # noqa: BLE001 — best-effort one-shot.
            print(f"Error: {exc}", file=sys.stderr)
            return EXIT_IO_ERROR
        formatter = _get_formatter(args)
        # Issue 5 (v0.8.0): thread --force-emit-rewrite through so FAIL
        # verdicts on managed-policy analysis suppress rewrite output too.
        force_emit = getattr(args, "force_emit_rewrite", False)
        # v0.8.1 (M2): structlog audit trail for bypass of FAIL verdict.
        from .self_check import CheckVerdict

        if force_emit and result.self_check_result.verdict == CheckVerdict.FAIL:
            import structlog

            structlog.get_logger("sentinel.safety").warning(
                "force_emit_rewrite_bypass",
                verdict="FAIL",
                subcommand="managed",
            )
        _write_output(
            args, formatter.format_pipeline_result(result, force_emit=force_emit)
        )
        findings = list(result.risk_findings) + list(
            getattr(result.self_check_result, "findings", [])
        )
        return _verdict_to_exit_code(findings)

    print(f"Unknown managed subcommand: {sub!r}", file=sys.stderr)
    return EXIT_INVALID_ARGS


__all__ = ["cmd_managed"]

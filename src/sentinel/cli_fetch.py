"""``sentinel fetch`` subcommand handler — Phase 5 Task 1.

Top-level network-aware fetcher dispatcher.  Mutually exclusive flags
pick one of the eight Phase 4 fetchers; the resulting
:class:`~fetchers.base.FetchResult` is handed to :class:`Pipeline.run`
via a :class:`PolicyInput` so findings round-trip through the usual
Validate-Analyze-Rewrite-SelfCheck flow.

``--alert-on-new`` enables a light-weight hash-based diff: the last
fetched SHA-256 for the (source_type, source_spec) pair is persisted
to ``$XDG_DATA_HOME/sentinel/fetch_state.json`` and compared on the
next run.  On mismatch, a WARN line is emitted to stderr.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path
from typing import TYPE_CHECKING

from .exit_codes import (
    EXIT_INVALID_ARGS,
    EXIT_IO_ERROR,
    EXIT_SUCCESS,
)

if TYPE_CHECKING:  # pragma: no cover
    from .fetchers.base import FetchResult


def _build_http_client():
    """Construct a :class:`SentinelHTTPClient` from the live settings."""
    from .config import get_settings
    from .net.allow_list import AllowList
    from .net.cache import DiskCache
    from .net.client import SentinelHTTPClient
    from .net.retry import RetryPolicy

    settings = get_settings()
    allow = AllowList(list(settings.network.allow_list.domains) + list(settings.allow_domain))
    ttl = {
        "aws_docs": settings.cache.ttl_hours_aws_docs * 3600,
        "policy_sentry": settings.cache.ttl_hours_policy_sentry * 3600,
        "github": settings.cache.ttl_hours_github * 3600,
        "user_url": settings.cache.ttl_hours_user_url * 3600,
    }
    cache = DiskCache(ttl_seconds_by_source=ttl)
    retry = RetryPolicy.from_settings(settings.retries)
    return SentinelHTTPClient(
        settings=settings,
        allow_list=allow,
        cache=cache,
        retry_policy=retry,
        insecure=settings.insecure,
    )


def _state_path() -> Path:
    xdg = os.environ.get("XDG_DATA_HOME")
    base = Path(xdg) if xdg else Path.home() / ".local" / "share"
    return base / "sentinel" / "fetch_state.json"


def _check_alert(result: "FetchResult") -> None:
    """Compare SHA-256 with the last stored hash; WARN on diff.

    v0.8.1 (PE3): state-file read errors are now surfaced to stderr via
    [WARN] rather than silently swallowed. --alert-on-new depends on
    reading the prior state to detect drift; if the read fails, the
    operator must be informed so they know the alert is unreliable.
    """
    p = _state_path()
    key = f"{result.origin.source_type}::{result.origin.source_spec}"
    prev: dict[str, str] = {}
    if p.is_file():
        try:
            prev = json.loads(p.read_text(encoding="utf-8"))
        except OSError as exc:
            # v0.8.1 (PE3): was silently swallowed; now visible.
            print(
                f"[WARN] could not read fetch_state at {p}: {exc}. "
                f"--alert-on-new will not detect drift from prior state.",
                file=sys.stderr,
            )
            prev = {}
        except json.JSONDecodeError as exc:
            # State file corrupted — surface the parse error too.
            print(
                f"[WARN] fetch_state at {p} is not valid JSON: {exc}. "
                f"--alert-on-new will not detect drift from prior state.",
                file=sys.stderr,
            )
            prev = {}
    old = prev.get(key)
    cur = result.origin.sha256
    if old is not None and old != cur:
        print(
            f"[WARN] policy changed since last fetch: {key}\n"
            f"       old_sha256={old}\n"
            f"       new_sha256={cur}",
            file=sys.stderr,
        )
    prev[key] = cur
    try:
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(json.dumps(prev, indent=2), encoding="utf-8")
    except OSError as exc:
        print(f"[WARN] could not persist fetch_state: {exc}", file=sys.stderr)


def _dispatch_fetch(args: argparse.Namespace) -> "FetchResult":
    """Route the mutually-exclusive flags to the matching fetcher."""
    from .fetchers.aws_managed import AWSManagedFetcher
    from .fetchers.aws_sample import AWSSampleFetcher
    from .fetchers.clipboard import ClipboardFetcher
    from .fetchers.cloudsplaining import CloudSplainingFetcher
    from .fetchers.github import GitHubFetcher
    from .fetchers.url import URLFetcher
    from .cli import resolve_database
    from .config import get_settings

    if args.from_clipboard:
        return ClipboardFetcher().fetch("")

    if args.aws_managed:
        db = resolve_database(args)
        if db is None:
            raise RuntimeError("No database found for --aws-managed lookup.")
        return AWSManagedFetcher(db).fetch(args.aws_managed)

    # Remaining branches all need an HTTP client.
    client = _build_http_client()
    settings = get_settings()
    try:
        if args.url:
            return URLFetcher(client).fetch(args.url)
        if args.github:
            return GitHubFetcher(client, settings).fetch(args.github)
        if args.aws_sample:
            return AWSSampleFetcher(client).fetch(args.aws_sample)
        if args.cloudsplaining:
            return CloudSplainingFetcher(client, settings).fetch(args.cloudsplaining)
    finally:
        client.close()

    raise RuntimeError("fetch: no source flag supplied (argparse bug?)")


def cmd_fetch(args: argparse.Namespace) -> int:
    """Fetch a policy from a remote source and pipe through the full pipeline."""
    import httpx

    from .fetchers.base import FetcherError
    from .cli import resolve_database, resolve_inventory
    from .cli_utils import get_formatter, write_output, verdict_to_exit_code
    from .models import PolicyInput
    from .self_check import Pipeline, PipelineConfig

    from .net.client import ResponseTooLargeError

    try:
        fetch_result = _dispatch_fetch(args)
    except httpx.InvalidURL as exc:
        # Issue 6 (v0.8.0): httpx raises InvalidURL for URLs containing
        # newlines, tabs, or other non-printable characters. Surface an
        # actionable message at the CLI boundary instead of a raw traceback.
        print(
            f"Error: malformed URL — {exc}. "
            "Check for newlines, tabs, or other non-printable characters in your --url argument.",
            file=sys.stderr,
        )
        return EXIT_INVALID_ARGS
    except ResponseTooLargeError as exc:
        # SEC-M1: upstream refused an oversized body.  Surface the size /
        # limit so operators know to raise max_download_bytes (or investigate
        # a compromised/misbehaving mirror).
        print(
            f"Error: fetched response exceeds max_download_bytes — {exc}. "
            "Increase settings.network.max_download_bytes if the source is trusted.",
            file=sys.stderr,
        )
        return EXIT_IO_ERROR
    except FetcherError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return EXIT_IO_ERROR
    except RuntimeError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return EXIT_INVALID_ARGS

    if getattr(args, "alert_on_new", False):
        _check_alert(fetch_result)

    policy_input = PolicyInput(
        body_bytes=fetch_result.body,
        origin=fetch_result.origin,
    )
    db = resolve_database(args)
    inv = resolve_inventory(args)
    config = PipelineConfig(
        intent=getattr(args, "intent", None),
        account_id=getattr(args, "account_id", None),
        region=getattr(args, "region", None),
    )
    try:
        pipeline = Pipeline(db, inv)
        result = pipeline.run(policy_input, config=config)
    except Exception as exc:  # noqa: BLE001 — surface any downstream error.
        print(f"Error: {exc}", file=sys.stderr)
        return EXIT_IO_ERROR
    formatter = get_formatter(args)
    # Issue 5 (v0.8.0): thread --force-emit-rewrite so FAIL suppresses output.
    force_emit = getattr(args, "force_emit_rewrite", False)
    # SEC-L4 (v0.8.2): emit audit event on every --force-emit-rewrite use,
    # not only on FAIL.  ``bypass_of_failure`` distinguishes genuine
    # overrides from belt-and-suspenders CI usage.
    from .self_check import CheckVerdict

    if force_emit:
        import structlog

        verdict = result.self_check_result.verdict
        structlog.get_logger("sentinel.safety").warning(
            "force_emit_rewrite_bypass",
            verdict=verdict.value,
            bypass_of_failure=(verdict == CheckVerdict.FAIL),
            subcommand="fetch",
        )
    write_output(args, formatter.format_pipeline_result(result, force_emit=force_emit))
    findings = list(result.risk_findings) + list(getattr(result.self_check_result, "findings", []))
    return verdict_to_exit_code(findings)


__all__ = ["cmd_fetch"]

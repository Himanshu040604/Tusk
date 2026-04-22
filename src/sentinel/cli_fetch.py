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
    EXIT_INVALID_ARGS, EXIT_IO_ERROR, EXIT_SUCCESS,
)

if TYPE_CHECKING:  # pragma: no cover
    from fetchers.base import FetchResult


def _build_http_client():
    """Construct a :class:`SentinelHTTPClient` from the live settings."""
    from .config import get_settings
    from .net.allow_list import AllowList
    from .net.cache import DiskCache
    from .net.client import SentinelHTTPClient
    from .net.retry import RetryPolicy

    settings = get_settings()
    allow = AllowList(list(settings.network.allow_list.domains)
                      + list(settings.allow_domain))
    ttl = {
        "aws_docs":      settings.cache.ttl_hours_aws_docs * 3600,
        "policy_sentry": settings.cache.ttl_hours_policy_sentry * 3600,
        "github":        settings.cache.ttl_hours_github * 3600,
        "user_url":      settings.cache.ttl_hours_user_url * 3600,
    }
    cache = DiskCache(ttl_seconds_by_source=ttl)
    retry = RetryPolicy.from_settings(settings.retries)
    return SentinelHTTPClient(
        settings=settings, allow_list=allow, cache=cache,
        retry_policy=retry, insecure=settings.insecure,
    )


def _state_path() -> Path:
    xdg = os.environ.get("XDG_DATA_HOME")
    base = Path(xdg) if xdg else Path.home() / ".local" / "share"
    return base / "sentinel" / "fetch_state.json"


def _check_alert(result: "FetchResult") -> None:
    """Compare SHA-256 with the last stored hash; WARN on diff."""
    p = _state_path()
    key = f"{result.origin.source_type}::{result.origin.source_spec}"
    prev: dict[str, str] = {}
    if p.is_file():
        try:
            prev = json.loads(p.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
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
    from fetchers.aws_managed import AWSManagedFetcher
    from fetchers.aws_sample import AWSSampleFetcher
    from fetchers.clipboard import ClipboardFetcher
    from fetchers.cloudsplaining import CloudSplainingFetcher
    from fetchers.github import GitHubFetcher
    from fetchers.url import URLFetcher
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
            return CloudSplainingFetcher(client, settings).fetch(
                args.cloudsplaining
            )
    finally:
        client.close()

    raise RuntimeError("fetch: no source flag supplied (argparse bug?)")


def cmd_fetch(args: argparse.Namespace) -> int:
    """Fetch a policy from a remote source and pipe through the full pipeline."""
    from fetchers.base import FetcherError
    from .cli import (
        resolve_database, resolve_inventory,
        _get_formatter, _write_output, _verdict_to_exit_code,
    )
    from .models import PolicyInput
    from .self_check import Pipeline, PipelineConfig

    try:
        fetch_result = _dispatch_fetch(args)
    except FetcherError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return EXIT_IO_ERROR
    except RuntimeError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return EXIT_INVALID_ARGS

    if getattr(args, "alert_on_new", False):
        _check_alert(fetch_result)

    policy_input = PolicyInput(
        body_bytes=fetch_result.body, origin=fetch_result.origin,
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
    formatter = _get_formatter(args)
    _write_output(args, formatter.format_pipeline_result(result))
    findings = list(result.risk_findings) + list(
        getattr(result.self_check_result, "findings", [])
    )
    return _verdict_to_exit_code(findings)


__all__ = ["cmd_fetch"]

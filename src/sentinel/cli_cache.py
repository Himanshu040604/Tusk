"""``sentinel cache`` subcommand handlers — Phase 5 Task 6.

Thin wrappers around :class:`sentinel.net.cache.DiskCache`.  Instantiation
uses the shared settings-derived TTL map so hits/misses reflect what the
real HTTP client sees.

Subcommands:

* ``stats``       — ``count`` + ``total_bytes`` across all entries.
* ``ls``          — metadata-only listing (url, source, fetched_at, …).
* ``purge``       — delete every entry; return the count.
* ``rotate-key``  — wipe the cache AND regenerate the HMAC root key.
  Prompts for confirmation unless ``--yes`` is supplied.
"""

from __future__ import annotations

import argparse
import json
import sys

from .exit_codes import EXIT_INVALID_ARGS, EXIT_IO_ERROR, EXIT_SUCCESS
from .net.cache import DiskCache


def _build_cache() -> DiskCache:
    """Construct a :class:`DiskCache` with the process-wide settings."""
    from .config import get_settings

    settings = get_settings()
    # Build the TTL map keyed by source — mirrors ``cache.py._default_ttl_by_source``
    # but reads the values via the live Settings singleton so operator
    # overrides in config.toml are honoured.
    ttl = {
        "aws_docs":      settings.cache.ttl_hours_aws_docs * 3600,
        "policy_sentry": settings.cache.ttl_hours_policy_sentry * 3600,
        "github":        settings.cache.ttl_hours_github * 3600,
        "user_url":      settings.cache.ttl_hours_user_url * 3600,
    }
    return DiskCache(ttl_seconds_by_source=ttl)


def _human_bytes(n: int) -> str:
    for unit in ("B", "KiB", "MiB", "GiB"):
        if n < 1024:
            return f"{n:.1f} {unit}"
        n /= 1024
    return f"{n:.1f} TiB"


def cmd_cache(args: argparse.Namespace) -> int:
    """Dispatch to ``stats`` / ``ls`` / ``purge`` / ``rotate-key``."""
    sub = getattr(args, "cache_cmd", None)
    fmt = getattr(args, "output_format", "text")

    try:
        cache = _build_cache()
    except OSError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return EXIT_IO_ERROR

    if sub == "stats":
        s = cache.stats()
        if fmt == "json":
            print(json.dumps(s, indent=2))
        else:
            print(f"entries      : {s['count']}")
            print(f"total_bytes  : {s['total_bytes']} "
                  f"({_human_bytes(s['total_bytes'])})")
        return EXIT_SUCCESS

    if sub == "ls":
        rows = cache.ls()
        if fmt == "json":
            print(json.dumps(rows, indent=2, default=str))
        else:
            if not rows:
                print("(cache is empty)")
                return EXIT_SUCCESS
            for r in rows:
                print(
                    f"[{r.get('source') or '-'}] {r.get('url') or '-'}  "
                    f"fetched={r.get('fetched_at')}  "
                    f"ttl={r.get('ttl_seconds')}s  "
                    f"size={r.get('size_bytes')}B"
                )
        return EXIT_SUCCESS

    if sub == "purge":
        n = cache.purge()
        print(f"Purged {n} entries.")
        return EXIT_SUCCESS

    if sub == "rotate-key":
        if not getattr(args, "yes", False):
            try:
                answer = input(
                    "This will delete all cached entries. "
                    "Continue? [y/N] "
                ).strip().lower()
            except (EOFError, KeyboardInterrupt):
                print("Aborted.", file=sys.stderr)
                return EXIT_INVALID_ARGS
            if answer not in {"y", "yes"}:
                print("Aborted.")
                return EXIT_SUCCESS
        cache.rotate_key()
        print("Cache key rotated; all entries purged.")
        return EXIT_SUCCESS

    print(f"Unknown cache subcommand: {sub!r}", file=sys.stderr)
    return EXIT_INVALID_ARGS


__all__ = ["cmd_cache"]

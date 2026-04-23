"""Phase 5 odds-and-ends CLI handlers.

Collected into a single module to keep ``cli.py`` lean:

* :func:`cmd_watch`   — ``sentinel watch <path>``    (Task 2 / M6).
* :func:`cmd_wizard`  — interactive intent helper   (Task 3).
* :func:`cmd_compare` — two-policy risk diff         (Task 4).
* :func:`cmd_search`  — GitHub Search API wrapper    (Task 5).
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path

from .exit_codes import EXIT_INVALID_ARGS, EXIT_IO_ERROR, EXIT_SUCCESS


# ---------------------------------------------------------------------------
# Task 2 — sentinel watch
# ---------------------------------------------------------------------------

_DEBOUNCE_SECONDS = 0.2


def _run_pipeline_on_file(path: Path) -> int:
    """Re-use the standard run path by minting a synthetic argparse NS."""
    from .cli import cmd_run

    ns = argparse.Namespace(
        policy_file=str(path),
        input_format="auto",
        intent=None,
        account_id=None,
        region=None,
        strict=False,
        max_retries=3,
        no_companions=False,
        no_conditions=False,
        interactive=False,
        policy_type=None,
        condition_profile="moderate",
        allow_wildcard_actions=False,
        allow_wildcard_resources=False,
        output_format="text",
        output=None,
        database=None,
        inventory=None,
        batch=None,
        fail_fast=False,
    )
    return cmd_run(ns)


def cmd_watch(args: argparse.Namespace) -> int:
    """Watch a file or directory and re-run the pipeline on every change."""
    try:
        from watchfiles import watch
    except ImportError:
        print("Error: watchfiles not installed. Run `uv sync`.", file=sys.stderr)
        return EXIT_IO_ERROR

    target = Path(args.path)
    if not target.exists():
        print(f"Error: path not found: {target}", file=sys.stderr)
        return EXIT_IO_ERROR

    print(f"[WATCH] watching {target} (Ctrl-C to stop)", file=sys.stderr)
    last_fire: dict[str, float] = {}
    try:
        for changes in watch(str(target)):
            now = time.monotonic()
            for _change, path_str in changes:
                p = Path(path_str)
                if not p.is_file() or p.suffix.lower() not in {".json", ".yaml", ".yml"}:
                    continue
                if now - last_fire.get(path_str, 0.0) < _DEBOUNCE_SECONDS:
                    continue
                last_fire[path_str] = now
                print(f"[WARN] re-validating {p}", file=sys.stderr)
                try:
                    _run_pipeline_on_file(p)
                except Exception as exc:  # noqa: BLE001 — surface + keep watching.
                    print(f"[ERROR] {p}: {exc}", file=sys.stderr)
    except KeyboardInterrupt:
        print("\n[WATCH] stopped.", file=sys.stderr)
    return EXIT_SUCCESS


# ---------------------------------------------------------------------------
# Task 3 — sentinel wizard
# ---------------------------------------------------------------------------


def _wizard_prompt(question: str, default: str | None = None) -> str:
    suffix = f" [{default}]" if default else ""
    try:
        ans = input(f"{question}{suffix}: ").strip()
    except (EOFError, KeyboardInterrupt):
        print("\nAborted.", file=sys.stderr)
        sys.exit(EXIT_INVALID_ARGS)
    return ans or (default or "")


def cmd_wizard(args: argparse.Namespace) -> int:
    """Interactive intent-to-policy builder."""
    from .analyzer import IntentMapper
    from .cli import resolve_database

    db = resolve_database(args)
    mapper = IntentMapper(db)

    print("=== sentinel wizard — interactive least-privilege drafter ===")
    service = _wizard_prompt("service (e.g. s3, ec2)").strip().lower()
    if not service:
        print("Error: a service prefix is required.", file=sys.stderr)
        return EXIT_INVALID_ARGS
    intent = _wizard_prompt("intent (read-only / read-write / admin)", default="read-only")
    resource = _wizard_prompt(f"resource ARN pattern (optional; default '*')", default="*")

    mapping = mapper.map_intent(intent, service_filter=[service])
    actions = sorted(set(mapping.actions))
    if not actions:
        # P1-4 α — refuse to emit a wildcard fallback.  A least-privilege
        # tool that silently falls back to ``service:*`` when it cannot
        # classify the intent violates the product's core guarantee.
        print(
            f"[ERROR] Could not classify intent {intent!r} for service {service!r}.",
            file=sys.stderr,
        )
        print(
            "Recognized intents: read-only, read-write, write, admin, list, "
            "deploy, tagging, permissions",
            file=sys.stderr,
        )
        return EXIT_INVALID_ARGS

    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "WizardGenerated",
                "Effect": "Allow",
                "Action": actions,
                "Resource": resource or "*",
            }
        ],
    }
    print("")
    print(json.dumps(policy, indent=2))
    print("")
    print("(Run `sentinel run <file>` on the saved JSON for full validation.)", file=sys.stderr)
    return EXIT_SUCCESS


# ---------------------------------------------------------------------------
# Task 4 — sentinel compare
# ---------------------------------------------------------------------------


def _analyze_for_compare(path: str, args: argparse.Namespace) -> dict:
    from .analyzer import RiskAnalyzer
    from .cli import read_policy_input, resolve_database
    from .parser import PolicyParser

    db = resolve_database(args)
    content, fmt = read_policy_input(path, "auto")
    parser = PolicyParser(db)
    policy = parser.parse_policy_auto(content, fmt)
    actions: list[str] = []
    for stmt in policy.statements:
        actions.extend(stmt.actions)
        if stmt.not_actions:
            actions.extend(stmt.not_actions)
    analyzer = RiskAnalyzer(db)
    findings = analyzer.analyze_actions(actions)
    return {
        "path": path,
        "actions": sorted(set(actions)),
        "findings": [
            f"{getattr(f, 'severity', '')}:{getattr(f, 'description', repr(f))}" for f in findings
        ],
    }


def cmd_compare(args: argparse.Namespace) -> int:
    """Diff two policies' risk profiles."""
    try:
        a = _analyze_for_compare(args.policy_a, args)
        b = _analyze_for_compare(args.policy_b, args)
    except FileNotFoundError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return EXIT_IO_ERROR
    set_a, set_b = set(a["findings"]), set(b["findings"])
    both = sorted(set_a & set_b)
    only_a = sorted(set_a - set_b)
    only_b = sorted(set_b - set_a)
    actions_only_a = sorted(set(a["actions"]) - set(b["actions"]))
    actions_only_b = sorted(set(b["actions"]) - set(a["actions"]))

    payload = {
        "policy_a": args.policy_a,
        "policy_b": args.policy_b,
        "findings_both": both,
        "findings_only_a": only_a,
        "findings_only_b": only_b,
        "actions_only_a": actions_only_a,
        "actions_only_b": actions_only_b,
    }
    if getattr(args, "output_format", "text") == "json":
        print(json.dumps(payload, indent=2))
        return EXIT_SUCCESS
    print(f"A: {args.policy_a}\nB: {args.policy_b}\n")
    print(f"Findings in BOTH ({len(both)}):")
    for f in both:
        print(f"  - {f}")
    print(f"\nFindings only in A ({len(only_a)}):")
    for f in only_a:
        print(f"  - {f}")
    print(f"\nFindings only in B ({len(only_b)}):")
    for f in only_b:
        print(f"  - {f}")
    print(f"\nActions only in A: {actions_only_a}")
    print(f"Actions only in B: {actions_only_b}")
    return EXIT_SUCCESS


# ---------------------------------------------------------------------------
# Task 5 — sentinel search
# ---------------------------------------------------------------------------


def cmd_search(args: argparse.Namespace) -> int:
    """Search GitHub for public IAM policies matching ``query``."""
    from .config import get_settings
    from .net.allow_list import AllowList
    from .net.cache import DiskCache
    from .net.client import SentinelHTTPClient
    from .net.retry import RetryPolicy

    settings = get_settings()
    if settings.github_token is None:
        print(
            "Error: SENTINEL_GITHUB_TOKEN (or [github_token] in config) is "
            "required for `search --on-github` (GitHub Search API is "
            "authenticated-only at useful rate limits).",
            file=sys.stderr,
        )
        return EXIT_INVALID_ARGS

    # GitHub Search API is on api.github.com, which may not be in the
    # default allow-list.  Extend for the duration of this call.
    allow = AllowList(
        list(settings.network.allow_list.domains) + list(settings.allow_domain) + ["api.github.com"]
    )
    cache = DiskCache(ttl_seconds_by_source={"github": 60})  # short TTL for search
    retry = RetryPolicy.from_settings(settings.retries)
    token = settings.github_token.get_secret_value()
    # P2-12 α — urlencode the query so `&` / `#` / spaces / quotes in
    # the user's input can't break URL parsing or (worse) inject extra
    # URL parameters into the GitHub Search call.
    from urllib.parse import urlencode, quote

    params = {
        "q": f"{args.query} in:file extension:json",
        "per_page": max(1, min(100, args.limit)),
    }
    url = f"https://api.github.com/search/code?{urlencode(params, quote_via=quote)}"
    with SentinelHTTPClient(
        settings=settings,
        allow_list=allow,
        cache=cache,
        retry_policy=retry,
        insecure=settings.insecure,
    ) as client:
        try:
            resp = client.get(
                url,
                source="github",
                headers={
                    "Authorization": f"token {token}",
                    "Accept": "application/vnd.github+json",
                },
            )
        except Exception as exc:  # noqa: BLE001 — surface GitHub errors.
            print(f"Error: GitHub search failed: {exc}", file=sys.stderr)
            return EXIT_IO_ERROR

    try:
        data = json.loads(resp.text)
    except json.JSONDecodeError as exc:
        print(f"Error: GitHub returned non-JSON: {exc}", file=sys.stderr)
        return EXIT_IO_ERROR
    items = data.get("items", []) or []
    rows = [
        {
            "repo": it.get("repository", {}).get("full_name"),
            "path": it.get("path"),
            "url": it.get("html_url"),
        }
        for it in items
    ]
    if getattr(args, "output_format", "text") == "json":
        print(json.dumps(rows, indent=2))
    else:
        if not rows:
            print("(no matches)")
            return EXIT_SUCCESS
        for r in rows:
            print(f"{r['repo']}  {r['path']}  {r['url']}")
    return EXIT_SUCCESS


__all__ = ["cmd_watch", "cmd_wizard", "cmd_compare", "cmd_search"]

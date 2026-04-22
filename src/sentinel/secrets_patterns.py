"""Shared secret-pattern redaction module.

Single source of truth for THREE consumers that must not drift:

1. M10 structlog ``redact_sensitive`` processor  — :func:`redact_event_dict`
2. M22 pre-commit grep hook                      — :func:`grep_sources`
3. H11 VCR.py cassette response-body scrubber    — :func:`scrub_bytes`

All three call sites import :data:`REDACT_KEYS`, :data:`SECRET_PATTERNS`,
and :data:`REDACT_PLACEHOLDER` from this module.  A Phase 6 contract test
(``tests/test_secrets_patterns.py::test_single_source_of_truth``) asserts
no consumer reimplements scrubbing logic.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

REDACT_PLACEHOLDER: str = "**********"

#: Case-insensitive deny-list of dict-key / header names whose values are
#: always scrubbed.  Compared via ``.lower()``; entries MUST be lowercase.
REDACT_KEYS: frozenset[str] = frozenset(
    {
        "token",
        "authorization",
        "api_key",
        "api-key",
        "github_token",
        "github-token",
        "x-github-token",
        "secret",
        "password",
        "x-api-key",
        "bearer",
    }
)

#: Consolidated regex list — covers every secret format any consumer has
#: matched historically.  Single list, no per-consumer subset.
SECRET_PATTERNS: list[re.Pattern[str]] = [
    # GitHub classic / server / user / refresh / OAuth PATs
    re.compile(r"gh[pousr]_[A-Za-z0-9]{36,}"),
    # GitHub fine-grained PAT (exact length 82)
    re.compile(r"github_pat_[A-Za-z0-9_]{82}"),
    # AWS access key ID families
    re.compile(r"(AKIA|ASIA|AGPA|AIDA)[A-Z0-9]{16}"),
    # AWS secret access key (key=value form)
    re.compile(
        r"aws_secret_access_key\s*[:=]\s*[\"']?[A-Za-z0-9/+=]{40}[\"']?",
        re.IGNORECASE,
    ),
    # RFC 6750 bearer tokens
    re.compile(r"Bearer\s+[A-Za-z0-9\-._~+/]+=*"),
    # JWT triplet (base64url.base64url.base64url)
    re.compile(
        r"eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]+"
    ),
]


def scrub_bytes(body: bytes) -> bytes:
    """Scrub all :data:`SECRET_PATTERNS` from a response body.

    Used by the H11 VCR cassette ``before_record_response`` callback.
    Decodes body as UTF-8 with ``errors="replace"`` for binary safety,
    re-encodes after substitution.

    Args:
        body: Raw HTTP response body bytes.

    Returns:
        The same bytes with any matched secret substring replaced by
        :data:`REDACT_PLACEHOLDER`.
    """
    text = body.decode("utf-8", errors="replace")
    for pattern in SECRET_PATTERNS:
        text = pattern.sub(REDACT_PLACEHOLDER, text)
    return text.encode("utf-8")


def redact_event_dict(
    _logger: Any, _method_name: str, event_dict: dict[str, Any]
) -> dict[str, Any]:
    """structlog processor (M10).

    Mutates ``event_dict`` in place AND returns it — matches the structlog
    processor protocol.  Scrubs by dict-key match (:data:`REDACT_KEYS`) AND
    by regex substitution on stringified values.  Non-string values pass
    through unchanged.

    Args:
        _logger: structlog BoundLogger; unused.
        _method_name: structlog method name; unused.
        event_dict: The log event dict to redact.

    Returns:
        The (mutated) ``event_dict``.
    """
    for key in list(event_dict.keys()):
        if key.lower() in REDACT_KEYS:
            event_dict[key] = REDACT_PLACEHOLDER
            continue
        val = event_dict[key]
        if isinstance(val, str):
            for pattern in SECRET_PATTERNS:
                val = pattern.sub(REDACT_PLACEHOLDER, val)
            event_dict[key] = val
    return event_dict


def grep_sources(paths: list[str]) -> list[tuple[str, int, str]]:
    """Pre-commit hook entry point (M22).

    Walks each path (file or directory) and runs :data:`SECRET_PATTERNS`
    line-by-line.  Returns a list of ``(path, line_no, matched_text)``
    tuples for every hit.  A caller is expected to print hits to stderr
    and exit non-zero if the list is non-empty.

    Args:
        paths: Filesystem paths to scan.  Directories are walked
            recursively; non-existent paths are silently skipped.

    Returns:
        List of ``(path, line_no, matched_text)`` tuples (may be empty).
    """
    hits: list[tuple[str, int, str]] = []
    for raw_path in paths:
        root = Path(raw_path)
        if not root.exists():
            continue
        files = [root] if root.is_file() else list(root.rglob("*"))
        for fp in files:
            if not fp.is_file():
                continue
            try:
                text = fp.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            for lineno, line in enumerate(text.splitlines(), start=1):
                for pattern in SECRET_PATTERNS:
                    match = pattern.search(line)
                    if match:
                        hits.append((str(fp), lineno, match.group(0)))
                        # one hit per line is enough — stop scanning this line
                        break
    return hits


__all__ = [
    "REDACT_PLACEHOLDER",
    "REDACT_KEYS",
    "SECRET_PATTERNS",
    "scrub_bytes",
    "redact_event_dict",
    "grep_sources",
]

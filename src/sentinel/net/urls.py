"""URL helpers for ``sentinel.net`` — log-safe and parsing utilities.

Distinct from :mod:`sentinel.net.cache`'s ``canonical_url`` (which is a
cache-key formatter that drops fragments and collapses empty paths):
this module's helpers preserve path, query, and fragment verbatim so
their output can be safely rendered in logs or error messages.
"""

from __future__ import annotations

from urllib.parse import urlsplit, urlunsplit

__all__ = ["strip_url_credentials"]


def strip_url_credentials(url: str) -> str:
    """Return ``url`` with any ``user[:pass]@`` userinfo component removed.

    Safe for structured logs — preserves scheme, port, path, query, and
    fragment so operators still see the useful bits of the URL.  RFC 3986
    §3.2.1: the userinfo subcomponent is everything before the ``@`` in
    the authority; ``urlsplit`` parses it into ``parts.username`` /
    ``parts.password`` and exposes the host separately via
    ``parts.hostname`` — so rebuilding netloc from ``hostname`` (+ port)
    is the canonical way to drop credentials without touching the rest.

    Fast path: if ``@`` does not appear anywhere in the URL, no stripping
    is possible — return the string unchanged to avoid the parser round-
    trip cost on every logger call.  Query strings may legitimately
    contain ``@`` (e.g. ``?ref=user@domain``); the ``urlsplit`` parser
    correctly leaves those untouched because the authority ends at the
    first ``/`` or ``?``.
    """
    if "@" not in url:
        return url
    parts = urlsplit(url)
    host = parts.hostname or ""
    port = parts.port
    netloc = f"{host}:{port}" if port else host
    return urlunsplit(
        (parts.scheme, netloc, parts.path, parts.query, parts.fragment)
    )

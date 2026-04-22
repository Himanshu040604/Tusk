"""SSRF guards (§ 8.2).

Hand-rolled fallback implementing the same rules ``httpx-secure`` would
enforce — we prefer stdlib ``ipaddress`` so the security-critical path
has no third-party dependency surface (§ 14 risk: ``httpx-secure`` thin).

Rules implemented (H2 + H9 + H10 + H13):

* RFC 1918 + link-local + loopback + multicast IPv4 rejected.
* ULA, link-local, loopback, multicast IPv6 rejected.
* NAT64 / Teredo / 6to4 tunnel prefixes rejected; embedded IPv4 is
  extracted and run through the IPv4 check transitively.
* Scheme allow-list: only ``http`` / ``https``.
* DNS resolve-once: every A/AAAA answer is validated.
* Literal-IP redirects: URL hostnames parsed by ``ipaddress.ip_address``
  directly when they are not hostnames.

Public API:

* :func:`resolve_and_validate` — full chain (scheme -> parse -> resolve
  -> per-IP check).  Raises :class:`SSRFBlockedError`.
* :func:`block_private_ipv4` / :func:`block_private_ipv6` — narrow
  per-address helpers for redirect hop validation.
* :func:`validate_scheme` — standalone scheme guard.
"""

from __future__ import annotations

import ipaddress
import socket
from typing import Final
from urllib.parse import urlparse

# H10 scheme guard — frozenset for O(1) membership, immutable.
ALLOWED_SCHEMES: Final[frozenset[str]] = frozenset({"http", "https"})


class SSRFBlockedError(Exception):
    """Raised when a URL / IP fails SSRF validation.

    The message includes the blocked address and the reason so logs /
    CLI output can forensic-replay rejected fetches.
    """


def validate_scheme(url: str) -> str:
    """Return the scheme lowercased; raise :class:`SSRFBlockedError` if disallowed."""
    parsed = urlparse(url)
    scheme = (parsed.scheme or "").lower()
    if scheme not in ALLOWED_SCHEMES:
        raise SSRFBlockedError(
            f"scheme {scheme!r} not in allowed set {sorted(ALLOWED_SCHEMES)} "
            f"(url={url!r})"
        )
    return scheme


def _strip_zone(addr: str) -> str:
    """Drop IPv6 zone-ID suffix (``fe80::1%eth0`` -> ``fe80::1``)."""
    return addr.split("%", 1)[0]


def block_private_ipv4(addr: str) -> None:
    """Reject RFC 1918 / loopback / link-local / multicast IPv4.

    Raises:
        SSRFBlockedError: On any blocked range.
    """
    ip = ipaddress.IPv4Address(addr)
    # ``is_private`` catches RFC1918 + 169.254/16 link-local + 127/8 loopback.
    if (
        ip.is_private
        or ip.is_loopback
        or ip.is_link_local
        or ip.is_multicast
        or ip.is_unspecified
        or ip.is_reserved
    ):
        raise SSRFBlockedError(f"IPv4 {addr} is in a blocked range")

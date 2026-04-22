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


# H13 — tunneling-protocol prefixes that embed IPv4 (NAT64, 6to4, Teredo).
# These networks may map to RFC1918 destinations when the embedded v4 is
# extracted.  We reject by prefix AND extract+recurse through IPv4 check.
_NAT64_WELL_KNOWN: Final = ipaddress.IPv6Network("64:ff9b::/96")
_NAT64_LOCAL: Final = ipaddress.IPv6Network("64:ff9b:1::/48")
_TEREDO: Final = ipaddress.IPv6Network("2001::/32")
_6TO4: Final = ipaddress.IPv6Network("2002::/16")
_IPV4_MAPPED: Final = ipaddress.IPv6Network("::ffff:0:0/96")


def _extract_embedded_v4(ip: ipaddress.IPv6Address) -> ipaddress.IPv4Address | None:
    """Extract the embedded IPv4 address from tunnel / mapped IPv6 addresses.

    Returns None if no embedded v4 is present.  Handles:

    * IPv4-mapped (``::ffff:a.b.c.d``)
    * NAT64 well-known + local-use (last 32 bits)
    * Teredo (``IPv6Address.teredo[1]`` — second element is client IPv4)
    * 6to4 (middle 32 bits after ``2002:``)
    """
    if ip in _IPV4_MAPPED:
        return ip.ipv4_mapped
    if ip in _NAT64_WELL_KNOWN or ip in _NAT64_LOCAL:
        # Last 32 bits encode IPv4.
        return ipaddress.IPv4Address(int(ip) & 0xFFFFFFFF)
    if ip in _TEREDO and ip.teredo is not None:
        return ip.teredo[1]
    if ip in _6TO4 and ip.sixtofour is not None:
        return ip.sixtofour
    return None


def block_private_ipv6(addr: str) -> None:
    """Reject ULA / link-local / loopback / multicast + tunnel prefixes.

    For addresses in NAT64 / 6to4 / Teredo / IPv4-mapped ranges, the
    embedded IPv4 is extracted and run through the IPv4 block check —
    a Teredo-wrapped ``169.254.169.254`` must not escape.

    Raises:
        SSRFBlockedError: On any blocked address.
    """
    ip = ipaddress.IPv6Address(_strip_zone(addr))
    if (
        ip.is_private
        or ip.is_loopback
        or ip.is_link_local
        or ip.is_multicast
        or ip.is_unspecified
        or ip.is_reserved
        or ip.is_site_local  # deprecated but still flagged defensively
    ):
        raise SSRFBlockedError(f"IPv6 {addr} is in a blocked range")

    embedded = _extract_embedded_v4(ip)
    if embedded is not None:
        # Recurse through v4 guard — an attacker can't tunnel 127.0.0.1 via
        # ``::ffff:127.0.0.1`` or ``64:ff9b::7f00:1``.
        try:
            block_private_ipv4(str(embedded))
        except SSRFBlockedError as exc:
            raise SSRFBlockedError(
                f"IPv6 {addr} embeds blocked IPv4 {embedded}: {exc}"
            ) from exc
        # Non-embedded-blocked but still a tunnel — reject as surface:
        raise SSRFBlockedError(
            f"IPv6 {addr} uses a tunneling prefix ({embedded}) — rejected "
            f"to avoid DNS-rebinding / escape paths"
        )

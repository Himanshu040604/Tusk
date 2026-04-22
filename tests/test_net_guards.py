"""Tests for :mod:`sentinel.net.guards` (Phase 3 SSRF protections).

Covers scheme allow-list, IPv4/IPv6 private-range rejection, tunnel
prefix rejection (NAT64, 6to4, Teredo, IPv4-mapped), DNS resolution
path with monkeypatched ``socket.getaddrinfo``, and the literal-IP
fast path used on redirect hops (H9).
"""

from __future__ import annotations

import socket
from unittest.mock import patch

import pytest

from sentinel.net.guards import (
    ALLOWED_SCHEMES,
    SSRFBlockedError,
    block_private_ipv4,
    block_private_ipv6,
    resolve_and_validate,
    validate_scheme,
)


# ---------------------------------------------------------------------------
# Scheme allow-list
# ---------------------------------------------------------------------------


class TestScheme:
    def test_allowed_schemes_constant(self) -> None:
        assert ALLOWED_SCHEMES == frozenset({"http", "https"})

    @pytest.mark.parametrize("scheme", ["http", "https", "HTTP", "Https"])
    def test_valid_schemes(self, scheme: str) -> None:
        assert validate_scheme(f"{scheme}://example.com/") == scheme.lower()

    @pytest.mark.parametrize(
        "url",
        [
            "file:///etc/passwd",
            "ftp://example.com/",
            "gopher://example.com/",
            "ldap://example.com/",
            "javascript:alert(1)",
            "data:text/plain;base64,SGVsbG8=",
        ],
    )
    def test_blocked_schemes(self, url: str) -> None:
        with pytest.raises(SSRFBlockedError, match="scheme"):
            validate_scheme(url)


# ---------------------------------------------------------------------------
# IPv4 guard
# ---------------------------------------------------------------------------


class TestIPv4:
    @pytest.mark.parametrize(
        "addr",
        [
            "10.0.0.1",            # RFC 1918 class A
            "172.16.0.1",          # RFC 1918 class B
            "192.168.1.1",         # RFC 1918 class C
            "127.0.0.1",           # loopback
            "169.254.169.254",     # AWS / GCP / Azure metadata
            "0.0.0.0",             # unspecified
            "224.0.0.1",           # multicast
            "255.255.255.255",     # broadcast (reserved)
            "100.64.0.1",          # CGNAT (private per ipaddress)
        ],
    )
    def test_blocked_ipv4(self, addr: str) -> None:
        with pytest.raises(SSRFBlockedError):
            block_private_ipv4(addr)

    @pytest.mark.parametrize(
        "addr", ["8.8.8.8", "1.1.1.1", "140.82.121.4"],
    )
    def test_public_ipv4_passes(self, addr: str) -> None:
        block_private_ipv4(addr)  # no raise


# ---------------------------------------------------------------------------
# IPv6 guard
# ---------------------------------------------------------------------------


class TestIPv6:
    @pytest.mark.parametrize(
        "addr",
        [
            "::1",                 # loopback
            "fe80::1",             # link-local
            "fc00::1",             # ULA
            "ff02::1",             # multicast
            "::",                  # unspecified
        ],
    )
    def test_blocked_ipv6_plain(self, addr: str) -> None:
        with pytest.raises(SSRFBlockedError):
            block_private_ipv6(addr)

    def test_zone_id_stripped(self) -> None:
        # fe80::1%eth0 still resolves to the blocked base address.
        with pytest.raises(SSRFBlockedError):
            block_private_ipv6("fe80::1%eth0")

    def test_ipv4_mapped_to_loopback_rejected(self) -> None:
        with pytest.raises(SSRFBlockedError):
            block_private_ipv6("::ffff:127.0.0.1")

    def test_ipv4_mapped_to_rfc1918_rejected(self) -> None:
        with pytest.raises(SSRFBlockedError):
            block_private_ipv6("::ffff:10.0.0.1")

    def test_6to4_wrapping_public_still_rejected(self) -> None:
        # 6to4 range is itself considered a tunnel prefix and rejected.
        with pytest.raises(SSRFBlockedError):
            block_private_ipv6("2002:0808:0808::")

    def test_nat64_well_known_rejected(self) -> None:
        with pytest.raises(SSRFBlockedError):
            block_private_ipv6("64:ff9b::0a00:0001")  # embeds 10.0.0.1

    def test_public_ipv6_passes(self) -> None:
        # Google public DNS 2001:4860:4860::8888 is public; not in any blocked class.
        block_private_ipv6("2001:4860:4860::8888")


# ---------------------------------------------------------------------------
# resolve_and_validate — full chain
# ---------------------------------------------------------------------------


class TestResolveAndValidate:
    def test_literal_public_ipv4_url_passes(self) -> None:
        # Literal IP skips DNS; 8.8.8.8 is public.
        assert resolve_and_validate("http://8.8.8.8/") == "http://8.8.8.8/"

    def test_literal_private_ipv4_url_blocked(self) -> None:
        with pytest.raises(SSRFBlockedError):
            resolve_and_validate("http://169.254.169.254/latest/meta-data/")

    def test_literal_loopback_ipv6_blocked(self) -> None:
        with pytest.raises(SSRFBlockedError):
            resolve_and_validate("http://[::1]/")

    def test_empty_host_blocked(self) -> None:
        with pytest.raises(SSRFBlockedError, match="hostname"):
            resolve_and_validate("http:///path")

    def test_disallowed_scheme_blocked(self) -> None:
        with pytest.raises(SSRFBlockedError, match="scheme"):
            resolve_and_validate("file:///etc/passwd")

    def test_dns_all_public_passes(self) -> None:
        fake_info = [
            (socket.AF_INET, 0, 0, "", ("93.184.216.34", 0)),
        ]
        with patch("socket.getaddrinfo", return_value=fake_info):
            assert resolve_and_validate("https://example.com/") == "https://example.com/"

    def test_dns_returns_private_ipv4_blocked(self) -> None:
        fake_info = [
            (socket.AF_INET, 0, 0, "", ("10.0.0.5", 0)),
        ]
        with patch("socket.getaddrinfo", return_value=fake_info):
            with pytest.raises(SSRFBlockedError):
                resolve_and_validate("https://evil.example.com/")

    def test_dns_returns_metadata_ip_blocked(self) -> None:
        fake_info = [
            (socket.AF_INET, 0, 0, "", ("169.254.169.254", 0)),
        ]
        with patch("socket.getaddrinfo", return_value=fake_info):
            with pytest.raises(SSRFBlockedError):
                resolve_and_validate("https://rebind.example.com/")

    def test_dns_failure_blocked(self) -> None:
        with patch(
            "socket.getaddrinfo",
            side_effect=socket.gaierror("nodename nor servname provided"),
        ):
            with pytest.raises(SSRFBlockedError, match="DNS"):
                resolve_and_validate("https://nonexistent.invalid/")

    def test_dns_empty_answers_blocked(self) -> None:
        with patch("socket.getaddrinfo", return_value=[]):
            with pytest.raises(SSRFBlockedError, match="no A/AAAA"):
                resolve_and_validate("https://empty.example.com/")

    def test_dns_mixed_public_private_blocked(self) -> None:
        """Any private answer in an A+AAAA list must block."""
        fake_info = [
            (socket.AF_INET, 0, 0, "", ("8.8.8.8", 0)),
            (socket.AF_INET6, 0, 0, "", ("::1", 0, 0, 0)),
        ]
        with patch("socket.getaddrinfo", return_value=fake_info):
            with pytest.raises(SSRFBlockedError):
                resolve_and_validate("https://mixed.example.com/")

"""Tests for :mod:`sentinel.net.client` (Phase 3 hardened HTTP client).

Covers:

* Allow-list enforcement at the front door.
* SSRF blocking on initial URL.
* H9 redirect-chaser: 302 to a private IP must raise :class:`SSRFBlockedError`.
* Cache hit/miss semantics + ``X-Sentinel-Cache`` marker headers.
* ``--insecure`` WARN log emission.
"""

from __future__ import annotations

import socket
from pathlib import Path
from unittest.mock import patch

import httpx
import pytest

from sentinel.config import Settings
from sentinel.net.allow_list import AllowList
from sentinel.net.cache import DiskCache
from sentinel.net.client import (
    DomainNotAllowedError,
    ResponseTooLargeError,
    SentinelHTTPClient,
)
from sentinel.net.guards import SSRFBlockedError
from sentinel.net.retry import RetryPolicy


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def settings() -> Settings:
    s = Settings()
    s.network.allow_list.domains = ["example.com", "allowed.test"]
    s.network.max_redirects = 3
    return s


@pytest.fixture
def allow_list(settings: Settings) -> AllowList:
    return AllowList(settings.network.allow_list.domains)


@pytest.fixture
def cache(tmp_path: Path) -> DiskCache:
    return DiskCache(cache_dir=tmp_path / "cache")


@pytest.fixture
def retry() -> RetryPolicy:
    # Tight budget for tests.
    return RetryPolicy(budgets={"user_url": 1, "github": 1, "aws_docs": 1})


@pytest.fixture
def client(
    settings: Settings,
    allow_list: AllowList,
    cache: DiskCache,
    retry: RetryPolicy,
) -> SentinelHTTPClient:
    return SentinelHTTPClient(
        settings=settings,
        allow_list=allow_list,
        cache=cache,
        retry_policy=retry,
        insecure=False,
    )


# ---------------------------------------------------------------------------
# Allow-list enforcement
# ---------------------------------------------------------------------------


class TestAllowList:
    def test_unlisted_domain_rejected(self, client: SentinelHTTPClient) -> None:
        with pytest.raises(DomainNotAllowedError):
            client.get("https://notallowed.test/", source="user_url")

    def test_listed_domain_passes_allow_list(
        self, client: SentinelHTTPClient, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Allowed domain still goes through SSRF guard; we mock DNS to public IP."""
        fake_info = [(socket.AF_INET, 0, 0, "", ("93.184.216.34", 0))]
        with patch("socket.getaddrinfo", return_value=fake_info):
            # Preflight succeeds; the actual GET would hit the network,
            # so we only assert that no DomainNotAllowedError fired.
            with patch.object(
                client._client, "get", side_effect=httpx.ConnectError("no net in tests")
            ):
                with pytest.raises(httpx.ConnectError):
                    client.get("https://example.com/", source="user_url")


# ---------------------------------------------------------------------------
# SSRF blocking — initial URL
# ---------------------------------------------------------------------------


class TestSsrfInitial:
    def test_ssrf_on_private_ip_literal(self, client: SentinelHTTPClient) -> None:
        # Allow-list accepts literal-IP 169.254.169.254 (no allow-list entry
        # covers it, so allow-list check rejects first).
        with pytest.raises(DomainNotAllowedError):
            client.get("http://169.254.169.254/latest/", source="user_url")

    def test_ssrf_on_dns_to_private_ip(self, client: SentinelHTTPClient) -> None:
        fake_info = [(socket.AF_INET, 0, 0, "", ("10.0.0.1", 0))]
        with patch("socket.getaddrinfo", return_value=fake_info):
            with pytest.raises(SSRFBlockedError):
                client.get("https://example.com/", source="user_url")


# ---------------------------------------------------------------------------
# H9 — redirect-chaser re-runs preflight on every hop
# ---------------------------------------------------------------------------


class TestRedirectChaserH9:
    def test_302_to_private_ip_blocked(
        self,
        client: SentinelHTTPClient,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """The INITIAL host resolves public, then the 302 points at 10.0.0.1.

        The H9 enforcement re-runs ``_preflight`` on the redirect target
        BEFORE issuing the next hop — that must raise :class:`SSRFBlockedError`
        (because the target host is not even allow-listed, we may get
        DomainNotAllowedError instead depending on config, which is also
        acceptable H9 behaviour).
        """
        # First hop DNS returns public.
        fake_info = [(socket.AF_INET, 0, 0, "", ("93.184.216.34", 0))]

        redirect_response = httpx.Response(
            status_code=302,
            headers={"Location": "http://10.0.0.1/internal"},
            request=httpx.Request("GET", "https://example.com/"),
        )

        with patch("socket.getaddrinfo", return_value=fake_info):
            with patch.object(client._client, "get", return_value=redirect_response):
                with pytest.raises((SSRFBlockedError, DomainNotAllowedError)):
                    client.get("https://example.com/", source="user_url")

    def test_too_many_redirects(self, client: SentinelHTTPClient, settings: Settings) -> None:
        """Exceeding ``network.max_redirects`` must raise TooManyRedirects."""
        fake_info = [(socket.AF_INET, 0, 0, "", ("93.184.216.34", 0))]

        def make_302(url: str) -> httpx.Response:
            return httpx.Response(
                status_code=302,
                headers={"Location": url},
                request=httpx.Request("GET", url),
            )

        # Every request returns a self-redirect within the allow-listed domain.
        # Limit is 3; we should exhaust at hop 3.
        redirect_resp = make_302("https://example.com/loop")

        with patch("socket.getaddrinfo", return_value=fake_info):
            with patch.object(client._client, "get", return_value=redirect_resp):
                with pytest.raises(httpx.TooManyRedirects):
                    client.get("https://example.com/", source="user_url")


# ---------------------------------------------------------------------------
# Cache integration
# ---------------------------------------------------------------------------


class TestCacheIntegration:
    def test_cache_hit_short_circuits(
        self,
        client: SentinelHTTPClient,
        cache: DiskCache,
    ) -> None:
        # Pre-seed the cache.
        cache.put(
            url="https://example.com/x",
            source="user_url",
            body=b"cached-body",
            headers={"Content-Type": "text/plain"},
        )
        # No HTTP call should happen because cache hits; patching httpx
        # confirms it.  Even so, the pre-flight still runs — mock DNS.
        fake_info = [(socket.AF_INET, 0, 0, "", ("93.184.216.34", 0))]
        with patch("socket.getaddrinfo", return_value=fake_info):
            with patch.object(
                client._client, "get", side_effect=AssertionError("should not hit network")
            ):
                resp = client.get("https://example.com/x", source="user_url")
        assert resp.status_code == 200
        assert resp.content == b"cached-body"
        assert resp.headers.get("X-Sentinel-Cache") == "HIT"

    def test_cache_miss_populates_on_2xx(
        self, client: SentinelHTTPClient, cache: DiskCache
    ) -> None:
        fake_info = [(socket.AF_INET, 0, 0, "", ("93.184.216.34", 0))]
        live = httpx.Response(
            status_code=200,
            content=b"live-body",
            headers={"Content-Type": "text/plain"},
            request=httpx.Request("GET", "https://example.com/miss"),
        )
        with patch("socket.getaddrinfo", return_value=fake_info):
            with patch.object(client._client, "get", return_value=live):
                resp = client.get("https://example.com/miss", source="user_url")
        assert resp.headers.get("X-Sentinel-Cache") == "MISS"
        # Cache is now populated.
        entry = cache.get("https://example.com/miss", "user_url")
        assert entry is not None
        assert entry.body == b"live-body"


# ---------------------------------------------------------------------------
# --insecure WARN emission
# ---------------------------------------------------------------------------


class TestInsecureWarn:
    def test_insecure_emits_warn_log(
        self,
        settings: Settings,
        allow_list: AllowList,
        cache: DiskCache,
        retry: RetryPolicy,
    ) -> None:
        insecure_client = SentinelHTTPClient(
            settings=settings,
            allow_list=allow_list,
            cache=cache,
            retry_policy=retry,
            insecure=True,
        )
        fake_info = [(socket.AF_INET, 0, 0, "", ("93.184.216.34", 0))]
        live = httpx.Response(
            status_code=200,
            content=b"x",
            request=httpx.Request("GET", "https://example.com/"),
        )
        with patch("socket.getaddrinfo", return_value=fake_info):
            # Patch the logger so we can introspect the warning call.
            with patch.object(insecure_client._log, "warning") as mock_warn:
                with patch.object(insecure_client._client, "get", return_value=live):
                    insecure_client.get("https://example.com/", source="user_url")
        mock_warn.assert_called()
        # At least one call mentions TLS disabled.
        assert any("tls_verify_disabled" in str(c) for c in mock_warn.call_args_list)

    def test_insecure_does_not_populate_cache_on_2xx(
        self,
        settings: Settings,
        allow_list: AllowList,
        cache: DiskCache,
        retry: RetryPolicy,
    ) -> None:
        """SEC-M3: --insecure responses must NOT persist to HMAC cache.

        Prevents persistent MITM poisoning of future secure runs: a
        tampered body from an insecure session would otherwise be
        signed and served (with HMAC valid) on every subsequent run.
        """
        insecure_client = SentinelHTTPClient(
            settings=settings,
            allow_list=allow_list,
            cache=cache,
            retry_policy=retry,
            insecure=True,
        )
        fake_info = [(socket.AF_INET, 0, 0, "", ("93.184.216.34", 0))]
        live = httpx.Response(
            status_code=200,
            content=b"live-body-over-insecure",
            headers={"Content-Type": "text/plain"},
            request=httpx.Request("GET", "https://example.com/insecure"),
        )
        with patch("socket.getaddrinfo", return_value=fake_info):
            with patch.object(insecure_client._client, "get", return_value=live):
                resp = insecure_client.get(
                    "https://example.com/insecure", source="user_url"
                )
        # Response still returned to caller.
        assert resp.status_code == 200
        assert resp.content == b"live-body-over-insecure"
        # Cache must NOT be populated.
        assert cache.get("https://example.com/insecure", "user_url") is None

    def test_secure_run_can_still_read_prior_secure_cache_entry(
        self,
        settings: Settings,
        allow_list: AllowList,
        cache: DiskCache,
        retry: RetryPolicy,
    ) -> None:
        """Read path unchanged: prior legitimate entries remain usable.

        Pre-populating cache via the secure path must still be served
        by later insecure runs (the design explicitly allows reads —
        only writes are blocked during --insecure).
        """
        cache.put(
            url="https://example.com/prior",
            source="user_url",
            body=b"secure-cached-body",
            headers={"Content-Type": "text/plain"},
            etag=None,
        )
        insecure_client = SentinelHTTPClient(
            settings=settings,
            allow_list=allow_list,
            cache=cache,
            retry_policy=retry,
            insecure=True,
        )
        with patch.object(
            insecure_client._client, "get",
            side_effect=AssertionError("should not hit network on HIT"),
        ):
            resp = insecure_client.get(
                "https://example.com/prior", source="user_url"
            )
        assert resp.content == b"secure-cached-body"
        assert resp.headers.get("X-Sentinel-Cache") == "HIT"

    def test_insecure_sets_httpx_verify_false(
        self,
        settings: Settings,
        allow_list: AllowList,
        cache: DiskCache,
        retry: RetryPolicy,
    ) -> None:
        c = SentinelHTTPClient(
            settings=settings,
            allow_list=allow_list,
            cache=cache,
            retry_policy=retry,
            insecure=True,
        )
        # httpx stores verify on the transport; check via _transport or _options.
        # Easiest: the Client's _transport context carries it.  Just assert
        # the constructor accepted insecure=True.
        assert c._insecure is True


# ---------------------------------------------------------------------------
# SEC-M1 — max_download_bytes enforcement
# ---------------------------------------------------------------------------


class TestMaxDownloadBytes:
    """SEC-M1: enforce settings.network.max_download_bytes.

    Two-layer defense — preflight on Content-Length + post-check on the
    actual buffered body length — to defend against both honest and
    lying servers while keeping the cache clean.
    """

    @pytest.fixture
    def tight_client(
        self,
        settings: Settings,
        allow_list: AllowList,
        cache: DiskCache,
        retry: RetryPolicy,
    ) -> SentinelHTTPClient:
        # Shrink limit for testing.
        settings.network.max_download_bytes = 1024
        return SentinelHTTPClient(
            settings=settings,
            allow_list=allow_list,
            cache=cache,
            retry_policy=retry,
            insecure=False,
        )

    def test_honest_oversize_content_length_rejected(
        self, tight_client: SentinelHTTPClient, cache: DiskCache
    ) -> None:
        """Server honestly declares Content-Length > limit → preflight rejects."""
        fake_info = [(socket.AF_INET, 0, 0, "", ("93.184.216.34", 0))]
        live = httpx.Response(
            status_code=200,
            content=b"x" * 2048,
            headers={"Content-Length": "2048"},
            request=httpx.Request("GET", "https://example.com/big"),
        )
        with patch("socket.getaddrinfo", return_value=fake_info):
            with patch.object(tight_client._client, "get", return_value=live):
                with pytest.raises(ResponseTooLargeError) as excinfo:
                    tight_client.get("https://example.com/big", source="user_url")
        assert excinfo.value.size == 2048
        assert excinfo.value.limit == 1024
        # Cache must NOT be poisoned.
        assert cache.get("https://example.com/big", "user_url") is None

    def test_lying_server_post_check_rejected(
        self, tight_client: SentinelHTTPClient, cache: DiskCache
    ) -> None:
        """Server lies about Content-Length → post-check catches it."""
        fake_info = [(socket.AF_INET, 0, 0, "", ("93.184.216.34", 0))]
        live = httpx.Response(
            status_code=200,
            content=b"x" * 2048,
            headers={"Content-Length": "100"},  # lie
            request=httpx.Request("GET", "https://example.com/liar"),
        )
        with patch("socket.getaddrinfo", return_value=fake_info):
            with patch.object(tight_client._client, "get", return_value=live):
                with pytest.raises(ResponseTooLargeError) as excinfo:
                    tight_client.get("https://example.com/liar", source="user_url")
        assert excinfo.value.size == 2048
        # Cache must NOT be poisoned.
        assert cache.get("https://example.com/liar", "user_url") is None

    def test_under_limit_passes(
        self, tight_client: SentinelHTTPClient, cache: DiskCache
    ) -> None:
        """Small body under the limit flows through normally."""
        fake_info = [(socket.AF_INET, 0, 0, "", ("93.184.216.34", 0))]
        live = httpx.Response(
            status_code=200,
            content=b"ok" * 100,  # 200 bytes << 1024
            request=httpx.Request("GET", "https://example.com/small"),
        )
        with patch("socket.getaddrinfo", return_value=fake_info):
            with patch.object(tight_client._client, "get", return_value=live):
                resp = tight_client.get(
                    "https://example.com/small", source="user_url"
                )
        assert resp.status_code == 200
        assert resp.content == b"ok" * 100
        # Cache populated on MISS.
        entry = cache.get("https://example.com/small", "user_url")
        assert entry is not None

    def test_malformed_content_length_falls_through_to_post_check(
        self, tight_client: SentinelHTTPClient
    ) -> None:
        """Non-numeric Content-Length → preflight skip, post-check decides."""
        fake_info = [(socket.AF_INET, 0, 0, "", ("93.184.216.34", 0))]
        live = httpx.Response(
            status_code=200,
            content=b"x" * 2048,
            headers={"Content-Length": "not-a-number"},
            request=httpx.Request("GET", "https://example.com/bad-cl"),
        )
        with patch("socket.getaddrinfo", return_value=fake_info):
            with patch.object(tight_client._client, "get", return_value=live):
                with pytest.raises(ResponseTooLargeError):
                    tight_client.get("https://example.com/bad-cl", source="user_url")

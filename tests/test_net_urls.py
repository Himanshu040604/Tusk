"""Tests for ``sentinel.net.urls.strip_url_credentials`` (SEC-L1)."""

from __future__ import annotations

from sentinel.net.urls import strip_url_credentials


class TestStripUrlCredentials:
    """SEC-L1: remove user[:pass]@ userinfo from URLs rendered in logs."""

    def test_no_credentials_returns_unchanged(self):
        url = "https://example.com/path?q=1"
        assert strip_url_credentials(url) == url

    def test_no_at_sign_takes_fast_path(self):
        # Fast path returns the same object identity, not just equal.
        url = "https://example.com/path"
        assert strip_url_credentials(url) is url

    def test_user_only_stripped(self):
        assert strip_url_credentials("https://alice@example.com/path") == "https://example.com/path"

    def test_user_and_password_stripped(self):
        assert (
            strip_url_credentials("https://alice:s3cret@example.com/path")
            == "https://example.com/path"
        )

    def test_port_preserved(self):
        assert (
            strip_url_credentials("https://alice:s3cret@example.com:8443/path")
            == "https://example.com:8443/path"
        )

    def test_query_preserved(self):
        assert (
            strip_url_credentials("https://alice:s3cret@example.com/path?q=1&r=2")
            == "https://example.com/path?q=1&r=2"
        )

    def test_fragment_preserved(self):
        assert (
            strip_url_credentials("https://alice:s3cret@example.com/path#frag")
            == "https://example.com/path#frag"
        )

    def test_at_in_query_not_falsely_redacted(self):
        """Query strings often contain ``@`` — must not be confused for userinfo.

        This is the exact false-positive class that broke the prior
        naive regex ``//[^@]+@`` from the U6 commit.
        """
        url = "https://example.com/path?ref=user@domain"
        assert strip_url_credentials(url) == url

    def test_at_in_path_not_falsely_redacted(self):
        """``@`` is a reserved-but-legal path char per RFC 3986."""
        url = "https://example.com/users/@alice"
        # urlsplit parses the @ inside path correctly; authority
        # is still ``example.com`` (no userinfo).
        result = strip_url_credentials(url)
        assert "example.com" in result
        assert "alice" in result

    def test_http_scheme_also_stripped(self):
        assert strip_url_credentials("http://alice:s3cret@example.com/") == "http://example.com/"

    def test_empty_string_safe(self):
        assert strip_url_credentials("") == ""

    def test_bare_hostname_returns_unchanged(self):
        # Not a real URL; urlsplit handles it as path-only.
        url = "example.com"
        assert strip_url_credentials(url) == url

    def test_token_like_username_stripped(self):
        assert (
            strip_url_credentials("https://ghp_abc123def456@github.com/owner/repo")
            == "https://github.com/owner/repo"
        )

"""Smoke coverage for ``sentinel.logging_setup``.

Previously at 0% coverage (phase7_postship_review_tests.md § "Dimension B").
Covers the public API ``configure`` plus ``ssl_cert_file_audit`` branches.
"""

from __future__ import annotations

import io
from pathlib import Path

import pytest

from sentinel.logging_setup import configure, ssl_cert_file_audit


def test_configure_human_format() -> None:
    """configure(fmt='human') configures structlog with ConsoleRenderer."""
    stream = io.StringIO()
    configure(level="INFO", fmt="human", stream=stream)

    import structlog

    logger = structlog.get_logger("test.human")
    logger.info("hello_human")
    output = stream.getvalue()
    assert "hello_human" in output


def test_configure_json_format() -> None:
    """configure(fmt='json') configures structlog with JSONRenderer."""
    stream = io.StringIO()
    configure(level="INFO", fmt="json", stream=stream)

    import structlog

    logger = structlog.get_logger("test.json")
    logger.info("hello_json", key="value")
    output = stream.getvalue()
    assert "hello_json" in output
    assert '"key": "value"' in output


def test_configure_respects_level(caplog: pytest.LogCaptureFixture) -> None:
    """configure(level='WARNING') filters DEBUG/INFO."""
    stream = io.StringIO()
    configure(level="WARNING", fmt="human", stream=stream)

    import structlog

    logger = structlog.get_logger("test.level")
    logger.info("should_not_appear")
    logger.warning("should_appear")

    output = stream.getvalue()
    # Structlog uses filtering_bound_logger; INFO below WARNING is filtered.
    assert "should_appear" in output
    assert "should_not_appear" not in output


def test_configure_no_color_env(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """NO_COLOR env var selects color-disabled ConsoleRenderer."""
    monkeypatch.setenv("NO_COLOR", "1")
    monkeypatch.delenv("FORCE_COLOR", raising=False)
    stream = io.StringIO()
    # Must not raise; ConsoleRenderer construction should honor NO_COLOR.
    configure(level="INFO", fmt="human", stream=stream)


def test_configure_force_color_env(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """FORCE_COLOR overrides NO_COLOR (standard convention)."""
    monkeypatch.setenv("NO_COLOR", "1")
    monkeypatch.setenv("FORCE_COLOR", "1")
    stream = io.StringIO()
    configure(level="INFO", fmt="human", stream=stream)


def test_ssl_cert_file_audit_no_env_var(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """ssl_cert_file_audit returns silently when no env var set."""
    monkeypatch.delenv("SSL_CERT_FILE", raising=False)
    monkeypatch.delenv("REQUESTS_CA_BUNDLE", raising=False)
    # Must not raise.
    ssl_cert_file_audit()


def test_ssl_cert_file_audit_missing_file(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """ssl_cert_file_audit warns when env var points at non-existent file."""
    missing = tmp_path / "nonexistent.pem"
    monkeypatch.setenv("SSL_CERT_FILE", str(missing))
    stream = io.StringIO()
    configure(level="WARNING", fmt="json", stream=stream)
    ssl_cert_file_audit()
    output = stream.getvalue()
    assert "ssl_cert_file_set_but_missing" in output


def test_ssl_cert_file_audit_happy_path(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """ssl_cert_file_audit logs sha256 when env var points at a real file."""
    bundle = tmp_path / "ca.pem"
    bundle.write_bytes(b"-----BEGIN CERTIFICATE-----\nstub\n-----END CERTIFICATE-----")
    monkeypatch.setenv("SSL_CERT_FILE", str(bundle))
    stream = io.StringIO()
    configure(level="WARNING", fmt="json", stream=stream)
    ssl_cert_file_audit()
    output = stream.getvalue()
    assert "ssl_cert_file_override_active" in output
    assert "sha256" in output

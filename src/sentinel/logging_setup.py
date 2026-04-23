"""Structlog configuration.

Processor chain (§ 11.1) applied in order:

1. :func:`structlog.contextvars.merge_contextvars`  — binds per-request context
2. :func:`structlog.processors.add_log_level`       — level tag
3. :func:`structlog.processors.TimeStamper`         — ISO, UTC timestamp
4. :func:`sentinel.secrets_patterns.redact_event_dict` (M10)
5. chosen renderer: ``ConsoleRenderer`` (human) or ``JSONRenderer`` (json)

Import-time discipline (H23):

* **Phase 1 uses** ``cache_logger_on_first_use=False`` so repeat calls to
  :func:`configure` during tests / CLI re-init actually take effect.  The
  flag may flip to ``True`` in Phase 6 once configuration is proven stable.
* **No module-level ``structlog.get_logger()`` calls** anywhere in
  ``src/sentinel/``.  Callers obtain loggers inside function bodies or
  class ``__init__``.  Exit gate: ``grep -rn 'get_logger()' src/`` finds
  zero import-time matches.
"""

from __future__ import annotations

import logging
import os
import sys
from pathlib import Path
from typing import Literal

import structlog

from .secrets_patterns import redact_event_dict

LogFormat = Literal["human", "json"]
LogLevel = Literal["DEBUG", "INFO", "WARNING", "ERROR"]


def _pick_renderer(fmt: LogFormat) -> object:
    if fmt == "json":
        return structlog.processors.JSONRenderer()
    # Respect NO_COLOR (standard convention) and FORCE_COLOR.
    no_color = os.environ.get("NO_COLOR") not in (None, "")
    force_color = os.environ.get("FORCE_COLOR") not in (None, "")
    use_color = (not no_color) or force_color
    return structlog.dev.ConsoleRenderer(colors=use_color)


def configure(
    level: LogLevel = "INFO",
    fmt: LogFormat = "human",
    stream: object | None = None,
) -> None:
    """Configure the process-wide structlog pipeline.

    Safe to call multiple times — Phase 1's
    ``cache_logger_on_first_use=False`` makes reconfiguration deterministic.

    Args:
        level: Logging level threshold.
        fmt: ``"human"`` or ``"json"``.  Selects the final renderer.
        stream: Optional stream override; defaults to ``sys.stderr`` so
            log output never pollutes stdout pipelines.
    """
    stream = stream or sys.stderr

    # stdlib logging is the backing transport — structlog writes through it
    # so third-party libraries that log via `logging` (tenacity, alembic,
    # httpx, ...) end up in the same sink with identical format.
    logging.basicConfig(
        level=getattr(logging, level, logging.INFO),
        format="%(message)s",
        stream=stream,  # type: ignore[arg-type]
        force=True,
    )

    structlog.configure(
        processors=[
            structlog.contextvars.merge_contextvars,
            structlog.processors.add_log_level,
            structlog.processors.TimeStamper(fmt="iso", utc=True),
            redact_event_dict,  # type: ignore[list-item]
            _pick_renderer(fmt),  # type: ignore[list-item]
        ],
        wrapper_class=structlog.make_filtering_bound_logger(getattr(logging, level, logging.INFO)),
        context_class=dict,
        logger_factory=structlog.PrintLoggerFactory(file=stream),  # type: ignore[arg-type]
        # H23: False during Phase 1 so reconfigure actually reshapes bound
        # loggers.  May flip to True in Phase 6 once init is stable.
        cache_logger_on_first_use=False,
    )


def ssl_cert_file_audit() -> None:
    """M15 — log a WARN with SHA-256 of ``SSL_CERT_FILE`` if set.

    Must run AFTER :func:`configure` so ``redact_event_dict`` is active,
    and BEFORE any subcommand dispatches an HTTPS request.  Letting ops
    audit corporate MITM bundle swaps via SIEM pipelines.
    """
    import hashlib

    bundle_path = os.environ.get("SSL_CERT_FILE") or os.environ.get("REQUESTS_CA_BUNDLE")
    if not bundle_path:
        return

    logger = structlog.get_logger("sentinel.security")
    path = Path(bundle_path)
    if not path.is_file():
        logger.warning(
            "ssl_cert_file_set_but_missing",
            path=str(path),
            env_var=("SSL_CERT_FILE" if os.environ.get("SSL_CERT_FILE") else "REQUESTS_CA_BUNDLE"),
        )
        return

    try:
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
    except OSError as exc:
        logger.warning(
            "ssl_cert_file_unreadable",
            path=str(path),
            error=str(exc),
        )
        return

    logger.warning(
        "ssl_cert_file_override_active",
        path=str(path),
        sha256=digest,
        env_var=("SSL_CERT_FILE" if os.environ.get("SSL_CERT_FILE") else "REQUESTS_CA_BUNDLE"),
        note=("Corporate MITM bundle swap surface — audit hash against a trusted reference."),
    )


__all__ = ["configure", "ssl_cert_file_audit", "LogFormat", "LogLevel"]

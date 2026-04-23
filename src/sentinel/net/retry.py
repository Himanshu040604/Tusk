"""Retry policies (§ 8.6) built on ``tenacity``.

Per-source budgets (GitHub 5, AWS docs 3, user URLs 2) combined with a
process-wide wall-clock cap (``max_total_wait_seconds``).  4xx responses
that are not worth retrying are wrapped in :class:`NonRetryableHTTPError`
so tenacity's ``retry_if_exception_type`` predicate filters them out.

``reraise=True`` is set on every ``Retrying`` we construct — callers see
the real underlying exception rather than tenacity's ``RetryError``
wrapper, which matters for structured-log correlation.
"""

from __future__ import annotations

from dataclasses import dataclass
from email.utils import parsedate_to_datetime
from datetime import datetime, timezone
from typing import TYPE_CHECKING, Callable, Final, Optional

import httpx
from tenacity import (
    Retrying,
    retry_if_exception,
    stop_after_attempt,
    stop_after_delay,
    stop_any,
    wait_exponential,
)

if TYPE_CHECKING:
    from ..config import RetriesSettings


# Default budgets mirror ``RetriesBudgets`` in config.py.
_DEFAULT_BUDGETS: Final[dict[str, int]] = {
    "github": 5,
    "aws_docs": 3,
    "user_url": 2,
}


class NonRetryableHTTPError(httpx.HTTPError):
    """4xx response that tenacity should NOT retry.

    Raised by the client wrapper when a response status falls into the
    definite-failure bucket (404, 401, 403, ...).  Matches
    :class:`httpx.HTTPError` so existing ``except httpx.HTTPError``
    handlers still catch it.
    """

    def __init__(self, message: str, status_code: int) -> None:
        super().__init__(message)
        self.status_code = status_code


# HTTP status codes that DO justify a retry.  Anything else 4xx is
# wrapped in NonRetryableHTTPError.  429 and 5xx are retryable; 408
# is request-timeout (retryable); the rest of 4xx are permanent.
_RETRYABLE_STATUS_CODES: Final[frozenset[int]] = frozenset(
    {408, 425, 429, 500, 502, 503, 504}
)


def is_retryable_status(status_code: int) -> bool:
    """Return True iff ``status_code`` is worth retrying per § 8.6."""
    return status_code in _RETRYABLE_STATUS_CODES


def parse_retry_after(value: str | None) -> float | None:
    """Parse ``Retry-After`` header (RFC 7231 §7.1.3): seconds or HTTP-date.

    Returns seconds-from-now as a float, or ``None`` if unparseable / absent.
    Negative results are clamped to 0 (past-date header from a clock-skewed
    server).
    """
    if not value:
        return None
    value = value.strip()
    try:
        return max(0.0, float(value))
    except ValueError:
        pass
    try:
        dt = parsedate_to_datetime(value)
    except (TypeError, ValueError):
        return None
    if dt is None:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    delta = (dt - datetime.now(timezone.utc)).total_seconds()
    return max(0.0, delta)


@dataclass(frozen=True)
class RetryPolicy:
    """Per-source retry configuration.

    Attributes:
        budgets: Dict of source-name -> max attempts.  Keys match the
            ``source`` argument passed to ``client.get()`` (``github``,
            ``aws_docs``, ``user_url``, ``policy_sentry`` etc.).
        max_total_wait_seconds: Wall-clock cap across all retry attempts.
            Prevents a runaway exponential backoff from hanging the CLI
            longer than a user reasonably expects.
        base_wait_seconds: Initial backoff interval; doubled each attempt.
    """

    budgets: dict[str, int]
    max_total_wait_seconds: int = 300
    base_wait_seconds: float = 1.0

    @classmethod
    def from_settings(cls, settings: "RetriesSettings") -> "RetryPolicy":
        """Build a policy from a ``RetriesSettings`` config block."""
        b = settings.budgets
        return cls(
            budgets={
                "github": b.github,
                "aws_docs": b.aws_docs,
                "user_url": b.user_url,
            },
            max_total_wait_seconds=settings.max_total_wait_seconds,
        )

    def budget_for(self, source: str) -> int:
        """Return the attempt budget for ``source`` (defaults to user_url's)."""
        return self.budgets.get(source, self.budgets.get("user_url", 2))

    def retrying(
        self,
        source: str,
        retry_after_hook: Callable[[], float | None] | None = None,
    ) -> Retrying:
        """Build a :class:`tenacity.Retrying` iterator for ``source``.

        Args:
            source: Source key whose budget applies (``github`` etc.).
            retry_after_hook: Optional callable returning seconds to wait
                per the last response's ``Retry-After`` header.  When
                provided, overrides exponential backoff for a single round.

        The iterator stops when EITHER the attempt budget or the wall-
        clock cap is exhausted.  ``reraise=True`` surfaces the underlying
        error instead of ``RetryError``.
        """
        attempts = self.budget_for(source)

        def _wait(retry_state):  # type: ignore[no-untyped-def]
            if retry_after_hook is not None:
                hinted = retry_after_hook()
                if hinted is not None:
                    return hinted
            # Fall back to exponential: base * 2^(attempt-1), capped at 60s.
            return wait_exponential(
                multiplier=self.base_wait_seconds, max=60.0
            )(retry_state)

        def _should_retry(exc: BaseException) -> bool:
            # Retry any httpx.HTTPError EXCEPT NonRetryableHTTPError.
            if isinstance(exc, NonRetryableHTTPError):
                return False
            return isinstance(exc, httpx.HTTPError)

        return Retrying(
            stop=stop_any(
                stop_after_attempt(attempts),
                stop_after_delay(self.max_total_wait_seconds),
            ),
            wait=_wait,
            retry=retry_if_exception(_should_retry),
            reraise=True,
        )


__all__ = [
    "NonRetryableHTTPError",
    "RetryPolicy",
    "is_retryable_status",
    "parse_retry_after",
]

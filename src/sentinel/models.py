"""Shared dataclasses for fetched-policy provenance — M4 + M5.

This module is a deliberately-small home for the two types that cross
the fetcher / pipeline / formatter boundary:

``PolicyOrigin`` (M5, § 8.4)
    Provenance record attached to every rendered policy.  Carries
    ``source_type``, ``source_spec``, ``sha256`` of the raw bytes,
    ``fetched_at``, and the ``cache_status`` annotation supplied by
    :class:`~sentinel.net.client.SentinelHTTPClient`.

``PolicyInput`` (M4, § 17 Amendment 4 M4)
    Normalised pipeline input — bytes + origin.  Replaces the legacy
    ``policy_text: str`` argument to :meth:`Pipeline.run` so every
    invocation carries its provenance forward to formatters.

I1 note from § 8.4: the ``sha256`` attests bytes-this-tool-acted-on,
**not** provenance of the upstream source.  Renderers must keep that
factual — never suggest the hash authenticates the upstream.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from datetime import datetime, timezone


@dataclass(frozen=True)
class PolicyOrigin:
    """Provenance record for a fetched policy — M5 per § 8.4.

    Attributes:
        source_type: Discriminator — one of ``"local"``, ``"url"``,
            ``"github"``, ``"aws-sample"``, ``"aws-managed"``,
            ``"cloudsplaining"``, ``"clipboard"``, ``"stdin"``.
        source_spec: Fetcher-specific locator — URL, ``owner/repo/path``,
            sample name, managed policy name, or ``"<stdin>"``.
        sha256: Hex digest of the raw policy bytes.  Bytes-we-acted-on,
            not upstream provenance.
        fetched_at: UTC timestamp of the fetch.
        cache_status: ``"HIT"`` / ``"MISS"`` / ``"N/A"``.  ``"N/A"`` is
            used when no HTTP cache was consulted (local file, clipboard,
            stdin).
    """

    source_type: str
    source_spec: str
    sha256: str
    fetched_at: datetime
    cache_status: str


@dataclass(frozen=True)
class PolicyInput:
    """Normalised policy-to-pipeline input — M4.

    The pipeline's ``run()`` method accepts this single object so that
    every downstream step (validate, analyze, rewrite, self-check,
    format) can access the raw bytes and the provenance record.
    """

    body_bytes: bytes
    origin: PolicyOrigin

    @property
    def text(self) -> str:
        """Decode ``body_bytes`` as UTF-8 for the JSON / YAML parser."""
        return self.body_bytes.decode("utf-8")

    @classmethod
    def from_text(cls, text: str, origin: PolicyOrigin) -> "PolicyInput":
        """Build a :class:`PolicyInput` from a decoded string."""
        return cls(body_bytes=text.encode("utf-8"), origin=origin)

    @classmethod
    def from_stdin_text(cls, text: str) -> "PolicyInput":
        """Back-compat helper for callers that only have a string.

        Emits a ``source_type="stdin"`` origin with the bytes' SHA-256
        and ``cache_status="N/A"``.  Used by the legacy
        :meth:`Pipeline.run_text` shim.
        """
        body = text.encode("utf-8")
        origin = PolicyOrigin(
            source_type="stdin",
            source_spec="<text>",
            sha256=hashlib.sha256(body).hexdigest(),
            fetched_at=datetime.now(timezone.utc),
            cache_status="N/A",
        )
        return cls(body_bytes=body, origin=origin)


__all__ = ["PolicyOrigin", "PolicyInput"]

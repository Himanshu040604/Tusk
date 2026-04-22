"""GitHub fetcher — resolves ``owner/repo/path`` specs to raw content.

Spec accepted forms:

* ``owner/repo/path/to/file.json`` (the branch defaults to ``main``).
* ``https://github.com/owner/repo/blob/<branch>/path/to/file.json``.
* ``https://raw.githubusercontent.com/owner/repo/<branch>/path`` (passed
  through without modification).

Network access uses :class:`SentinelHTTPClient` with ``source="github"``
so the per-source retry budget and 24 h TTL apply (§ 5.5).  When
``SENTINEL_GITHUB_TOKEN`` is present on :class:`Settings`, an
``Authorization: token <t>`` header is attached; otherwise a single
``[WARN]`` log fires (§ 8.6 — single fetches still work without a
token, but rate-limits are tight).
"""

from __future__ import annotations

from typing import TYPE_CHECKING
from urllib.parse import urlparse

import structlog

from .base import Fetcher, FetchResult, InvalidSpecError
from ._http_helpers import build_fetch_result

if TYPE_CHECKING:  # pragma: no cover
    from sentinel.config import Settings
    from sentinel.net.client import SentinelHTTPClient


_RAW_HOST = "raw.githubusercontent.com"
_DEFAULT_BRANCH = "main"


def _parse_spec(spec: str) -> tuple[str, str]:
    """Return ``(raw_url, canonical_spec)`` from any accepted form.

    The canonical_spec is what goes into :attr:`PolicyOrigin.source_spec`
    — a ``owner/repo@branch/path`` form stable across the three input
    shapes.  Makes cache analysis and log diffing tractable.
    """
    if spec.startswith(("http://", "https://")):
        parsed = urlparse(spec)
        if parsed.netloc == _RAW_HOST:
            parts = parsed.path.lstrip("/").split("/", 3)
            if len(parts) < 4:
                raise InvalidSpecError(f"malformed raw URL: {spec!r}")
            owner, repo, branch, path = parts
            return spec, f"{owner}/{repo}@{branch}/{path}"
        if parsed.netloc in ("github.com", "www.github.com"):
            parts = parsed.path.lstrip("/").split("/")
            # Expected: owner / repo / blob / branch / path...
            if len(parts) < 5 or parts[2] != "blob":
                raise InvalidSpecError(f"unsupported github.com URL: {spec!r}")
            owner, repo, _, branch, *rest = parts
            path = "/".join(rest)
            raw = f"https://{_RAW_HOST}/{owner}/{repo}/{branch}/{path}"
            return raw, f"{owner}/{repo}@{branch}/{path}"
        raise InvalidSpecError(f"not a GitHub URL: {spec!r}")

    # owner/repo/path... form.
    parts = spec.split("/", 2)
    if len(parts) < 3 or not all(parts[:2]):
        raise InvalidSpecError(
            f"expected 'owner/repo/path' or a github.com URL, got {spec!r}"
        )
    owner, repo, path = parts
    raw = f"https://{_RAW_HOST}/{owner}/{repo}/{_DEFAULT_BRANCH}/{path}"
    return raw, f"{owner}/{repo}@{_DEFAULT_BRANCH}/{path}"


class GitHubFetcher:
    """Fetches policy JSON blobs from GitHub via raw.githubusercontent.com."""

    def __init__(
        self,
        client: "SentinelHTTPClient",
        settings: "Settings",
    ) -> None:
        self._client = client
        self._settings = settings
        self._log = structlog.get_logger("sentinel.fetchers.github")
        self._warned_no_token = False

    def _auth_headers(self) -> dict[str, str]:
        token = self._settings.github_token
        if token is None:
            if not self._warned_no_token:
                self._log.warning(
                    "github_token_absent",
                    note=(
                        "SENTINEL_GITHUB_TOKEN not set; unauthenticated "
                        "raw.githubusercontent.com requests are allowed "
                        "but subject to tight anonymous rate limits."
                    ),
                )
                self._warned_no_token = True
            return {}
        return {"Authorization": f"token {token.get_secret_value()}"}

    def fetch(self, spec: str) -> FetchResult:
        raw_url, canonical = _parse_spec(spec)
        response = self._client.get(
            raw_url, source="github", headers=self._auth_headers(),
        )
        return build_fetch_result(
            response=response,
            source_type="github",
            source_spec=canonical,
        )


__all__ = ["GitHubFetcher", "Fetcher"]

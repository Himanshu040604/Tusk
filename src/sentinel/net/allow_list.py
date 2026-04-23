"""URL allow-list (M11).

Dot-prefix matching with IDNA normalization.  Defeats two attack shapes:

* **Suffix-confusion:** naïve ``host.endswith(entry)`` allows
  ``evilraw.githubusercontent.com`` under an allow-list of
  ``raw.githubusercontent.com`` — the match is a byte suffix, not a
  domain boundary.  The fix is ``host.endswith("." + entry)`` so a
  subdomain boundary dot is required, plus an explicit equality branch
  for exact matches.
* **Unicode homoglyphs:** ``раw.githubusercontent.com`` with Cyrillic
  ``а`` is visually indistinguishable from the Latin version.  IDNA
  encoding converts both to ASCII punycode, and the homoglyph version
  produces a different ASCII string — the match fails safely.

See prod_imp.md § 8.1.
"""

from __future__ import annotations

from urllib.parse import urlparse

import idna


class AllowList:
    """Dot-prefix + IDNA-normalized domain allow-list.

    Construction:
        >>> al = AllowList(["docs.aws.amazon.com", "github.com"])
        >>> al.is_allowed("https://github.com/x")        # True
        >>> al.is_allowed("https://api.github.com/x")    # True (subdomain)
        >>> al.is_allowed("https://evil-github.com/x")   # False (no dot boundary)
        >>> al.is_allowed("https://notgithub.com/x")     # False

    ``extend()`` supports the ``--allow-domain`` ephemeral CLI flag (§ 7.3):
    in-memory only, never persisted.
    """

    __slots__ = ("_entries",)

    def __init__(self, domains: list[str]) -> None:
        self._entries: frozenset[str] = frozenset(self._normalize(d) for d in domains if d)

    @staticmethod
    def _normalize(domain: str) -> str:
        """Lowercase, strip ``*.`` wildcard, strip trailing dot, IDNA-encode.

        Returns an empty string for malformed / non-encodable input — the
        caller's membership check will then fail safely.
        """
        raw = domain.strip().lower().lstrip("*.").rstrip(".")
        if not raw:
            return ""
        try:
            return idna.encode(raw).decode("ascii")
        except idna.IDNAError:
            return ""

    def is_allowed(self, url: str) -> bool:
        """Return True iff ``url``'s host matches an entry (exact or subdomain).

        Host is extracted via :func:`urllib.parse.urlparse`, lowercased,
        IDNA-normalized, and checked with exact-equality OR dot-boundary
        suffix match.  Malformed URLs, empty hosts, and IDNA-uncodable
        labels all return False.
        """
        parsed = urlparse(url)
        host_raw = (parsed.hostname or "").strip().lower().rstrip(".")
        if not host_raw:
            return False
        try:
            host = idna.encode(host_raw).decode("ascii")
        except idna.IDNAError:
            return False
        for entry in self._entries:
            if not entry:
                continue
            if host == entry or host.endswith("." + entry):
                return True
        return False

    def extend(self, domain: str) -> None:
        """Add ``domain`` to the in-memory allow-list (never persisted).

        Used by the ephemeral ``--allow-domain`` CLI flag per § 5.2 /
        § 7.3.  Silently skips empty / unencodable domains to keep CLI
        parsing simple; callers that need strict validation should
        pre-check with ``idna.encode()`` themselves.
        """
        normalized = self._normalize(domain)
        if normalized:
            self._entries = self._entries | {normalized}

    def __contains__(self, url: str) -> bool:
        return self.is_allowed(url)

    def __repr__(self) -> str:
        return f"AllowList({sorted(self._entries)!r})"


__all__ = ["AllowList"]

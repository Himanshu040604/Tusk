"""Typed intent specification for the validate/analyze/rewrite pipeline.

`IntentSpec` is the single source of truth for "what the user wants this
policy to do". It is parsed once at CLI entry from a natural-language
string (``--intent "read s3 deploy artifacts"``) and threaded through
the analyzer and rewriter so both pipelines share a consistent view.

Design note (Amendment 13): pre-v0.9.0, intent flowed as a raw string
into the rewriter and was re-parsed by ``_intent_based_expansion()``
without ever reaching ``_scope_resources()``. As a result, resource
scoping ignored intent entirely. IntentSpec consolidates parsing in one
place and exposes ``resource_hints`` for the rewriter to consume.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .analyzer import AccessLevel


_STOP_WORDS: frozenset[str] = frozenset(
    {
        "a", "an", "and", "the", "for", "to", "of", "in", "on", "with",
        "from", "by", "at", "as", "is", "be", "or", "only", "all", "any",
        "this", "that", "these", "those", "my", "our", "your",
    }
)

# Tokens treated as access verbs and excluded from resource_hints. Curated
# narrowly: only words that are essentially never used as resource nouns
# (so "deploy", "deployment", "permissions" deliberately stay as hints).
_PURE_ACCESS_VERBS: frozenset[str] = frozenset(
    {
        "read", "write", "list", "view", "get", "put", "modify", "update",
        "create", "delete", "manage", "grant", "tag", "fetch", "enumerate",
        "remove",
    }
)

_TOKEN_RE: re.Pattern[str] = re.compile(r"[A-Za-z][A-Za-z0-9-]*")


@dataclass(frozen=True)
class IntentSpec:
    """Parsed developer intent.

    Attributes:
        raw_intent: Original intent string (preserved for traceability and audit).
        services: AWS service prefixes extracted from the intent (e.g. ``{"s3"}``).
        access_levels: Access levels extracted from the intent.
        resource_hints: Lowercase content words that are neither service names nor
            access verbs - used by the rewriter to filter candidate ARNs.
    """

    raw_intent: str
    services: set[str] = field(default_factory=set)
    access_levels: set["AccessLevel"] = field(default_factory=set)
    resource_hints: list[str] = field(default_factory=list)

    @classmethod
    def empty(cls) -> "IntentSpec":
        """Return an empty IntentSpec for "no intent provided" cases."""
        return cls(raw_intent="", services=set(), access_levels=set(), resource_hints=[])

    def is_empty(self) -> bool:
        """True if the spec carries no actionable signal."""
        return not (self.services or self.access_levels or self.resource_hints)

    @classmethod
    def from_string(cls, intent: str) -> "IntentSpec":
        """Parse a natural-language intent string into an IntentSpec.

        Reuses ``IntentMapper`` for service + access-level extraction so the
        analyzer and rewriter agree on the same parse. ``resource_hints`` is
        populated by ``_extract_resource_hints`` (added separately).

        Args:
            intent: Natural-language intent (e.g. "read s3 deploy artifacts").

        Returns:
            IntentSpec with services and access_levels populated; empty if
            the intent string is blank.
        """
        if not intent or not intent.strip():
            return cls.empty()

        # Local import breaks the circular dep with the analyzer module.
        from .analyzer import IntentMapper

        mapper = IntentMapper(database=None)
        mapping = mapper.map_intent(intent)

        return cls(
            raw_intent=intent,
            services=set(mapping.services),
            access_levels=set(mapping.access_levels),
            resource_hints=[],
        )

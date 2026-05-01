"""Tests for the IntentSpec typed-intent dataclass."""

from __future__ import annotations

from sentinel.analyzer import AccessLevel
from sentinel.intent_spec import IntentSpec


class TestIntentSpecConstruction:
    """IntentSpec can be built directly and via from_string()."""

    def test_empty_intent_spec(self) -> None:
        spec = IntentSpec.empty()
        assert spec.raw_intent == ""
        assert spec.services == set()
        assert spec.access_levels == set()
        assert spec.resource_hints == []

    def test_direct_construction(self) -> None:
        spec = IntentSpec(
            raw_intent="read s3 deploy artifacts",
            services={"s3"},
            access_levels={AccessLevel.LIST, AccessLevel.READ},
            resource_hints=["deploy", "artifacts"],
        )
        assert spec.services == {"s3"}
        assert "deploy" in spec.resource_hints

    def test_is_empty(self) -> None:
        assert IntentSpec.empty().is_empty()
        spec = IntentSpec(
            raw_intent="x",
            services=set(),
            access_levels=set(),
            resource_hints=[],
        )
        assert spec.is_empty()
        spec_with_service = IntentSpec(
            raw_intent="x", services={"s3"}, access_levels=set(), resource_hints=[]
        )
        assert not spec_with_service.is_empty()

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


class TestIntentSpecFromString:
    """from_string() parses raw intent into typed fields."""

    def test_read_only_s3(self) -> None:
        spec = IntentSpec.from_string("read-only s3")
        assert spec.raw_intent == "read-only s3"
        assert "s3" in spec.services
        assert AccessLevel.READ in spec.access_levels

    def test_resource_hints_extracted(self) -> None:
        spec = IntentSpec.from_string("read s3 deploy artifacts")
        assert "deploy" in spec.resource_hints
        assert "artifacts" in spec.resource_hints
        assert "s3" not in spec.resource_hints
        assert "read" not in spec.resource_hints

    def test_empty_string(self) -> None:
        spec = IntentSpec.from_string("")
        assert spec.is_empty()

    def test_no_database_required(self) -> None:
        spec = IntentSpec.from_string("write to lambda for deployments")
        assert "lambda" in spec.services
        assert "deployments" in spec.resource_hints

    def test_from_string_accepts_none(self) -> None:
        """Issue 2: from_string(None) returns empty without TypeError.

        Type signature widened to ``str | None`` (Amendment 13 follow-up)
        so Optional callers (CLI sites that may pass ``args.intent``
        without guarding) get predictable empty spec rather than a
        TypeError surprise.
        """
        spec = IntentSpec.from_string(None)
        assert spec.is_empty()
        assert spec.raw_intent == ""

    def test_from_string_accepts_whitespace(self) -> None:
        """Issue 2: whitespace-only input maps to empty (same as None)."""
        spec = IntentSpec.from_string("   \t\n  ")
        assert spec.is_empty()


class TestIntentMappingIntegration:
    """IntentMapping carries an IntentSpec for downstream consumers."""

    def test_intent_mapping_has_intent_spec(self) -> None:
        from sentinel.analyzer import IntentMapper

        mapper = IntentMapper(database=None)
        mapping = mapper.map_intent("read s3 deploy")
        assert mapping.intent_spec is not None
        assert "s3" in mapping.intent_spec.services
        assert "deploy" in mapping.intent_spec.resource_hints
        assert mapping.intent_spec.raw_intent == "read s3 deploy"

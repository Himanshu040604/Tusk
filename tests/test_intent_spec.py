"""Tests for the IntentSpec typed-intent dataclass."""

from __future__ import annotations

import pytest

from sentinel.analyzer import AccessLevel
from sentinel.intent_spec import IntentSpec


class TestIntentSpecConstruction:
    """IntentSpec can be built directly and via from_string()."""

    def test_empty_intent_spec(self) -> None:
        spec = IntentSpec.empty()
        assert spec.raw_intent == ""
        # Issue 10 (Amendment 13 follow-up): containers are now immutable
        # (frozenset / tuple). frozenset() == set() is True so the
        # services/access_levels asserts still hold; tuple == list is False
        # so resource_hints needs () not [].
        assert spec.services == frozenset()
        assert spec.access_levels == frozenset()
        assert spec.resource_hints == ()

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

    def test_two_char_env_tokens_kept(self) -> None:
        """Issue 8: common 2-char env names (qa/ci/eu/us/dr) survive filtering.

        Pre-fix the ``len(tok) < 3`` filter silently dropped these — operator
        typing ``--intent "read s3 qa"`` got resource_hints=[] without any
        signal. Now the floor is single-char only.
        """
        for env in ("qa", "ci", "eu", "us", "dr"):
            spec = IntentSpec.from_string(f"read s3 {env}")
            assert env in spec.resource_hints, f"{env!r} should remain a hint"

    def test_single_char_dropped(self) -> None:
        """Single-char tokens still drop (noise floor — bare letters from regex)."""
        spec = IntentSpec.from_string("read s3 a b c xyz")
        assert "a" not in spec.resource_hints
        assert "b" not in spec.resource_hints
        assert "c" not in spec.resource_hints
        assert "xyz" in spec.resource_hints


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


class TestIntentSpecImmutability:
    """Issue 10: frozen=True must guarantee both reassignment AND in-place safety."""

    def test_services_cannot_be_mutated_in_place(self) -> None:
        """frozenset.add doesn't exist — in-place mutation impossible."""
        spec = IntentSpec.from_string("read s3 deploy")
        with pytest.raises(AttributeError):
            spec.services.add("ec2")  # type: ignore[attr-defined]

    def test_resource_hints_cannot_be_mutated_in_place(self) -> None:
        """tuple.append doesn't exist — in-place mutation impossible."""
        spec = IntentSpec.from_string("read s3 deploy")
        with pytest.raises(AttributeError):
            spec.resource_hints.append("artifacts")  # type: ignore[attr-defined]

    def test_attribute_reassignment_blocked(self) -> None:
        """frozen=True still blocks attribute rebinding."""
        spec = IntentSpec.from_string("read s3")
        with pytest.raises(Exception):  # FrozenInstanceError, subclass of AttributeError
            spec.services = frozenset({"ec2"})  # type: ignore[misc]

    def test_set_input_coerced_to_frozenset(self) -> None:
        """Backwards compat: callers may pass set() / list() literals."""
        spec = IntentSpec(
            raw_intent="x",
            services={"s3"},
            access_levels={AccessLevel.READ},
            resource_hints=["deploy"],
        )
        assert isinstance(spec.services, frozenset)
        assert isinstance(spec.access_levels, frozenset)
        assert isinstance(spec.resource_hints, tuple)
        assert spec.services == frozenset({"s3"})
        assert spec.resource_hints == ("deploy",)

    def test_string_input_rejected(self) -> None:
        """Issue N1 (Bundle E): bare str/bytes must raise TypeError.

        ``frozenset("s3")`` iterates the string per-character to
        ``frozenset({'s', '3'})``, silently corrupting the spec. Reject
        bare str/bytes so the failure is loud at construction time
        rather than later as a no-op service lookup.
        """
        with pytest.raises(TypeError, match="must be an iterable"):
            IntentSpec(raw_intent="x", services="s3")  # type: ignore[arg-type]
        with pytest.raises(TypeError, match="must be an iterable"):
            IntentSpec(raw_intent="x", resource_hints="deploy")  # type: ignore[arg-type]
        with pytest.raises(TypeError, match="must be an iterable"):
            IntentSpec(raw_intent="x", services=b"s3")  # type: ignore[arg-type]
        # Section A.2: complete the loop coverage. The __post_init__ guard
        # iterates ("services", "access_levels", "resource_hints") so all
        # three field paths must be exercised. Without this case, a future
        # regression that special-cases services/resource_hints but skips
        # access_levels would slip through.
        with pytest.raises(TypeError, match="must be an iterable"):
            IntentSpec(raw_intent="x", access_levels="READ")  # type: ignore[arg-type]

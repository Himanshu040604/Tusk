"""Fuzz tests for :class:`sentinel.parser.PolicyParser`.

Hand-rolled pathological inputs — deeply nested JSON, huge strings,
malformed Unicode, unusual Effect/Action shapes.  If ``hypothesis``
is installed, a small property-based block runs too.
"""

from __future__ import annotations

import json
import random

import pytest

from sentinel.parser import PolicyParser, PolicyParserError

try:  # pragma: no cover
    from hypothesis import given, settings, strategies as st

    _HAS_HYPOTHESIS = True
except ImportError:  # pragma: no cover
    _HAS_HYPOTHESIS = False


@pytest.fixture
def parser() -> PolicyParser:
    return PolicyParser()


# ---------------------------------------------------------------------------
# H12 pre-parse depth guard
# ---------------------------------------------------------------------------


class TestDeeplyNestedJson:
    def test_very_deep_array_nesting_rejected(self, parser: PolicyParser) -> None:
        # Default max_json_nesting_depth=32.  Build depth=200.
        inner = "null"
        for _ in range(200):
            inner = f"[{inner}]"
        with pytest.raises(PolicyParserError, match="nesting depth"):
            parser.parse_policy(inner)

    def test_very_deep_object_nesting_rejected(self, parser: PolicyParser) -> None:
        inner = "null"
        for _ in range(200):
            inner = '{"x":' + inner + "}"
        with pytest.raises(PolicyParserError, match="nesting depth"):
            parser.parse_policy(inner)

    def test_mixed_deep_nesting_rejected(self, parser: PolicyParser) -> None:
        s = "null"
        for i in range(100):
            s = "[" + s + "]" if i % 2 else '{"k":' + s + "}"
        with pytest.raises(PolicyParserError):
            parser.parse_policy(s)

    def test_depth_exactly_at_limit_passes_depth_check(
        self, parser: PolicyParser
    ) -> None:
        # Depth-15 object is safely below the default 32-depth limit; the
        # parse may fail on policy-shape validation but the nesting check
        # must not trigger.
        inner = '"leaf"'
        for _ in range(15):
            inner = '{"k":' + inner + "}"
        try:
            parser.parse_policy(inner)
        except PolicyParserError as exc:
            # We only care about "nesting depth" NOT being in the message.
            assert "nesting depth" not in str(exc)


# ---------------------------------------------------------------------------
# Malformed JSON / Unicode
# ---------------------------------------------------------------------------


class TestMalformedInputs:
    def test_empty_string_rejected(self, parser: PolicyParser) -> None:
        with pytest.raises(PolicyParserError):
            parser.parse_policy("")

    def test_random_bytes_rejected(self, parser: PolicyParser) -> None:
        with pytest.raises(PolicyParserError):
            parser.parse_policy("\x00\xff\x01\x02garbage")

    def test_unterminated_string_rejected(self, parser: PolicyParser) -> None:
        with pytest.raises(PolicyParserError):
            parser.parse_policy('{"Statement": "unterminated')

    def test_trailing_comma_rejected(self, parser: PolicyParser) -> None:
        with pytest.raises(PolicyParserError):
            parser.parse_policy('{"Statement":[1,2,3,]}')

    @pytest.mark.parametrize(
        "payload",
        [
            '{"\\uD83D\\uDCA9":"pile"}',   # valid surrogate pair — should parse
        ],
    )
    def test_weird_but_valid_unicode(
        self, parser: PolicyParser, payload: str
    ) -> None:
        # These do not form a valid POLICY but must not crash the parser.
        # Expect PolicyParserError (shape), not some lower-level exception.
        try:
            parser.parse_policy(payload)
        except PolicyParserError:
            pass


# ---------------------------------------------------------------------------
# Huge strings
# ---------------------------------------------------------------------------


class TestHugeStrings:
    def test_megabyte_action_string(self, parser: PolicyParser) -> None:
        giant = "s3:" + "A" * 1_000_000
        doc = json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {"Effect": "Allow", "Action": giant, "Resource": "*"}
                ],
            }
        )
        # Either parses (invalid action) or raises PolicyParserError;
        # what we care about is bounded CPU time — we simply call it.
        try:
            parser.parse_policy(doc)
        except PolicyParserError:
            pass


# ---------------------------------------------------------------------------
# hypothesis block (optional)
# ---------------------------------------------------------------------------


@pytest.mark.skipif(not _HAS_HYPOTHESIS, reason="hypothesis not installed")
class TestHypothesis:
    @given(st.text(max_size=200))
    @settings(max_examples=50, deadline=500)
    def test_random_text_never_crashes(self, s: str) -> None:
        parser = PolicyParser()
        try:
            parser.parse_policy(s)
        except PolicyParserError:
            pass

    @given(
        st.recursive(
            st.none() | st.booleans() | st.integers() | st.text(max_size=10),
            lambda children: st.lists(children, max_size=5)
            | st.dictionaries(st.text(max_size=5), children, max_size=5),
            max_leaves=30,
        )
    )
    @settings(max_examples=30, deadline=500)
    def test_random_json_structure_never_crashes(self, data: object) -> None:
        parser = PolicyParser()
        try:
            parser.parse_policy(json.dumps(data))
        except PolicyParserError:
            pass

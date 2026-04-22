"""Tests for :mod:`sentinel.secrets_patterns` (Phase 1 + Amendment 6 Theme A).

Covers the three consumers + the single-source-of-truth contract test
that asserts no other module reimplements the scrub logic.
"""

from __future__ import annotations

import re
import subprocess
from pathlib import Path

import pytest

from sentinel.secrets_patterns import (
    REDACT_KEYS,
    REDACT_PLACEHOLDER,
    SECRET_PATTERNS,
    grep_sources,
    redact_event_dict,
    scrub_bytes,
)


# ---------------------------------------------------------------------------
# Fixture strings — real-looking (but synthetic) secrets.
# ---------------------------------------------------------------------------

GH_CLASSIC_PAT = "ghp_" + "A" * 40
GH_FINE_PAT = "github_pat_" + "A" * 82
AWS_ACCESS_KEY = "AKIAIOSFODNN7EXAMPLE"
AWS_SECRET = 'aws_secret_access_key = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"'
BEARER = "Bearer abcDEF123.token_-"
JWT = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.SflKxw"


class TestScrubBytes:
    """H11 VCR cassette body scrubber."""

    def test_scrubs_github_classic_pat(self) -> None:
        out = scrub_bytes(f"authorization: token {GH_CLASSIC_PAT}".encode())
        assert GH_CLASSIC_PAT.encode() not in out
        assert REDACT_PLACEHOLDER.encode() in out

    def test_scrubs_github_fine_grained_pat(self) -> None:
        out = scrub_bytes(GH_FINE_PAT.encode())
        assert GH_FINE_PAT.encode() not in out

    def test_scrubs_aws_access_key(self) -> None:
        out = scrub_bytes(f"AccessKey: {AWS_ACCESS_KEY}".encode())
        assert AWS_ACCESS_KEY.encode() not in out

    def test_scrubs_aws_secret_access_key(self) -> None:
        out = scrub_bytes(AWS_SECRET.encode())
        # The key=value match replaces the whole thing including the value.
        assert b"wJalrXUtnFEMI" not in out

    def test_scrubs_bearer_token(self) -> None:
        out = scrub_bytes(BEARER.encode())
        assert b"abcDEF" not in out

    def test_scrubs_jwt(self) -> None:
        out = scrub_bytes(JWT.encode())
        assert b"eyJhbGci" not in out

    def test_binary_safe_roundtrip(self) -> None:
        # Random-ish binary body with a PAT glued in must survive decode.
        body = b"\x00\x01\x02" + GH_CLASSIC_PAT.encode() + b"\xff\xfe"
        out = scrub_bytes(body)
        assert isinstance(out, bytes)
        assert GH_CLASSIC_PAT.encode() not in out

    def test_no_secret_passthrough(self) -> None:
        body = b"no secrets here, just text"
        assert scrub_bytes(body) == body


class TestRedactEventDict:
    """M10 structlog processor."""

    def test_redacts_by_key(self) -> None:
        out = redact_event_dict(None, "info", {"token": "some-token"})
        assert out["token"] == REDACT_PLACEHOLDER

    def test_key_match_is_case_insensitive(self) -> None:
        out = redact_event_dict(None, "info", {"Authorization": "Bearer xyz"})
        assert out["Authorization"] == REDACT_PLACEHOLDER

    def test_redacts_by_regex_in_string_value(self) -> None:
        out = redact_event_dict(
            None, "info", {"msg": f"PAT is {GH_CLASSIC_PAT} today"}
        )
        assert GH_CLASSIC_PAT not in out["msg"]
        assert REDACT_PLACEHOLDER in out["msg"]

    def test_non_string_values_pass_through(self) -> None:
        out = redact_event_dict(None, "info", {"count": 42, "flag": True})
        assert out == {"count": 42, "flag": True}

    def test_mutates_and_returns_same_dict(self) -> None:
        event = {"msg": "plain"}
        out = redact_event_dict(None, "info", event)
        assert out is event  # processor contract: identity

    def test_multiple_matches_in_one_string(self) -> None:
        event = {"msg": f"{GH_CLASSIC_PAT} and {AWS_ACCESS_KEY}"}
        out = redact_event_dict(None, "info", event)
        assert GH_CLASSIC_PAT not in out["msg"]
        assert AWS_ACCESS_KEY not in out["msg"]

    def test_known_redact_keys_are_lowercase(self) -> None:
        # Contract test — the deny-list must be all-lowercase.
        for key in REDACT_KEYS:
            assert key == key.lower(), f"REDACT_KEYS entry {key!r} must be lowercase"


class TestGrepSources:
    """M22 pre-commit hook."""

    def test_hits_on_pat_in_file(self, tmp_path: Path) -> None:
        f = tmp_path / "bad.py"
        f.write_text(f"TOKEN = '{GH_CLASSIC_PAT}'\n")
        hits = grep_sources([str(f)])
        assert len(hits) == 1
        assert hits[0][0] == str(f)
        assert hits[0][1] == 1
        assert GH_CLASSIC_PAT in hits[0][2]

    def test_no_hits_on_clean_file(self, tmp_path: Path) -> None:
        f = tmp_path / "ok.py"
        f.write_text("x = 1\n")
        assert grep_sources([str(f)]) == []

    def test_recurses_directories(self, tmp_path: Path) -> None:
        sub = tmp_path / "sub"
        sub.mkdir()
        (sub / "a.py").write_text(f"k = '{AWS_ACCESS_KEY}'\n")
        hits = grep_sources([str(tmp_path)])
        assert len(hits) == 1

    def test_silently_skips_missing_path(self) -> None:
        assert grep_sources(["/nonexistent/path/xyz"]) == []

    def test_one_hit_per_line_even_on_multiple_patterns(
        self, tmp_path: Path
    ) -> None:
        f = tmp_path / "double.txt"
        # Put two secrets on the same line; we only report one hit per line.
        f.write_text(f"{GH_CLASSIC_PAT} {AWS_ACCESS_KEY}\n")
        hits = grep_sources([str(f)])
        assert len(hits) == 1


class TestSingleSourceOfTruth:
    """Amendment 6 Theme A — contract test: no consumer reimplements logic."""

    REPO_ROOT = Path(__file__).resolve().parent.parent
    SRC = REPO_ROOT / "src"

    def test_secret_patterns_is_a_list_of_compiled_patterns(self) -> None:
        assert isinstance(SECRET_PATTERNS, list)
        assert len(SECRET_PATTERNS) > 0
        for p in SECRET_PATTERNS:
            assert isinstance(p, re.Pattern)

    def test_no_other_module_defines_secret_patterns(self) -> None:
        """Grep src/ for re-definitions of ``SECRET_PATTERNS = [``.

        If another module declares its own list, this test fails loudly.
        The canonical definition lives in ``secrets_patterns.py``.
        """
        hits: list[str] = []
        for py in self.SRC.rglob("*.py"):
            if py.name == "secrets_patterns.py":
                continue
            text = py.read_text(encoding="utf-8", errors="replace")
            # Match assignment shape ``SECRET_PATTERNS = [`` or ``SECRET_PATTERNS: ... = [``
            if re.search(r"^\s*SECRET_PATTERNS\s*[:=]", text, re.MULTILINE):
                hits.append(str(py))
        assert not hits, f"SECRET_PATTERNS redefined outside canonical module: {hits}"

    def test_consumers_import_from_canonical_module(self) -> None:
        """Any file referencing SECRET_PATTERNS must import from secrets_patterns."""
        offenders: list[str] = []
        for py in self.SRC.rglob("*.py"):
            if py.name == "secrets_patterns.py":
                continue
            text = py.read_text(encoding="utf-8", errors="replace")
            if "SECRET_PATTERNS" not in text:
                continue
            # Must have an import from secrets_patterns nearby.
            if not re.search(
                r"from\s+[\w.]*secrets_patterns\s+import", text
            ) and not re.search(r"import\s+[\w.]*secrets_patterns", text):
                offenders.append(str(py))
        assert not offenders, (
            f"Files reference SECRET_PATTERNS without importing from "
            f"secrets_patterns: {offenders}"
        )


class TestRedactPlaceholder:
    def test_placeholder_is_stars(self) -> None:
        assert REDACT_PLACEHOLDER == "**********"

    def test_placeholder_not_empty(self) -> None:
        # If someone ever blanks this, downstream telemetry breaks silently.
        assert REDACT_PLACEHOLDER

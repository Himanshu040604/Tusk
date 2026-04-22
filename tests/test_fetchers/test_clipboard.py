"""Tests for :class:`fetchers.clipboard.ClipboardFetcher`.

Uses monkeypatched ``pyperclip`` so tests never touch a real clipboard
backend (headless CI hosts have no clipboard service).
"""

from __future__ import annotations

import pytest

from fetchers.base import ClipboardUnavailable, PolicyNotFoundError
from fetchers.clipboard import ClipboardFetcher


class TestClipboardFetcher:
    def test_reads_clipboard_text(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        import pyperclip

        payload = '{"Version":"2012-10-17","Statement":[]}'
        monkeypatch.setattr(pyperclip, "paste", lambda: payload)
        result = ClipboardFetcher().fetch("")
        assert result.body == payload.encode()
        assert result.origin.source_type == "clipboard"
        assert result.cache_status == "N/A"

    def test_empty_clipboard_raises(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        import pyperclip

        monkeypatch.setattr(pyperclip, "paste", lambda: "")
        with pytest.raises(PolicyNotFoundError):
            ClipboardFetcher().fetch("")

    def test_pyperclip_exception_maps_to_clipboard_unavailable(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        import pyperclip

        def boom() -> str:
            raise pyperclip.PyperclipException("no backend")

        monkeypatch.setattr(pyperclip, "paste", boom)
        with pytest.raises(ClipboardUnavailable):
            ClipboardFetcher().fetch("")

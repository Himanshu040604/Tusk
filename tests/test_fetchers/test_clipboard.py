"""Tests for :class:`fetchers.clipboard.ClipboardFetcher`.

Uses monkeypatched ``pyperclip`` so tests never touch a real clipboard
backend (headless CI hosts have no clipboard service).
"""

from __future__ import annotations

import pytest

from fetchers.base import ClipboardUnavailable
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

    def test_empty_clipboard_raises_clipboard_unavailable(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """An empty clipboard raises ClipboardUnavailable (not PolicyNotFoundError)."""
        import pyperclip

        monkeypatch.setattr(pyperclip, "paste", lambda: "")
        # Force the WSL fallback to also return empty.
        monkeypatch.setattr(
            "fetchers.clipboard._is_wsl", lambda: False
        )
        with pytest.raises(ClipboardUnavailable, match="empty"):
            ClipboardFetcher().fetch("")

    def test_pyperclip_exception_with_no_wsl_raises_unavailable(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """When pyperclip raises AND WSL fallback is unavailable, we raise ClipboardUnavailable."""
        import pyperclip

        def boom() -> str:
            raise pyperclip.PyperclipException("no backend")

        monkeypatch.setattr(pyperclip, "paste", boom)
        # Disable the WSL fallback path so we can observe the "no backend" mapping.
        monkeypatch.setattr(
            "fetchers.clipboard._is_wsl", lambda: False
        )
        with pytest.raises(ClipboardUnavailable, match="backend unavailable"):
            ClipboardFetcher().fetch("")

"""Clipboard fetcher — grabs policy JSON from the host clipboard.

Backend order:

1. :mod:`pyperclip` — preferred; works on macOS, Linux (xclip/xsel),
   and Windows out of the box.
2. WSL fallback — on WSL detected via ``/proc/version`` containing
   ``microsoft`` or ``WSL``, shell out to PowerShell's ``Get-Clipboard``
   via ``powershell.exe``.

Raises :class:`ClipboardUnavailable` with a remediation hint when no
backend succeeds (e.g., a headless Linux host with no xclip / xsel
installed).  The message is intentionally actionable — the user gets
the exact packages to install.

Spec: ignored — the fetcher takes no argument beyond the clipboard
contents itself.  Callers pass ``""`` (the CLI does this).
"""

from __future__ import annotations

import subprocess
from pathlib import Path

import structlog

from .base import ClipboardUnavailable, Fetcher, FetchResult
from ._http_helpers import build_local_origin


_WSL_MARKERS = ("microsoft", "wsl")


def _is_wsl() -> bool:
    """Detect WSL via ``/proc/version``.

    Linux hosts without ``/proc/version`` (unusual) or non-Linux
    platforms simply get ``False`` — they never enter the WSL path.
    """
    try:
        content = Path("/proc/version").read_text(encoding="utf-8", errors="replace")
    except OSError:
        return False
    lower = content.lower()
    return any(marker in lower for marker in _WSL_MARKERS)


def _wsl_paste() -> str:
    """Invoke PowerShell via ``powershell.exe`` to read the clipboard.

    Returns the text.  ``subprocess.CalledProcessError`` or
    ``FileNotFoundError`` bubble out so the caller can translate them
    to :class:`ClipboardUnavailable`.
    """
    result = subprocess.check_output(
        ["powershell.exe", "-NoProfile", "-Command", "Get-Clipboard"],
        text=True,
    )
    # PowerShell's Get-Clipboard appends a trailing CRLF on Windows.
    return result.rstrip("\r\n")


class ClipboardFetcher:
    """Reads a policy JSON blob from the host clipboard."""

    def __init__(self) -> None:
        self._log = structlog.get_logger("sentinel.fetchers.clipboard")

    def fetch(self, spec: str) -> FetchResult:  # noqa: ARG002 — spec unused
        text = self._try_pyperclip()
        if text is None and _is_wsl():
            text = self._try_wsl()

        if text is None:
            raise ClipboardUnavailable(
                "Clipboard backend unavailable. Install one of: "
                "`xclip`, `xsel` (Linux); `wl-clipboard` (Wayland); "
                "on WSL ensure `powershell.exe` is on PATH."
            )

        if not text.strip():
            raise ClipboardUnavailable(
                "Clipboard is empty — copy a policy JSON first."
            )

        body = text.encode("utf-8")
        origin = build_local_origin(
            source_type="clipboard",
            source_spec="<clipboard>",
            body=body,
        )
        return FetchResult(
            body=body, headers={}, cache_status="N/A", origin=origin,
        )

    def _try_pyperclip(self) -> str | None:
        try:
            import pyperclip  # Lazy: optional on headless CI.
        except ImportError:
            return None
        try:
            return pyperclip.paste()
        except pyperclip.PyperclipException as exc:  # type: ignore[attr-defined]
            self._log.warning("pyperclip_failed", error=str(exc))
            return None

    def _try_wsl(self) -> str | None:
        try:
            return _wsl_paste()
        except (subprocess.CalledProcessError, FileNotFoundError, OSError) as exc:
            self._log.warning("wsl_clipboard_failed", error=str(exc))
            return None


__all__ = ["ClipboardFetcher", "Fetcher"]

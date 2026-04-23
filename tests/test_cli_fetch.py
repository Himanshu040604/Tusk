"""Tests for :mod:`sentinel.cli_fetch` CLI-boundary concerns.

Phase 8 (v0.8.0) regression: Issue 6 — ``httpx.InvalidURL`` must be
translated into an actionable operator message at the CLI boundary
rather than bubbling up as a raw traceback.
"""

from __future__ import annotations

from argparse import Namespace
from unittest.mock import patch

import httpx
import pytest

from sentinel.cli_fetch import cmd_fetch
from sentinel.exit_codes import EXIT_INVALID_ARGS


@pytest.fixture
def _base_fetch_args(tmp_path) -> Namespace:
    """Namespace mimicking ``sentinel fetch --url <url>`` minimum surface.

    Every argparse-added attribute that ``cmd_fetch`` may inspect needs a
    default so ``getattr(args, ...)`` doesn't raise inside the handler.
    """
    return Namespace(
        command="fetch",
        database=None,
        inventory=None,
        output_format="text",
        output=None,
        url=None,
        github=None,
        aws_sample=None,
        aws_managed=None,
        cloudsplaining=None,
        from_clipboard=False,
        alert_on_new=False,
        intent=None,
        account_id=None,
        region=None,
    )


def test_cmd_fetch_malformed_url_actionable(
    _base_fetch_args: Namespace,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Issue 6: URLs with embedded newlines produce an actionable message.

    The test patches ``_dispatch_fetch`` to raise ``httpx.InvalidURL`` with
    the message httpx would actually emit for a URL containing a newline.
    We assert:

    1. Return code is ``EXIT_INVALID_ARGS`` (not EXIT_IO_ERROR).
    2. stderr contains the guidance substring "malformed URL".
    3. stderr mentions "newlines" so the operator knows what to fix.
    4. stderr does NOT contain "Traceback" — the exception was caught.
    """
    args = _base_fetch_args
    args.url = "https://example.com/\npolicy.json"

    with patch(
        "sentinel.cli_fetch._dispatch_fetch",
        side_effect=httpx.InvalidURL(
            "Invalid non-printable ASCII character in URL, '\\n' at position 19"
        ),
    ):
        rc = cmd_fetch(args)

    captured = capsys.readouterr()
    assert rc == EXIT_INVALID_ARGS
    assert "malformed URL" in captured.err
    assert "newlines" in captured.err
    assert "Traceback" not in captured.err

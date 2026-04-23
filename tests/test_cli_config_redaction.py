"""L7 regression test (Amendment 5).

Running ``uv run sentinel config show`` with
``SENTINEL_GITHUB_TOKEN=ghp_*`` set in the environment MUST NOT print
the raw token anywhere in stdout or stderr.  The ``SecretStr`` wrapper
on :attr:`Settings.github_token` renders as ``**********`` when the
config is dumped — this test asserts the wrapper is plumbed through
every rendering path (JSON + human).
"""

from __future__ import annotations

import os
import subprocess
import sys

import pytest

FAKE_TOKEN = "ghp_fake_0123456789abcdef0123456789abcdef"


def _run_config_show(
    fmt: str | None = None,
) -> subprocess.CompletedProcess:
    env = os.environ.copy()
    env["SENTINEL_GITHUB_TOKEN"] = FAKE_TOKEN
    # Ensure ephemeral env-forbidden keys are NOT set.
    env.pop("SENTINEL_INSECURE", None)
    env.pop("SENTINEL_ALLOW_DOMAIN", None)

    cmd = [sys.executable, "-m", "sentinel", "config", "show"]
    if fmt:
        cmd.extend(["--format", fmt])
    return subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        env=env,
        timeout=30,
    )


class TestConfigShowRedaction:
    def test_human_format_does_not_leak_token(self) -> None:
        result = _run_config_show()
        # Even if the command exits non-zero, the token must not appear.
        combined = result.stdout + result.stderr
        assert FAKE_TOKEN not in combined, (
            f"raw token leaked in `config show` output!\n\n{combined}"
        )

    def test_json_format_does_not_leak_token(self) -> None:
        result = _run_config_show(fmt="json")
        combined = result.stdout + result.stderr
        assert FAKE_TOKEN not in combined, f"raw token leaked in JSON `config show`!\n\n{combined}"

    def test_redaction_marker_present(self) -> None:
        """At least one of the expected redaction markers must be emitted.

        If neither ``**********`` nor ``<redacted>`` appears, the
        ``github_token`` field was silently dropped rather than redacted
        — also a regression.
        """
        result = _run_config_show()
        out = result.stdout + result.stderr
        # Accept any of the conventional placeholder strings.
        markers = ["**********", "<redacted>", "SecretStr"]
        assert any(m in out for m in markers), (
            f"no redaction marker found in config show output: {out!r}"
        )

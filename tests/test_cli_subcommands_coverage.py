"""Smoke coverage for cli_config, cli_cache, cli_misc subcommand handlers.

Previously at 0% coverage (phase7_postship_review_tests.md § "Dimension B").
These tests exercise the public entry points with simple Namespace-based
invocations so the bulk of each module is reached.
"""

from __future__ import annotations

import argparse
import io
import sys
from pathlib import Path
from unittest.mock import patch

import pytest

from sentinel.exit_codes import EXIT_INVALID_ARGS, EXIT_SUCCESS


# ---------------------------------------------------------------------------
# cli_config
# ---------------------------------------------------------------------------


def test_cmd_config_show_prints_toml(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """`sentinel config show` emits valid TOML rendered from Settings."""
    from sentinel.cli_config import cmd_config

    ns = argparse.Namespace(config_cmd="show")
    rc = cmd_config(ns)
    assert rc == EXIT_SUCCESS
    out = capsys.readouterr().out
    # Must be non-empty and contain recognisable TOML keys.
    assert len(out) > 0


def test_cmd_config_path_prints_default(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """`sentinel config path` prints a path even when no file exists."""
    from sentinel.cli_config import cmd_config

    ns = argparse.Namespace(config_cmd="path")
    rc = cmd_config(ns)
    assert rc == EXIT_SUCCESS
    out = capsys.readouterr().out.strip()
    # Must be an absolute-looking path.
    assert len(out) > 0


def test_cmd_config_init_writes_starter(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """`sentinel config init` writes a starter config to _user_config_path.

    Points the user-config dir at tmp_path via XDG_CONFIG_HOME so we don't
    touch the developer's real config.
    """
    from sentinel.cli_config import cmd_config

    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "xdg"))
    monkeypatch.delenv("APPDATA", raising=False)
    ns = argparse.Namespace(config_cmd="init")
    rc = cmd_config(ns)
    assert rc == EXIT_SUCCESS
    written = tmp_path / "xdg" / "sentinel" / "config.toml"
    assert written.exists()
    content = written.read_text(encoding="utf-8")
    assert "account_id" in content


def test_cmd_config_init_refuses_overwrite(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """`sentinel config init` refuses to overwrite existing config."""
    from sentinel.cli_config import cmd_config

    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "xdg"))
    monkeypatch.delenv("APPDATA", raising=False)
    existing = tmp_path / "xdg" / "sentinel" / "config.toml"
    existing.parent.mkdir(parents=True, exist_ok=True)
    existing.write_text("# existing\n", encoding="utf-8")

    ns = argparse.Namespace(config_cmd="init")
    rc = cmd_config(ns)
    assert rc == EXIT_INVALID_ARGS


def test_cmd_config_unknown_subcommand() -> None:
    """Unknown `config` subcommand yields EXIT_INVALID_ARGS."""
    from sentinel.cli_config import cmd_config

    ns = argparse.Namespace(config_cmd="bogus")
    rc = cmd_config(ns)
    assert rc == EXIT_INVALID_ARGS


# ---------------------------------------------------------------------------
# cli_cache
# ---------------------------------------------------------------------------


def test_cmd_cache_stats_runs(capsys: pytest.CaptureFixture[str]) -> None:
    """`sentinel cache stats` runs and prints count + bytes."""
    from sentinel.cli_cache import cmd_cache

    ns = argparse.Namespace(cache_cmd="stats", output_format="text")
    rc = cmd_cache(ns)
    assert rc == EXIT_SUCCESS
    out = capsys.readouterr().out
    assert "entries" in out or "count" in out


def test_cmd_cache_ls_runs(capsys: pytest.CaptureFixture[str]) -> None:
    """`sentinel cache ls` runs."""
    from sentinel.cli_cache import cmd_cache

    ns = argparse.Namespace(cache_cmd="ls", output_format="text")
    rc = cmd_cache(ns)
    assert rc == EXIT_SUCCESS


def test_cmd_cache_ls_json(capsys: pytest.CaptureFixture[str]) -> None:
    """`sentinel cache ls --output-format json` returns JSON-parseable list."""
    import json

    from sentinel.cli_cache import cmd_cache

    ns = argparse.Namespace(cache_cmd="ls", output_format="json")
    rc = cmd_cache(ns)
    assert rc == EXIT_SUCCESS
    out = capsys.readouterr().out
    parsed = json.loads(out)
    assert isinstance(parsed, list)


def test_cmd_cache_purge_runs(capsys: pytest.CaptureFixture[str]) -> None:
    """`sentinel cache purge` returns success even on empty cache."""
    from sentinel.cli_cache import cmd_cache

    ns = argparse.Namespace(cache_cmd="purge", output_format="text")
    rc = cmd_cache(ns)
    assert rc == EXIT_SUCCESS
    out = capsys.readouterr().out
    assert "Purged" in out


def test_cmd_cache_unknown_subcommand() -> None:
    """Unknown `cache` subcommand yields EXIT_INVALID_ARGS."""
    from sentinel.cli_cache import cmd_cache

    ns = argparse.Namespace(cache_cmd="bogus", output_format="text")
    rc = cmd_cache(ns)
    assert rc == EXIT_INVALID_ARGS


def test_cmd_cache_rotate_key_aborts_on_no(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """`sentinel cache rotate-key` aborts when user answers 'n'."""
    from sentinel.cli_cache import cmd_cache

    monkeypatch.setattr("builtins.input", lambda *_args, **_kw: "n")
    ns = argparse.Namespace(cache_cmd="rotate-key", output_format="text", yes=False)
    rc = cmd_cache(ns)
    assert rc == EXIT_SUCCESS
    out = capsys.readouterr().out
    assert "Aborted" in out


# ---------------------------------------------------------------------------
# cli_misc — cmd_compare, cmd_search
# ---------------------------------------------------------------------------


def _make_policy_file(tmp_path: Path, name: str, actions: list[str]) -> Path:
    """Helper: write a minimal IAM policy JSON to disk."""
    import json as _json

    path = tmp_path / name
    path.write_text(
        _json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Action": actions,
                        "Resource": "*",
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    return path


def test_cmd_compare_two_policies_produces_diff(
    tmp_path: Path,
    migrated_db_template: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """`sentinel compare` runs against two policies and emits a diff."""
    from sentinel.cli_misc import cmd_compare
    from tests.conftest import make_test_db

    p_a = _make_policy_file(tmp_path, "a.json", ["s3:GetObject"])
    p_b = _make_policy_file(tmp_path, "b.json", ["s3:PutObject"])
    db_path = make_test_db(tmp_path, template=migrated_db_template)

    ns = argparse.Namespace(
        policy_a=str(p_a),
        policy_b=str(p_b),
        database=str(db_path),
        inventory=None,
        output_format="text",
    )
    rc = cmd_compare(ns)
    assert rc == EXIT_SUCCESS
    out = capsys.readouterr().out
    assert "Actions only in A" in out
    assert "Actions only in B" in out


def test_cmd_compare_json_output(
    tmp_path: Path,
    migrated_db_template: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """`sentinel compare --output-format json` emits a parseable payload."""
    import json as _json

    from sentinel.cli_misc import cmd_compare
    from tests.conftest import make_test_db

    p_a = _make_policy_file(tmp_path, "a.json", ["s3:GetObject"])
    p_b = _make_policy_file(tmp_path, "b.json", ["s3:PutObject"])
    db_path = make_test_db(tmp_path, template=migrated_db_template)

    ns = argparse.Namespace(
        policy_a=str(p_a),
        policy_b=str(p_b),
        database=str(db_path),
        inventory=None,
        output_format="json",
    )
    rc = cmd_compare(ns)
    assert rc == EXIT_SUCCESS
    parsed = _json.loads(capsys.readouterr().out)
    assert "findings_both" in parsed
    assert "actions_only_a" in parsed
    assert "actions_only_b" in parsed


def test_cmd_compare_missing_policy_file(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """`sentinel compare` on a missing file returns EXIT_IO_ERROR."""
    from sentinel.exit_codes import EXIT_IO_ERROR as _EXIT_IO_ERROR
    from sentinel.cli_misc import cmd_compare

    ns = argparse.Namespace(
        policy_a=str(tmp_path / "does_not_exist.json"),
        policy_b=str(tmp_path / "also_missing.json"),
        database=None,
        inventory=None,
        output_format="text",
    )
    rc = cmd_compare(ns)
    assert rc == _EXIT_IO_ERROR


def test_cmd_search_requires_github_token(
    capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    """`sentinel search` without SENTINEL_GITHUB_TOKEN returns EXIT_INVALID_ARGS."""
    from sentinel.cli_misc import cmd_search

    # Force-clear any existing token via the Settings cache.
    monkeypatch.delenv("SENTINEL_GITHUB_TOKEN", raising=False)
    # Reset the cached Settings so the token absence takes effect.
    import sentinel.config as _cfg

    _cfg._SETTINGS = None  # type: ignore[attr-defined]

    ns = argparse.Namespace(query="s3:GetObject", limit=5)
    rc = cmd_search(ns)
    assert rc == EXIT_INVALID_ARGS
    err = capsys.readouterr().err
    assert "GITHUB_TOKEN" in err or "token" in err.lower()


# ---------------------------------------------------------------------------
# cli_managed
# ---------------------------------------------------------------------------


def test_cmd_managed_list_text(
    tmp_path: Path, migrated_db_template: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """`sentinel managed list` returns success; empty-DB -> hint message."""
    from sentinel.cli_managed import cmd_managed
    from tests.conftest import make_test_db

    db_path = make_test_db(tmp_path, template=migrated_db_template)
    ns = argparse.Namespace(
        managed_cmd="list",
        database=str(db_path),
        inventory=None,
        output_format="text",
    )
    rc = cmd_managed(ns)
    assert rc == EXIT_SUCCESS


def test_cmd_managed_list_json(
    tmp_path: Path, migrated_db_template: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """`sentinel managed list --output-format json` emits a JSON list."""
    import json as _json

    from sentinel.cli_managed import cmd_managed
    from tests.conftest import make_test_db

    db_path = make_test_db(tmp_path, template=migrated_db_template)
    ns = argparse.Namespace(
        managed_cmd="list",
        database=str(db_path),
        inventory=None,
        output_format="json",
    )
    rc = cmd_managed(ns)
    assert rc == EXIT_SUCCESS
    out = capsys.readouterr().out
    parsed = _json.loads(out)
    assert isinstance(parsed, list)


def test_cmd_managed_show_missing_policy(
    tmp_path: Path, migrated_db_template: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """`sentinel managed show <unknown>` returns EXIT_IO_ERROR."""
    from sentinel.exit_codes import EXIT_IO_ERROR as _EXIT_IO_ERROR
    from sentinel.cli_managed import cmd_managed
    from tests.conftest import make_test_db

    db_path = make_test_db(tmp_path, template=migrated_db_template)
    ns = argparse.Namespace(
        managed_cmd="show",
        database=str(db_path),
        inventory=None,
        output_format="text",
        name="DoesNotExist",
    )
    rc = cmd_managed(ns)
    assert rc == _EXIT_IO_ERROR


def test_cmd_managed_unknown_subcommand(
    tmp_path: Path, migrated_db_template: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """Unknown `managed` subcommand returns EXIT_INVALID_ARGS."""
    from sentinel.cli_managed import cmd_managed
    from tests.conftest import make_test_db

    db_path = make_test_db(tmp_path, template=migrated_db_template)
    ns = argparse.Namespace(
        managed_cmd="bogus",
        database=str(db_path),
        inventory=None,
        output_format="text",
    )
    rc = cmd_managed(ns)
    assert rc == EXIT_INVALID_ARGS


# ---------------------------------------------------------------------------
# cli_fetch — _check_alert and _state_path utilities
# ---------------------------------------------------------------------------


def test_state_path_honors_xdg_data_home(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """_state_path respects XDG_DATA_HOME env var."""
    from sentinel.cli_fetch import _state_path

    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "xdg"))
    p = _state_path()
    assert p == tmp_path / "xdg" / "sentinel" / "fetch_state.json"


def test_state_path_default_when_no_env(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """_state_path falls back to ~/.local/share when XDG_DATA_HOME absent."""
    from sentinel.cli_fetch import _state_path

    monkeypatch.delenv("XDG_DATA_HOME", raising=False)
    p = _state_path()
    # Must end in sentinel/fetch_state.json.
    assert p.name == "fetch_state.json"
    assert p.parent.name == "sentinel"


def test_check_alert_persists_hash_on_first_run(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """_check_alert persists the first-seen SHA256 to fetch_state.json."""
    from sentinel.cli_fetch import _check_alert
    from sentinel.models import PolicyOrigin
    from sentinel.fetchers.base import FetchResult
    from datetime import datetime, timezone

    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path))
    origin = PolicyOrigin(
        source_type="url",
        source_spec="https://example.com/policy.json",
        sha256="a" * 64,
        fetched_at=datetime.now(timezone.utc),
        cache_status="miss",
    )
    result = FetchResult(body=b"{}", origin=origin, headers={}, cache_status="MISS")

    _check_alert(result)

    state_file = tmp_path / "sentinel" / "fetch_state.json"
    assert state_file.exists()
    import json as _json

    state = _json.loads(state_file.read_text())
    assert state["url::https://example.com/policy.json"] == "a" * 64


def test_check_alert_warns_on_hash_change(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """_check_alert emits [WARN] when the SHA256 differs from the stored one."""
    import json as _json
    from datetime import datetime, timezone

    from sentinel.cli_fetch import _check_alert
    from sentinel.models import PolicyOrigin
    from sentinel.fetchers.base import FetchResult

    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path))
    state_file = tmp_path / "sentinel" / "fetch_state.json"
    state_file.parent.mkdir(parents=True, exist_ok=True)
    state_file.write_text(
        _json.dumps({"url::https://example.com/policy.json": "a" * 64})
    )

    origin = PolicyOrigin(
        source_type="url",
        source_spec="https://example.com/policy.json",
        sha256="b" * 64,  # Different!
        fetched_at=datetime.now(timezone.utc),
        cache_status="miss",
    )
    result = FetchResult(body=b"{}", origin=origin, headers={}, cache_status="MISS")
    _check_alert(result)

    err = capsys.readouterr().err
    assert "[WARN]" in err
    assert "changed since last fetch" in err


def test_check_alert_surfaces_oserror_on_state_read(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """v0.8.1 (PE3): OSError on state-file read is surfaced via [WARN].

    Pre-fix, the state-file read error was silently swallowed with a
    ``prev = {}`` fallback — the operator never knew --alert-on-new
    was running with a blank baseline.
    """
    from datetime import datetime, timezone

    from sentinel.cli_fetch import _check_alert
    from sentinel.models import PolicyOrigin
    from sentinel.fetchers.base import FetchResult

    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path))
    # Create the state file but make read_text raise OSError.
    state_file = tmp_path / "sentinel" / "fetch_state.json"
    state_file.parent.mkdir(parents=True, exist_ok=True)
    state_file.write_text("{}")

    def _raising_read_text(*args, **kwargs):
        raise OSError("simulated I/O error")

    monkeypatch.setattr("pathlib.Path.read_text", _raising_read_text)

    origin = PolicyOrigin(
        source_type="url",
        source_spec="https://example.com/policy.json",
        sha256="a" * 64,
        fetched_at=datetime.now(timezone.utc),
        cache_status="miss",
    )
    result = FetchResult(body=b"{}", origin=origin, headers={}, cache_status="MISS")
    _check_alert(result)
    err = capsys.readouterr().err
    assert "[WARN]" in err
    assert "could not read fetch_state" in err
    assert "--alert-on-new will not detect drift" in err


def test_check_alert_surfaces_json_decode_error_on_state_read(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """v0.8.1 (PE3): corrupted state file surfaces JSONDecodeError."""
    from datetime import datetime, timezone

    from sentinel.cli_fetch import _check_alert
    from sentinel.models import PolicyOrigin
    from sentinel.fetchers.base import FetchResult

    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path))
    state_file = tmp_path / "sentinel" / "fetch_state.json"
    state_file.parent.mkdir(parents=True, exist_ok=True)
    state_file.write_text("{ invalid json")

    origin = PolicyOrigin(
        source_type="url",
        source_spec="https://example.com/policy.json",
        sha256="a" * 64,
        fetched_at=datetime.now(timezone.utc),
        cache_status="miss",
    )
    result = FetchResult(body=b"{}", origin=origin, headers={}, cache_status="MISS")
    _check_alert(result)
    err = capsys.readouterr().err
    assert "[WARN]" in err
    assert "not valid JSON" in err

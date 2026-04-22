"""Tests for :mod:`sentinel.config` (Phase 1 + Amendment 6 Theme F3).

Covers:

* Precedence chain (shipped defaults -> system -> user -> project -> env -> CLI).
* Ephemeral-flag HARD-FAIL for ``insecure`` / ``allow_domain`` / ``skip_migrations``
  in TOML, and for ``insecure`` / ``allow_domain`` in env.
* Amendment 6 Theme F3 carve-out for ``SENTINEL_SKIP_MIGRATIONS`` (env loud-warn).
* ``SecretStr`` handling for ``github_token`` (L7).
"""

from __future__ import annotations

import os
from pathlib import Path

import pytest
from pydantic import SecretStr

from sentinel.config import (
    ConfigError,
    Settings,
    load_settings,
    load_toml_with_ephemeral_guard,
    reset_settings,
    warn_if_skip_migrations_env,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


@pytest.fixture
def clean_env(monkeypatch: pytest.MonkeyPatch) -> None:
    """Strip ``SENTINEL_*`` env vars so tests start from a clean slate."""
    for k in list(os.environ.keys()):
        if k.startswith("SENTINEL_"):
            # Exclude SENTINEL_DATA_DIR which the session fixture manages.
            if k != "SENTINEL_DATA_DIR":
                monkeypatch.delenv(k, raising=False)


@pytest.fixture(autouse=True)
def _reset_between_tests() -> None:
    reset_settings()


# ---------------------------------------------------------------------------
# Direct construction
# ---------------------------------------------------------------------------


class TestDefaults:
    def test_direct_construction_yields_defaults(self) -> None:
        s = Settings()
        assert s.account_id == "123456789012"
        assert s.region == "us-east-1"
        assert s.network.verify_tls is True
        assert s.pipeline.fail_fast is False
        assert s.network.max_redirects == 3

    def test_ephemeral_flags_default_false(self) -> None:
        s = Settings()
        assert s.insecure is False
        assert s.allow_domain == []
        assert s.skip_migrations is False


# ---------------------------------------------------------------------------
# TOML ephemeral guard
# ---------------------------------------------------------------------------


class TestEphemeralTomlGuard:
    """HARD-FAIL on ephemeral keys anywhere in a TOML file."""

    def test_insecure_in_root_rejected(self, tmp_path: Path) -> None:
        f = tmp_path / "bad.toml"
        f.write_text("insecure = true\n", encoding="utf-8")
        with pytest.raises(ConfigError, match="insecure"):
            load_toml_with_ephemeral_guard(f)

    def test_allow_domain_in_root_rejected(self, tmp_path: Path) -> None:
        f = tmp_path / "bad.toml"
        f.write_text('allow_domain = ["x.com"]\n', encoding="utf-8")
        with pytest.raises(ConfigError, match="allow_domain"):
            load_toml_with_ephemeral_guard(f)

    def test_skip_migrations_in_root_rejected(self, tmp_path: Path) -> None:
        f = tmp_path / "bad.toml"
        f.write_text("skip_migrations = true\n", encoding="utf-8")
        with pytest.raises(ConfigError, match="skip_migrations"):
            load_toml_with_ephemeral_guard(f)

    def test_nested_profile_insecure_rejected(self, tmp_path: Path) -> None:
        f = tmp_path / "bad.toml"
        f.write_text(
            "[profiles.dev]\ninsecure = true\n", encoding="utf-8"
        )
        with pytest.raises(ConfigError, match="insecure"):
            load_toml_with_ephemeral_guard(f)

    def test_deeply_nested_rejected(self, tmp_path: Path) -> None:
        f = tmp_path / "bad.toml"
        f.write_text(
            "[profiles.dev.stuff]\nallow_domain = ['x']\n", encoding="utf-8"
        )
        with pytest.raises(ConfigError):
            load_toml_with_ephemeral_guard(f)

    def test_clean_toml_loads(self, tmp_path: Path) -> None:
        f = tmp_path / "ok.toml"
        f.write_text('account_id = "999999999999"\n', encoding="utf-8")
        data = load_toml_with_ephemeral_guard(f)
        assert data["account_id"] == "999999999999"

    def test_malformed_toml_raises(self, tmp_path: Path) -> None:
        f = tmp_path / "broken.toml"
        f.write_text("not = valid toml [", encoding="utf-8")
        with pytest.raises(ConfigError, match="failed to parse"):
            load_toml_with_ephemeral_guard(f)


# ---------------------------------------------------------------------------
# Env-var ephemeral guard
# ---------------------------------------------------------------------------


class TestEphemeralEnvGuard:
    def test_sentinel_insecure_env_rejected(
        self, clean_env: None, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("SENTINEL_INSECURE", "1")
        with pytest.raises(ConfigError, match="insecure"):
            load_settings()

    def test_sentinel_allow_domain_env_rejected(
        self, clean_env: None, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("SENTINEL_ALLOW_DOMAIN", "x.com")
        with pytest.raises(ConfigError, match="allow_domain"):
            load_settings()


# ---------------------------------------------------------------------------
# SENTINEL_SKIP_MIGRATIONS carve-out (Amendment 6 F3)
# ---------------------------------------------------------------------------


class TestSkipMigrationsCarveOut:
    def test_unset_returns_false(
        self, clean_env: None, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.delenv("SENTINEL_SKIP_MIGRATIONS", raising=False)
        assert warn_if_skip_migrations_env() is False

    @pytest.mark.parametrize("val", ["1", "true", "TRUE", "yes", "on"])
    def test_truthy_values_return_true(
        self,
        clean_env: None,
        monkeypatch: pytest.MonkeyPatch,
        capsys: pytest.CaptureFixture,
        val: str,
    ) -> None:
        monkeypatch.setenv("SENTINEL_SKIP_MIGRATIONS", val)
        assert warn_if_skip_migrations_env() is True
        captured = capsys.readouterr()
        assert "[WARN]" in captured.err
        assert "SENTINEL_SKIP_MIGRATIONS" in captured.err

    @pytest.mark.parametrize("val", ["0", "false", "no", "", "bogus"])
    def test_falsy_values_return_false(
        self,
        clean_env: None,
        monkeypatch: pytest.MonkeyPatch,
        val: str,
    ) -> None:
        monkeypatch.setenv("SENTINEL_SKIP_MIGRATIONS", val)
        assert warn_if_skip_migrations_env() is False


# ---------------------------------------------------------------------------
# SecretStr redaction
# ---------------------------------------------------------------------------


class TestGithubTokenSecretStr:
    def test_token_stored_as_secret_str(self) -> None:
        s = Settings(github_token="ghp_faketoken")
        assert isinstance(s.github_token, SecretStr)
        assert s.github_token.get_secret_value() == "ghp_faketoken"

    def test_str_repr_does_not_leak_value(self) -> None:
        s = Settings(github_token="ghp_faketoken")
        # Pydantic's default SecretStr.__repr__ returns **** form.
        assert "ghp_faketoken" not in repr(s.github_token)
        assert "ghp_faketoken" not in str(s.github_token)

    def test_model_dump_redacts_by_default(self) -> None:
        s = Settings(github_token="ghp_faketoken")
        dumped = s.model_dump()
        # SecretStr dumps as SecretStr instance by default; str cast hides it.
        token_repr = str(dumped.get("github_token"))
        assert "ghp_faketoken" not in token_repr


# ---------------------------------------------------------------------------
# Precedence chain
# ---------------------------------------------------------------------------


class TestPrecedenceChain:
    """CLI overrides beat env; env beats TOML; TOML beats shipped defaults."""

    def test_cli_overrides_win(
        self, clean_env: None, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("SENTINEL_LOG_LEVEL", "WARNING")
        s = load_settings(cli_overrides={"logging": {"level": "ERROR"}})
        assert s.logging.level == "ERROR"

    def test_env_overrides_toml(
        self,
        clean_env: None,
        monkeypatch: pytest.MonkeyPatch,
        tmp_path: Path,
    ) -> None:
        toml = tmp_path / "c.toml"
        toml.write_text(
            "[logging]\nlevel = 'DEBUG'\n", encoding="utf-8"
        )
        monkeypatch.setenv("SENTINEL_LOG_LEVEL", "ERROR")
        s = load_settings(config_path_override=toml)
        assert s.logging.level == "ERROR"

    def test_explicit_config_path_loads(
        self, clean_env: None, tmp_path: Path
    ) -> None:
        toml = tmp_path / "c.toml"
        toml.write_text('account_id = "111111111111"\n', encoding="utf-8")
        s = load_settings(config_path_override=toml)
        assert s.account_id == "111111111111"

    def test_missing_config_path_raises(
        self, clean_env: None, tmp_path: Path
    ) -> None:
        with pytest.raises(ConfigError, match="not found"):
            load_settings(config_path_override=tmp_path / "missing.toml")


# ---------------------------------------------------------------------------
# Profile overlay
# ---------------------------------------------------------------------------


class TestProfileOverlay:
    def test_profile_override_applies(
        self, clean_env: None, tmp_path: Path
    ) -> None:
        toml = tmp_path / "c.toml"
        toml.write_text(
            "account_id = '000000000000'\n"
            "[profiles.dev]\n"
            "account_id = '222222222222'\n"
            "log_level = 'DEBUG'\n",
            encoding="utf-8",
        )
        s = load_settings(
            config_path_override=toml, profile_override="dev"
        )
        assert s.account_id == "222222222222"
        assert s.logging.level == "DEBUG"
        assert s.profile == "dev"

    def test_unknown_profile_raises(
        self, clean_env: None, tmp_path: Path
    ) -> None:
        toml = tmp_path / "c.toml"
        toml.write_text(
            "account_id = '000000000000'\n", encoding="utf-8"
        )
        with pytest.raises(ConfigError, match="not defined"):
            load_settings(
                config_path_override=toml, profile_override="nope"
            )


# ---------------------------------------------------------------------------
# Settings singleton behaviour
# ---------------------------------------------------------------------------


class TestSingleton:
    def test_get_returns_cached(self, clean_env: None) -> None:
        from sentinel.config import get_settings

        a = get_settings()
        b = get_settings()
        assert a is b

    def test_set_installs_singleton(self, clean_env: None) -> None:
        from sentinel.config import get_settings, set_settings

        custom = Settings(account_id="333333333333")
        set_settings(custom)
        assert get_settings() is custom

    def test_reset_clears_singleton(self, clean_env: None) -> None:
        from sentinel.config import get_settings, set_settings

        custom = Settings(account_id="444444444444")
        set_settings(custom)
        reset_settings()
        fresh = get_settings()
        assert fresh is not custom

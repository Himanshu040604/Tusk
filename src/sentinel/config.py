# NOTE: no `from __future__ import annotations` — pydantic v2 model file.
# Pydantic's Field(...)/model_rebuild() flow relies on runtime annotation
# evaluation, and PEP 563 deferred-eval interacts badly with pydantic's
# discriminated-union / computed-field validators.  Amendment 6 Theme J
# ruff rule FA102 is waived for this file via pyproject.toml
# [tool.ruff.lint.per-file-ignores].
"""Typed configuration for Sentinel.

Built on ``pydantic-settings`` (§ 3).  Implements the six-tier precedence
chain from § 5.2 (CLI > env > project-local TOML > user TOML > system TOML
> shipped defaults.toml).

Ephemeral-flag HARD-FAIL enforcement per § 5.2 Amendment 6 Theme F3:

* ``--insecure`` and ``--allow-domain``
    HARD-FAIL on ANY non-CLI source (TOML or env).
* ``--skip-migrations``
    HARD-FAIL on TOML.  LOUD-WARN-ACCEPT on env
    ``SENTINEL_SKIP_MIGRATIONS`` (panic-button for read-only filesystems).

Credentials use ``pydantic.SecretStr`` per § 7.5 so ``sentinel config show``
renders ``**********`` rather than the raw token.
"""

import os
import sys
import tomllib
from pathlib import Path
from typing import Any, Literal, Optional

from pydantic import BaseModel, Field, SecretStr, ValidationError
from pydantic_settings import (
    BaseSettings,
    PydanticBaseSettingsSource,
    SettingsConfigDict,
)


class ConfigError(Exception):
    """Raised when a configuration source violates a contract.

    Notably fired when an ephemeral CLI-only key (``insecure``,
    ``allow_domain``, ``skip_migrations``) is found in a persistable
    source (TOML file for all three; env var for the first two).  Error
    goes to ``sys.stderr`` directly before logging is configured.
    """


# ---------------------------------------------------------------------------
# Nested section schemas.
# ---------------------------------------------------------------------------


class NetworkAllowList(BaseModel):
    domains: list[str] = Field(default_factory=list)
    github_orgs: list[str] = Field(default_factory=list)


class NetworkSettings(BaseModel):
    max_download_bytes: int = 10_485_760
    timeout_seconds: int = 10
    max_redirects: int = 3
    verify_tls: bool = True
    allow_list: NetworkAllowList = Field(default_factory=NetworkAllowList)


class RetriesBudgets(BaseModel):
    github: int = 5
    aws_docs: int = 3
    user_url: int = 2


class RetriesSettings(BaseModel):
    max_total_wait_seconds: int = 300
    budgets: RetriesBudgets = Field(default_factory=RetriesBudgets)


class CacheSettings(BaseModel):
    ttl_hours_aws_docs: int = 168
    ttl_hours_policy_sentry: int = 72
    ttl_hours_github: int = 24
    ttl_hours_user_url: int = 1
    size_cap_mb: int = 500


class PipelineSettings(BaseModel):
    max_self_check_retries: int = 3
    fail_fast: bool = False


class IntentKeywordBucket(BaseModel):
    values: list[str] = Field(default_factory=list)
    levels: list[str] = Field(default_factory=list)


class IntentVerbPrefixes(BaseModel):
    read: list[str] = Field(default_factory=list)
    write: list[str] = Field(default_factory=list)
    admin: list[str] = Field(default_factory=list)


class IntentSettings(BaseModel):
    # dict keyed by bucket name (read, list, read_write, write, admin, ...)
    keywords: dict[str, IntentKeywordBucket] = Field(default_factory=dict)
    verb_prefixes: IntentVerbPrefixes = Field(default_factory=IntentVerbPrefixes)
    # Populated lazily at first use by parser._known_services() (L6).
    known_services: list[str] = Field(default_factory=list)


class SecuritySettings(BaseModel):
    critical_services: list[str] = Field(
        default_factory=lambda: ["iam", "sts", "organizations", "kms"]
    )
    region_less_global_services: list[str] = Field(
        default_factory=lambda: [
            "iam",
            "sts",
            "organizations",
            "cloudfront",
            "route53",
        ]
    )


class ConditionLimits(BaseModel):
    # Per-operator caps.  Stored as a plain dict so unknown operators are
    # accepted without schema churn.
    StringEquals: int = 4096
    StringLike: int = 4096
    ArnEquals: int = 8192
    ArnLike: int = 8192
    Bool: int = 64
    NumericEquals: int = 128
    DateEquals: int = 128

    model_config = {"extra": "allow"}


class ParserLimits(BaseModel):
    max_json_nesting_depth: int = 32
    max_statements_per_policy: int = 100
    max_document_chars: int = 10_000
    max_document_size: int = 10_485_760
    max_condition_value_chars: int = 4096
    condition: ConditionLimits = Field(default_factory=ConditionLimits)


class ParserSettings(BaseModel):
    limits: ParserLimits = Field(default_factory=ParserLimits)


class ConditionProfile(BaseModel):
    enabled_keys: list[str] = Field(default_factory=list)


class LoggingSettings(BaseModel):
    level: Literal["DEBUG", "INFO", "WARNING", "ERROR"] = "INFO"
    format: Literal["human", "json"] = "human"


class DefaultValues(BaseModel):
    account_id: str = "123456789012"
    region: str = "us-east-1"
    cache_ttl_hours: int = 24
    max_retries: int = 3


class ProfileConfig(BaseModel):
    """Per-profile override block.  All fields optional; merge via dict
    update onto the base :class:`Settings`."""

    account_id: Optional[str] = None
    region: Optional[str] = None
    log_level: Optional[str] = None
    log_format: Optional[str] = None
    max_retries: Optional[int] = None
    fail_fast: Optional[bool] = None
    security_critical_services: Optional[list[str]] = None

    model_config = {"extra": "allow"}


# ---------------------------------------------------------------------------
# Ephemeral-flag enforcement (§ 5.2 — Amendment 6 Theme F3).
# ---------------------------------------------------------------------------


#: Keys that MUST NOT appear in TOML.  If found, raise ``ConfigError``.
_EPHEMERAL_TOML_FORBIDDEN: frozenset[str] = frozenset(
    {"insecure", "allow_domain", "skip_migrations"}
)

#: Keys that MUST NOT appear in environment variables.  ``skip_migrations``
#: is deliberately absent from this set — its env form
#: (``SENTINEL_SKIP_MIGRATIONS``) is a legitimate read-only-fs escape hatch
#: and is LOUD-WARN-ACCEPTED by :func:`warn_if_skip_migrations_env`.
_EPHEMERAL_ENV_FORBIDDEN: frozenset[str] = frozenset({"insecure", "allow_domain"})


def _raise_ephemeral_toml(key: str, source_path: Path, line_hint: str = "") -> None:
    """Raise ``ConfigError`` for a banned TOML key with remediation text.

    The error goes to stderr via the caller's ``print`` — logging may not
    yet be configured at Settings construction time.
    """
    suffix = f":{line_hint}" if line_hint else ""
    msg = (
        f"ConfigError: Key {key!r} is CLI-only and cannot be set in "
        f"'{source_path}{suffix}'.\n"
        f"Use 'sentinel --{key.replace('_', '-')} <subcommand>' instead. "
        f"This restriction prevents accidental persistence of security-"
        f"sensitive flags (see prod_imp.md § 5.2)."
    )
    raise ConfigError(msg)


def _raise_ephemeral_env(key: str, env_name: str) -> None:
    msg = (
        f"ConfigError: Environment variable {env_name!r} cannot be set — "
        f"key {key!r} is CLI-only.\n"
        f"Use 'sentinel --{key.replace('_', '-')} <subcommand>' instead "
        f"(see prod_imp.md § 5.2)."
    )
    raise ConfigError(msg)


def warn_if_skip_migrations_env() -> bool:
    """Loud-warn when ``SENTINEL_SKIP_MIGRATIONS`` is set.

    This is the Amendment 6 Theme F3 carve-out: the flag is ephemeral in
    the CLI sense (never persisted to TOML) but its env form IS honored
    for read-only-filesystem / Docker ``:ro`` mount scenarios.

    Called by ``cli.main()`` BEFORE logging is configured so the warn goes
    to raw stderr via ``print`` — structured logging is not yet alive.

    Returns:
        True if the env var was set to a truthy value, False otherwise.
    """
    raw = os.environ.get("SENTINEL_SKIP_MIGRATIONS", "")
    if raw.strip().lower() in {"1", "true", "yes", "on"}:
        print(
            "[WARN] SENTINEL_SKIP_MIGRATIONS=1 is set — Alembic auto-upgrade "
            "will be skipped.\n"
            "       Use this only for read-only filesystems / Docker :ro "
            "mounts.\n"
            "       If this is unexpected, unset the variable and re-run.",
            file=sys.stderr,
        )
        return True
    return False


# ---------------------------------------------------------------------------
# TOML loader with ephemeral-key HARD-FAIL.
# ---------------------------------------------------------------------------


def _walk_keys(data: dict[str, Any], prefix: str = "") -> list[tuple[str, str]]:
    """Return a flat list of ``(dotted_key, top_level_key)`` pairs.

    Used to detect ephemeral keys at any nesting level.  Pydantic's
    ``extra='forbid'`` would catch root-level violations, but we also need
    to detect nested entries like ``[profiles.dev] insecure = true``.
    """
    out: list[tuple[str, str]] = []
    for k, v in data.items():
        dotted = f"{prefix}{k}"
        out.append((dotted, k))
        if isinstance(v, dict):
            out.extend(_walk_keys(v, prefix=f"{dotted}."))
    return out


def load_toml_with_ephemeral_guard(path: Path) -> dict[str, Any]:
    """Parse a TOML file; raise ``ConfigError`` if any ephemeral key appears.

    The whole tree is walked because ephemeral keys are illegal anywhere —
    top-level, under ``[profiles.<name>]``, or deeper.
    """
    try:
        data = tomllib.loads(path.read_text(encoding="utf-8"))
    except (OSError, tomllib.TOMLDecodeError) as exc:
        raise ConfigError(f"ConfigError: failed to parse {path}: {exc}") from exc

    for dotted, leaf in _walk_keys(data):
        if leaf in _EPHEMERAL_TOML_FORBIDDEN:
            _raise_ephemeral_toml(leaf, path, line_hint=dotted)

    return data


# ---------------------------------------------------------------------------
# Main Settings class.
# ---------------------------------------------------------------------------


class Settings(BaseSettings):
    """Top-level Sentinel configuration.

    Constructed via :func:`load_settings` which layers the six precedence
    tiers from § 5.2.  Direct instantiation gives only field defaults.

    The ``model_config`` below disables pydantic-settings' automatic
    TOML / env wiring because the precedence merge is custom (six tiers;
    nested profile overlay).  We build the dict ourselves and hand it
    to ``Settings(**merged)``.
    """

    # --- persistable config ---
    profile: Optional[str] = None
    account_id: str = "123456789012"
    region: str = "us-east-1"

    network: NetworkSettings = Field(default_factory=NetworkSettings)
    retries: RetriesSettings = Field(default_factory=RetriesSettings)
    cache: CacheSettings = Field(default_factory=CacheSettings)
    pipeline: PipelineSettings = Field(default_factory=PipelineSettings)
    intent: IntentSettings = Field(default_factory=IntentSettings)
    security: SecuritySettings = Field(default_factory=SecuritySettings)
    parser: ParserSettings = Field(default_factory=ParserSettings)
    logging: LoggingSettings = Field(default_factory=LoggingSettings)
    condition_profiles: dict[str, ConditionProfile] = Field(default_factory=dict)
    service_name_mappings: dict[str, str] = Field(default_factory=dict)
    defaults: DefaultValues = Field(default_factory=DefaultValues)
    profiles: dict[str, ProfileConfig] = Field(default_factory=dict)

    # --- credentials ---
    # L7 / § 7.5: SecretStr guarantees `sentinel config show` redacts it.
    github_token: Optional[SecretStr] = Field(default=None)

    # --- ephemeral (CLI-only) fields ---
    # These are surfaced for runtime consumers but NEVER loaded from TOML
    # (HARD-FAIL) nor from env for the first two (HARD-FAIL) — see
    # `_EPHEMERAL_*` sets.  `skip_migrations` is loaded only from env via
    # a dedicated carve-out path.
    insecure: bool = False
    allow_domain: list[str] = Field(default_factory=list)
    skip_migrations: bool = False

    # Paths — resolved later by ``load_settings``.
    config_path: Optional[Path] = None

    model_config = SettingsConfigDict(
        extra="ignore",
        env_prefix="SENTINEL_",
        env_nested_delimiter="__",
        case_sensitive=False,
    )

    @classmethod
    def settings_customise_sources(  # type: ignore[override]
        cls,
        settings_cls: type[BaseSettings],
        init_settings: PydanticBaseSettingsSource,
        env_settings: PydanticBaseSettingsSource,
        dotenv_settings: PydanticBaseSettingsSource,
        file_secret_settings: PydanticBaseSettingsSource,
    ) -> tuple[PydanticBaseSettingsSource, ...]:
        """Disable automatic env/dotenv/file sources.

        The precedence merge in :func:`load_settings` is explicit; we do
        not want pydantic-settings running its own merge underneath.
        """
        return (init_settings,)


# ---------------------------------------------------------------------------
# Precedence merge helpers.
# ---------------------------------------------------------------------------


def _deep_merge(base: dict[str, Any], overlay: dict[str, Any]) -> dict[str, Any]:
    """Recursively merge ``overlay`` into ``base``.  Overlay wins on leaves."""
    out = dict(base)
    for k, v in overlay.items():
        if (
            k in out
            and isinstance(out[k], dict)
            and isinstance(v, dict)
        ):
            out[k] = _deep_merge(out[k], v)
        else:
            out[k] = v
    return out


def _shipped_defaults_path() -> Path:
    """Locate ``defaults.toml`` bundled with the package.

    Walks up from this file's location; works for both editable installs
    (``uv sync``) and wheel installs.
    """
    here = Path(__file__).resolve()
    # src/sentinel/config.py -> project root is three parents up
    candidate = here.parent.parent.parent / "defaults.toml"
    if candidate.is_file():
        return candidate
    # Fallback: bundled alongside the package (future wheel layout)
    alt = here.parent / "defaults.toml"
    if alt.is_file():
        return alt
    return candidate  # return missing path — caller handles gracefully


def _system_config_path() -> Path:
    if sys.platform == "win32":
        base = os.environ.get("ProgramData", r"C:\ProgramData")
        return Path(base) / "sentinel" / "config.toml"
    return Path("/etc/sentinel/config.toml")


def _user_config_path() -> Path:
    if sys.platform == "win32":
        base = os.environ.get("APPDATA", "")
        if base:
            return Path(base) / "sentinel" / "config.toml"
    xdg = os.environ.get("XDG_CONFIG_HOME")
    if xdg:
        return Path(xdg) / "sentinel" / "config.toml"
    return Path.home() / ".config" / "sentinel" / "config.toml"


def _project_local_path() -> Path:
    return Path.cwd() / ".sentinel.toml"


# ---------------------------------------------------------------------------
# Env-var extraction with ephemeral HARD-FAIL.
# ---------------------------------------------------------------------------


#: Map from env var (without ``SENTINEL_`` prefix) to dotted Settings path.
#: Only the common flat flags are exposed here; nested section tweaks use
#: ``SENTINEL_NETWORK__VERIFY_TLS`` with the configured delimiter.
_ENV_MAP: dict[str, str] = {
    "PROFILE": "profile",
    "LOG_LEVEL": "logging.level",
    "LOG_FORMAT": "logging.format",
    "GITHUB_TOKEN": "github_token",
}


def _set_dotted(d: dict[str, Any], path: str, value: Any) -> None:
    parts = path.split(".")
    cur = d
    for p in parts[:-1]:
        cur = cur.setdefault(p, {})
    cur[parts[-1]] = value


def _env_overlay() -> dict[str, Any]:
    """Collect overrides from SENTINEL_* env vars, enforcing ephemeral bans."""
    overlay: dict[str, Any] = {}

    # HARD-FAIL on forbidden env keys.  Naming convention:
    # SENTINEL_INSECURE, SENTINEL_ALLOW_DOMAIN are banned.
    for key in _EPHEMERAL_ENV_FORBIDDEN:
        env_name = f"SENTINEL_{key.upper()}"
        if env_name in os.environ:
            _raise_ephemeral_env(key, env_name)

    for env_suffix, dotted in _ENV_MAP.items():
        raw = os.environ.get(f"SENTINEL_{env_suffix}")
        if raw is not None:
            _set_dotted(overlay, dotted, raw)

    return overlay


# ---------------------------------------------------------------------------
# Public API.
# ---------------------------------------------------------------------------


def load_settings(
    cli_overrides: Optional[dict[str, Any]] = None,
    config_path_override: Optional[Path] = None,
    profile_override: Optional[str] = None,
) -> Settings:
    """Build a :class:`Settings` by merging all six precedence layers.

    Layers applied low-to-high (higher wins):

    1. Shipped ``defaults.toml`` (bundled with the package)
    2. System config (``/etc/sentinel/config.toml`` or Windows ProgramData)
    3. User config (``~/.config/sentinel/config.toml`` or Windows APPDATA)
    4. Project-local ``./.sentinel.toml``
    5. ``SENTINEL_*`` environment variables
    6. ``cli_overrides`` (pass-through from argparse ``Namespace``)

    Ephemeral flags (``insecure``, ``allow_domain``, ``skip_migrations``)
    are HARD-FAILED if present in layers 1-4; ``skip_migrations`` is also
    LOUD-WARN-ACCEPTED from env by the separate
    :func:`warn_if_skip_migrations_env` path invoked from the CLI main.
    """
    # Layer 1 — shipped defaults.
    merged: dict[str, Any] = {}
    shipped = _shipped_defaults_path()
    if shipped.is_file():
        merged = _deep_merge(merged, load_toml_with_ephemeral_guard(shipped))

    # Layers 2-4 — system, user, project-local (guarded for ephemeral keys).
    for path in (_system_config_path(), _user_config_path(), _project_local_path()):
        if path.is_file():
            merged = _deep_merge(merged, load_toml_with_ephemeral_guard(path))

    # Explicit --config override takes precedence over the three TOML tiers.
    if config_path_override is not None:
        if not config_path_override.is_file():
            raise ConfigError(
                f"ConfigError: --config path {config_path_override} not found"
            )
        merged = _deep_merge(
            merged, load_toml_with_ephemeral_guard(config_path_override)
        )
        merged["config_path"] = str(config_path_override)

    # Layer 5 — environment.
    merged = _deep_merge(merged, _env_overlay())

    # Layer 6 — CLI overrides.
    if cli_overrides:
        # CLI overrides are NOT guarded because ephemeral flags are
        # legal here.  The CLI is their only valid origin.
        merged = _deep_merge(merged, cli_overrides)

    # Apply profile overlay if one was selected.
    chosen = profile_override or merged.get("profile")
    if chosen:
        prof = merged.get("profiles", {}).get(chosen)
        if prof is None:
            raise ConfigError(
                f"ConfigError: profile {chosen!r} not defined in any config "
                f"file.  Known profiles: "
                f"{sorted(merged.get('profiles', {}).keys())}"
            )
        # Apply profile fields that map onto top-level Settings keys.
        if prof.get("log_level"):
            _set_dotted(merged, "logging.level", prof["log_level"])
        if prof.get("log_format"):
            _set_dotted(merged, "logging.format", prof["log_format"])
        for field in ("account_id", "region"):
            if prof.get(field):
                merged[field] = prof[field]
        if prof.get("max_retries") is not None:
            _set_dotted(merged, "defaults.max_retries", prof["max_retries"])
        if prof.get("fail_fast") is not None:
            _set_dotted(merged, "pipeline.fail_fast", prof["fail_fast"])
        if prof.get("security_critical_services") is not None:
            _set_dotted(
                merged,
                "security.critical_services",
                prof["security_critical_services"],
            )
        merged["profile"] = chosen

    try:
        return Settings(**merged)
    except ValidationError as exc:
        raise ConfigError(f"ConfigError: invalid settings: {exc}") from exc


# ---------------------------------------------------------------------------
# Process-wide singleton — used by L6 `parser._known_services()` lazy loader.
# ---------------------------------------------------------------------------


_SETTINGS: Optional[Settings] = None


def get_settings() -> Settings:
    """Return the process-wide :class:`Settings`, constructing on demand.

    Never called at import time (L6 + H25 import-time discipline).  The
    first call materializes from CLI/env/TOML layers; subsequent calls
    return the cached instance.  Tests override via :func:`reset_settings`
    plus Phase 1.5 autouse cache-clear fixtures.
    """
    global _SETTINGS
    if _SETTINGS is None:
        _SETTINGS = load_settings()
    return _SETTINGS


def set_settings(settings: Settings) -> None:
    """Install ``settings`` as the process-wide singleton.

    Called by ``cli.main()`` after CLI arg parsing so downstream modules
    see the fully-resolved configuration.
    """
    global _SETTINGS
    _SETTINGS = settings


def reset_settings() -> None:
    """Clear the process-wide singleton — intended for test fixtures."""
    global _SETTINGS
    _SETTINGS = None


__all__ = [
    "ConfigError",
    "Settings",
    "ProfileConfig",
    "load_settings",
    "get_settings",
    "set_settings",
    "reset_settings",
    "warn_if_skip_migrations_env",
    "load_toml_with_ephemeral_guard",
]

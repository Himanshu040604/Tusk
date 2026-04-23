"""Alembic migration env.py for the resource inventory database.

Mirrors ``migrations/iam/env.py`` — no-ORM mode, batch rendering for SQLite.
The two env.py files are kept separate (rather than one parametrized) so
each DB has its own ``versions/`` directory with independent revision
history per M18 dual-DB design.
"""

from __future__ import annotations

from alembic import context
from sqlalchemy import engine_from_config, pool

config = context.config

# NOTE (Issue 4, v0.8.0): fileConfig() call removed — Alembic's default
# logging config hijacks the root logger, producing "setup plugin" /
# "Context impl SQLiteImpl" noise on every invocation. Sentinel owns its
# logging via ``sentinel.logging_setup.configure()`` (structlog-based).

target_metadata = None


def run_migrations_offline() -> None:
    url = config.get_main_option("sqlalchemy.url")
    context.configure(
        url=url,
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
        render_as_batch=True,
    )
    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    connectable = engine_from_config(
        config.get_section(config.config_ini_section, {}),
        prefix="sqlalchemy.",
        poolclass=pool.NullPool,
    )
    with connectable.connect() as connection:
        context.configure(
            connection=connection,
            target_metadata=target_metadata,
            render_as_batch=True,
        )
        with context.begin_transaction():
            context.run_migrations()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()

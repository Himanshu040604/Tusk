"""Alembic migration env.py for the IAM actions database.

No-ORM mode per § 6.2 of prod_imp.md:

* ``target_metadata = None`` — all migrations hand-written as raw DDL via
  ``op.execute()`` / ``op.create_table()``.  ``alembic revision --autogenerate``
  is not supported (requires SQLAlchemy metadata we don't maintain).
* ``render_as_batch = True`` — required for SQLite ``ALTER COLUMN`` support
  on SQLite < 3.35.

Invoked via ``alembic -c alembic.ini -n iam upgrade head``.  The production
path is ``src/sentinel/migrations.py::check_and_upgrade_all_dbs()`` which
sets sqlalchemy.url at runtime via ``config.set_main_option`` to use absolute
paths (the ini-file relative paths are for manual debugging only).
"""

from __future__ import annotations

from logging.config import fileConfig

from alembic import context
from sqlalchemy import engine_from_config, pool

# Alembic Config object — provides access to values within the .ini in use.
config = context.config

# Interpret the config file for Python logging (no-op if no loggers section).
if config.config_file_name is not None:
    fileConfig(config.config_file_name)

# No-ORM mode: migrations are hand-written DDL, not auto-generated from
# declarative models.
target_metadata = None


def run_migrations_offline() -> None:
    """Run migrations in 'offline' mode — emits SQL to stdout.

    Useful for producing a `.sql` file that a DBA can review before
    applying.  Not used by Sentinel's auto-upgrade path (that uses online
    mode with a live SQLite connection).
    """
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
    """Run migrations in 'online' mode — live SQLite connection."""
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

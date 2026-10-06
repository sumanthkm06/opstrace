"""
OpsTrace Alembic Environment Configuration
Phase 2: PostgreSQL Database Design and Implementation
"""

import os
import sys
from logging.config import fileConfig
from pathlib import Path

from sqlalchemy import engine_from_config, pool
from alembic import context

# Ensure repository root and backend directory are in sys.path
BASE_DIR = Path(__file__).resolve().parent.parent.parent
BACKEND_DIR = BASE_DIR / "backend"
for path in (str(BASE_DIR), str(BACKEND_DIR)):
    if path not in sys.path:
        sys.path.insert(0, path)

from backend.app.core.config import get_settings
from backend.app.models import Base

# Alembic Config object
config = context.config

# Setup logging
if config.config_file_name is not None:
    fileConfig(config.config_file_name)

# Target metadata for autogenerate
target_metadata = Base.metadata


def get_url() -> str:
    """
    Dynamically retrieve the database URL from application settings (environment variables).
    Falls back to alembic.ini only if explicitly provided and not the default placeholder.
    """
    configured_url = config.get_main_option("sqlalchemy.url")
    if configured_url and configured_url != "driver://user:pass@localhost/dbname":
        return configured_url
    return get_settings().sqlalchemy_database_uri


def run_migrations_offline() -> None:
    """Run migrations in 'offline' mode."""
    url = get_url()
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
    """Run migrations in 'online' mode."""
    configuration = config.get_section(config.config_ini_section, {})
    configuration["sqlalchemy.url"] = get_url()

    connectable = engine_from_config(
        configuration,
        prefix="sqlalchemy.",
        poolclass=pool.NullPool,
    )

    with connectable.connect() as connection:
        context.configure(
            connection=connection,
            target_metadata=target_metadata,
            render_as_batch=connection.dialect.name == "sqlite",
        )

        with context.begin_transaction():
            context.run_migrations()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()

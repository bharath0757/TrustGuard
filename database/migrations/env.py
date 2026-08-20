"""
Alembic migration environment for TrustGuard.

Reads DATABASE_URL from the environment (falls back to alembic.ini value).
Imports all ORM models so that ``Base.metadata`` is fully populated before
Alembic compares it against the live schema for autogenerate.
"""
import os
import sys
from logging.config import fileConfig
from pathlib import Path

from alembic import context
from sqlalchemy import engine_from_config, pool

# ── Make project root importable ──────────────────────────────────────────
# alembic.ini already sets prepend_sys_path = . but we also set it here
# so ``alembic`` works when invoked from a subdirectory.
PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

# ── Import ORM models so Base.metadata is populated ───────────────────────
from database.base import Base
import database.models  # noqa: F401 — registers all 10 tables

config = context.config

# Set up Python logging from the alembic.ini [loggers] section.
if config.config_file_name is not None:
    fileConfig(config.config_file_name)

target_metadata = Base.metadata

# ── Override database URL from environment ────────────────────────────────
_database_url = os.environ.get("DATABASE_URL")
if _database_url:
    config.set_main_option("sqlalchemy.url", _database_url)


# ---------------------------------------------------------------------------
# Offline mode — emit SQL to stdout without a live connection
# ---------------------------------------------------------------------------

def run_migrations_offline() -> None:
    """Run migrations in 'offline' mode (no DB connection required)."""
    url = config.get_main_option("sqlalchemy.url")
    context.configure(
        url=url,
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
        # Render CREATE TYPE statements for PostgreSQL ENUMs.
        include_schemas=False,
        compare_type=True,
    )
    with context.begin_transaction():
        context.run_migrations()


# ---------------------------------------------------------------------------
# Online mode — connect to the database and apply migrations
# ---------------------------------------------------------------------------

def run_migrations_online() -> None:
    """Run migrations with a live database connection."""
    connectable = engine_from_config(
        config.get_section(config.config_ini_section, {}),
        prefix="sqlalchemy.",
        # NullPool: each migration gets a fresh connection; no pooling overhead.
        poolclass=pool.NullPool,
    )
    with connectable.connect() as connection:
        context.configure(
            connection=connection,
            target_metadata=target_metadata,
            compare_type=True,
        )
        with context.begin_transaction():
            context.run_migrations()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()

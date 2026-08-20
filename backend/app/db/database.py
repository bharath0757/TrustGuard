"""Database connection engine and session dependency."""

import asyncio
import logging
import os
import urllib.parse
from typing import AsyncGenerator, Optional

from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession, async_sessionmaker, create_async_engine

from app.core.config import settings
from app.db.models import Base

logger = logging.getLogger("trustguard.database")

# Thread/coroutine safety lock for schema initialization
_init_lock = asyncio.Lock()
_db_initialized = False

_engine: Optional[AsyncEngine] = None
_session_factory: Optional[async_sessionmaker[AsyncSession]] = None


def get_async_database_url(url: Optional[str] = None) -> str:
    """Resolve and convert database URL to the appropriate async dialect.
    
    Hierarchy:
    1. Explicitly passed url parameter
    2. DATABASE_URL from settings / environment
    3. POSTGRES_URL from settings / environment
    4. Local development SQLite fallback (non-Vercel only)
    """
    is_vercel = bool(os.environ.get("VERCEL"))

    if not url:
        url = (
            settings.DATABASE_URL
            or settings.POSTGRES_URL
            or os.environ.get("DATABASE_URL")
            or os.environ.get("POSTGRES_URL")
        )

    # Fail fast on Vercel if no PostgreSQL DATABASE_URL is configured
    if is_vercel:
        # Check if URL is missing or set to a local/sqlite URL
        if not url or "sqlite" in url.lower():
            err_msg = (
                "[DATABASE CONFIGURATION ERROR] DATABASE_URL (or POSTGRES_URL) is missing or set to SQLite "
                "in Vercel production environment. Vercel serverless functions require a persistent PostgreSQL "
                "database. Please configure DATABASE_URL in Vercel Project Settings -> Environment Variables "
                "with a valid PostgreSQL connection string (e.g., Supabase, Neon, AWS RDS, Vercel Postgres)."
            )
            logger.critical(err_msg)
            raise RuntimeError(err_msg)

    if not url:
        url = "sqlite+aiosqlite:///./trustguard.db"

    # Dialect conversions for SQLAlchemy async drivers
    if url.startswith("postgresql://"):
        url = url.replace("postgresql://", "postgresql+asyncpg://", 1)
    elif url.startswith("postgres://"):
        url = url.replace("postgres://", "postgresql+asyncpg://", 1)
    elif url.startswith("sqlite://") and not url.startswith("sqlite+aiosqlite://"):
        url = url.replace("sqlite://", "sqlite+aiosqlite://", 1)

    # Handle Postgres asyncpg query parameters if present (e.g., sslmode -> ssl)
    if "postgresql+asyncpg://" in url and "sslmode=" in url:
        # asyncpg prefers ssl=... or ssl parameter
        url = url.replace("sslmode=require", "ssl=require")
        url = url.replace("sslmode=prefer", "ssl=prefer")
        url = url.replace("sslmode=disable", "ssl=disable")

    return url


def get_database_engine(url: Optional[str] = None) -> AsyncEngine:
    """Create or return the configured SQLAlchemy AsyncEngine."""
    global _engine
    if _engine is None or url is not None:
        async_url = get_async_database_url(url)
        is_sqlite = "sqlite" in async_url

        engine_kwargs = {
            "echo": False,
        }

        if is_sqlite:
            engine_kwargs["connect_args"] = {"check_same_thread": False}
        else:
            # PostgreSQL engine optimizations for serverless resilience
            engine_kwargs["pool_pre_ping"] = True
            engine_kwargs["pool_recycle"] = 300

        created_engine = create_async_engine(async_url, **engine_kwargs)
        if url is None:
            _engine = created_engine
        return created_engine
    return _engine


def get_session_factory(engine: Optional[AsyncEngine] = None) -> async_sessionmaker[AsyncSession]:
    """Create or return the AsyncSession factory."""
    global _session_factory
    if _session_factory is None or engine is not None:
        target_engine = engine or get_database_engine()
        factory = async_sessionmaker(
            bind=target_engine,
            class_=AsyncSession,
            expire_on_commit=False,
            autoflush=False,
        )
        if engine is None:
            _session_factory = factory
        return factory
    return _session_factory


# Initialize module-level engine and session factory for backward compatibility
try:
    engine = get_database_engine()
    AsyncSessionLocal = get_session_factory(engine)
except Exception as e:
    # In Vercel build phase or when DATABASE_URL is missing, defer engine creation error to runtime
    logger.warning("Database engine initialization deferred: %s", e)
    engine = None  # type: ignore
    AsyncSessionLocal = None  # type: ignore


async def init_db(target_engine: Optional[AsyncEngine] = None):
    """Initialize database tables idempotently."""
    global _db_initialized
    eng = target_engine or get_database_engine()
    logger.info("Initializing database schema...")
    async with eng.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    _db_initialized = True
    logger.info("Database schema initialized successfully.")


async def ensure_db_initialized(target_engine: Optional[AsyncEngine] = None):
    """Ensure database schema is created at least once per worker process (idempotent)."""
    global _db_initialized
    if not _db_initialized:
        async with _init_lock:
            if not _db_initialized:
                await init_db(target_engine)


async def get_db() -> AsyncGenerator[AsyncSession, None]:
    """FastAPI dependency for providing async database sessions with auto-initialization."""
    await ensure_db_initialized()
    session_factory = get_session_factory()
    async with session_factory() as session:
        try:
            yield session
        except Exception:
            await session.rollback()
            raise
        finally:
            await session.close()

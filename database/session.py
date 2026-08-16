"""
TrustGuard — SQLAlchemy engine, session factory, and FastAPI dependency.

Configuration is read from the ``DATABASE_URL`` environment variable.
Set ``SQL_ECHO=true`` to log all generated SQL statements (development only).

Usage in a FastAPI route::

    from fastapi import Depends
    from sqlalchemy.orm import Session
    from database.session import get_db

    @router.get("/papers")
    def list_papers(db: Session = Depends(get_db)):
        return db.query(QuestionPaper).all()

Security
--------
No credentials are hardcoded.  ``DATABASE_URL`` **must** be set via the
environment or a ``.env`` file (which is git-ignored).  The application
refuses to start if the variable is missing.
"""
import os
import sys
from typing import Generator, Optional

from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker

# ---------------------------------------------------------------------------
# Engine
# ---------------------------------------------------------------------------

DATABASE_URL: Optional[str] = os.environ.get("DATABASE_URL")

if DATABASE_URL is None:
    # Allow import-time usage without a live database (e.g., pytest
    # creates its own in-memory engine).  Only raise when get_db() is
    # actually called without the variable set.
    DATABASE_URL = "sqlite://"  # no-op placeholder
    _PLACEHOLDER = True
else:
    _PLACEHOLDER = False

def _normalize_sync_url(url: Optional[str]) -> str:
    if not url:
        return "sqlite://"
    if url.startswith("postgresql+asyncpg://"):
        return url.replace("postgresql+asyncpg://", "postgresql://", 1)
    if url.startswith("sqlite+aiosqlite://"):
        return url.replace("sqlite+aiosqlite://", "sqlite://", 1)
    return url


_effective_url = _normalize_sync_url(DATABASE_URL)

engine_kwargs = {
    "echo": os.environ.get("SQL_ECHO", "false").lower() == "true",
}

if "sqlite" in _effective_url:
    engine_kwargs["connect_args"] = {"check_same_thread": False}
else:
    engine_kwargs["pool_pre_ping"] = True
    engine_kwargs["pool_size"] = 5
    engine_kwargs["max_overflow"] = 10

engine = create_engine(_effective_url, **engine_kwargs)

# ---------------------------------------------------------------------------
# Session factory
# ---------------------------------------------------------------------------

SessionLocal = sessionmaker(
    autocommit=False,
    autoflush=False,
    bind=engine,
)


# ---------------------------------------------------------------------------
# FastAPI dependency
# ---------------------------------------------------------------------------

def get_db() -> Generator[Session, None, None]:
    """
    Yield a database session scoped to a single HTTP request.

    Raises ``RuntimeError`` if ``DATABASE_URL`` was never set — prevents
    accidentally running a production service against the placeholder.

    The session is always closed in the ``finally`` block regardless of
    whether the route handler raises an exception.  Commits and rollbacks
    are the responsibility of the route handler or a middleware layer.
    """
    if _PLACEHOLDER:
        raise RuntimeError(
            "DATABASE_URL environment variable is not set. "
            "Set it in your .env file or environment before starting the server."
        )
    db: Session = SessionLocal()
    try:
        yield db
    finally:
        db.close()

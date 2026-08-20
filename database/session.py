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
"""
import os
from typing import Generator

from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker

# ---------------------------------------------------------------------------
# Engine
# ---------------------------------------------------------------------------

DATABASE_URL: str = os.environ.get(
    "DATABASE_URL",
    "postgresql://user:password@localhost:5432/trustguard",
)

engine = create_engine(
    DATABASE_URL,
    # Recycle stale connections silently rather than raising on first use.
    pool_pre_ping=True,
    # Conservative pool — tune for production workload.
    pool_size=10,
    max_overflow=20,
    # Enable SQL logging only when explicitly requested (never in production).
    echo=os.environ.get("SQL_ECHO", "false").lower() == "true",
)

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

    The session is always closed in the ``finally`` block regardless of
    whether the route handler raises an exception.  Commits and rollbacks
    are the responsibility of the route handler or a middleware layer.
    """
    db: Session = SessionLocal()
    try:
        yield db
    finally:
        db.close()

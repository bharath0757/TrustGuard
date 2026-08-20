"""
TrustGuard — database package.

Public surface:
    Base        : SQLAlchemy declarative base (all models register here)
    TimestampMixin: created_at / updated_at columns
    engine      : configured SQLAlchemy engine
    SessionLocal: session factory
    get_db      : FastAPI dependency that yields a database session
"""
from database.base import Base, TimestampMixin
from database.session import SessionLocal, engine, get_db

__all__ = [
    "Base",
    "TimestampMixin",
    "SessionLocal",
    "engine",
    "get_db",
]

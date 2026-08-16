"""
TrustGuard — SQLAlchemy declarative base and shared column mixins.

All ORM models import ``Base`` from this module and register themselves
against its metadata.  ``TimestampMixin`` provides server-side
(PostgreSQL ``NOW()``) *and* Python-side (for SQLite / testing) defaults
so the same model classes work in both environments without changes.
"""
from datetime import datetime, timezone

from sqlalchemy import DateTime, func
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column


# ---------------------------------------------------------------------------
# Python-side UTC helper
# ---------------------------------------------------------------------------

def _utcnow() -> datetime:
    """Return the current UTC datetime.  Used as Python-side column default."""
    return datetime.now(timezone.utc)


# ---------------------------------------------------------------------------
# Declarative base
# ---------------------------------------------------------------------------

class Base(DeclarativeBase):
    """
    Shared SQLAlchemy declarative base for all TrustGuard ORM models.

    All models that inherit from this class are automatically registered in
    ``Base.metadata``, which Alembic reads for auto-generation and which
    ``create_all()`` uses in tests.
    """


# ---------------------------------------------------------------------------
# Shared mixins
# ---------------------------------------------------------------------------

class TimestampMixin:
    """
    Adds ``created_at`` and ``updated_at`` columns to any model.

    - ``server_default=func.now()`` — set by the database on INSERT (PostgreSQL)
    - ``default=_utcnow``          — set by Python on INSERT (SQLite / tests)
    - ``onupdate=_utcnow``         — refreshed by Python on every UPDATE

    Both columns use timezone-aware timestamps (``TIMESTAMPTZ`` on PostgreSQL).
    """

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        default=_utcnow,
        nullable=False,
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        default=_utcnow,
        onupdate=_utcnow,
        nullable=False,
    )

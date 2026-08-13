"""
TrustGuard — AuditLog and ThreatEvent ORM models.

Tables
------
audit_logs     — append-only immutable record of every system action.
threat_events  — controlled security events raised by the attack simulator
                 or real-time detection logic.

Immutability
------------
``audit_logs`` intentionally has NO ``updated_at`` column.  Once a row is
written it must not be changed.  Application code and database grants must
enforce this; this model simply omits the column so any ORM update would
require adding it explicitly.

IP address storage
------------------
``actor_ip`` is stored as ``String(45)`` (handles both IPv4 and IPv6).
In the Alembic migration this maps to PostgreSQL ``INET`` for proper
IP-address indexing and validation.

JSONB metadata
--------------
``metadata`` / ``extra_data`` columns use ``JSON`` at the ORM layer.
The Alembic migration creates them as ``JSONB`` on PostgreSQL for
efficient GIN indexing.
"""
import enum
import uuid
from datetime import datetime
from typing import Optional

from sqlalchemy import Boolean, DateTime, Enum, ForeignKey, Index, JSON, String, Text, func
from sqlalchemy.orm import Mapped, mapped_column, relationship
from sqlalchemy import Uuid

from database.base import Base, _utcnow


# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------

class AuditResult(str, enum.Enum):
    """Outcome of an audited operation."""
    SUCCESS = "SUCCESS"
    FAILURE = "FAILURE"
    DENIED = "DENIED"


class ThreatEventType(str, enum.Enum):
    """
    Categories of controlled security events.

    UNAUTHORIZED_ACCESS — attempt to access a resource without authorization.
    INVALID_QUORUM      — reconstruction attempted without quorum.
    INTEGRITY_FAILURE   — fragment hash mismatch detected.
    DENIED_OPERATION    — an action explicitly blocked by policy.
    REPLAY_ATTEMPT      — duplicate request / token reuse detected.
    BRUTE_FORCE         — repeated failed authentication attempts.
    """
    UNAUTHORIZED_ACCESS = "UNAUTHORIZED_ACCESS"
    INVALID_QUORUM = "INVALID_QUORUM"
    INTEGRITY_FAILURE = "INTEGRITY_FAILURE"
    DENIED_OPERATION = "DENIED_OPERATION"
    REPLAY_ATTEMPT = "REPLAY_ATTEMPT"
    BRUTE_FORCE = "BRUTE_FORCE"


class ThreatSeverity(str, enum.Enum):
    """Relative severity of a threat event."""
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


# ---------------------------------------------------------------------------
# Models
# ---------------------------------------------------------------------------

class AuditLog(Base):
    """
    Immutable record of every action taken in the system.

    Design rules:
    - NEVER update an audit log row.
    - ``actor_id`` is nullable to capture unauthenticated or system-generated events.
    - ``metadata`` (JSONB in PG) holds arbitrary structured context without
      requiring schema changes.
    - Indexes support time-range queries, actor lookups, and target lookups.

    Note: this model intentionally omits ``TimestampMixin`` so there is
    no ``updated_at`` column — immutability by construction.
    """
    __tablename__ = "audit_logs"

    id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
    )
    # Immutable creation timestamp — set once and never changed.
    timestamp: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        default=_utcnow,
        nullable=False,
        comment="When the event occurred — immutable",
    )
    actor_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("users.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
        comment="NULL for system-generated or unauthenticated events",
    )
    actor_ip: Mapped[Optional[str]] = mapped_column(
        String(45),
        nullable=True,
        comment="IPv4 or IPv6 address of the request origin (INET in PostgreSQL)",
    )
    action: Mapped[str] = mapped_column(
        String(100),
        nullable=False,
        index=True,
        comment="Dot-namespaced action, e.g. 'paper.status_changed'",
    )
    target_type: Mapped[Optional[str]] = mapped_column(
        String(50),
        nullable=True,
        comment="Entity type, e.g. 'question_paper', 'access_request'",
    )
    target_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        Uuid(as_uuid=True),
        nullable=True,
        comment="UUID of the affected entity",
    )
    result: Mapped[AuditResult] = mapped_column(
        Enum(AuditResult, name="auditresult", create_constraint=True),
        nullable=False,
    )
    reason: Mapped[Optional[str]] = mapped_column(
        Text,
        nullable=True,
        comment="Human-readable explanation of the result",
    )
    extra_data: Mapped[Optional[dict]] = mapped_column(
        JSON,
        nullable=True,
        comment="Arbitrary JSON context (JSONB in PostgreSQL)",
    )

    # ── relationships ──────────────────────────────────────────────────────
    actor: Mapped[Optional["User"]] = relationship(
        "User",
        back_populates="audit_logs",
        foreign_keys=[actor_id],
    )

    # ── indexes ────────────────────────────────────────────────────────────
    __table_args__ = (
        # timestamp ASC here (ORM-level); the Alembic migration creates this DESC in PostgreSQL
        Index("ix_audit_logs_timestamp", "timestamp"),
        # Look up all events on a specific entity
        Index("ix_audit_logs_target", "target_type", "target_id"),
    )

    def __repr__(self) -> str:
        return (
            f"<AuditLog action={self.action!r} "
            f"result={self.result} ts={self.timestamp}>"
        )


class ThreatEvent(Base):
    """
    A discrete security event raised by detection logic or the attack simulator.

    ``resolved`` / ``resolved_at`` / ``resolved_by`` support an incident
    management workflow where security staff acknowledge and close events.

    Note: intentionally no ``TimestampMixin`` — ``timestamp`` is the single
    creation timestamp; there is no ``updated_at``.
    """
    __tablename__ = "threat_events"

    id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
    )
    timestamp: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        default=_utcnow,
        nullable=False,
        index=True,
    )
    event_type: Mapped[ThreatEventType] = mapped_column(
        Enum(ThreatEventType, name="threateventtype", create_constraint=True),
        nullable=False,
        index=True,
    )
    severity: Mapped[ThreatSeverity] = mapped_column(
        Enum(ThreatSeverity, name="threatseverity", create_constraint=True),
        nullable=False,
        index=True,
    )
    actor_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("users.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
        comment="Identified user behind the event; NULL if unauthenticated",
    )
    actor_ip: Mapped[Optional[str]] = mapped_column(
        String(45),
        nullable=True,
        comment="Source IP address (INET in PostgreSQL)",
    )
    target_type: Mapped[Optional[str]] = mapped_column(
        String(50),
        nullable=True,
    )
    target_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        Uuid(as_uuid=True),
        nullable=True,
    )
    description: Mapped[str] = mapped_column(
        Text,
        nullable=False,
        comment="Human-readable description of the security event",
    )
    extra_data: Mapped[Optional[dict]] = mapped_column(
        JSON,
        nullable=True,
        comment="Arbitrary JSON context (JSONB in PostgreSQL)",
    )

    # ── Incident resolution ────────────────────────────────────────────────
    resolved: Mapped[bool] = mapped_column(
        Boolean,
        nullable=False,
        default=False,
        server_default="false",
        index=True,
    )
    resolved_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )
    resolved_by: Mapped[Optional[uuid.UUID]] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("users.id", ondelete="SET NULL"),
        nullable=True,
        comment="Which security officer resolved / closed this event",
    )

    # ── relationships ──────────────────────────────────────────────────────
    actor: Mapped[Optional["User"]] = relationship(
        "User",
        back_populates="threat_events_as_actor",
        foreign_keys=[actor_id],
    )
    resolver: Mapped[Optional["User"]] = relationship(
        "User",
        back_populates="threat_events_resolved",
        foreign_keys=[resolved_by],
    )

    # ── indexes ────────────────────────────────────────────────────────────
    __table_args__ = (
        # In PostgreSQL, the Alembic migration adds a partial WHERE resolved=false filter
        Index("ix_threat_events_unresolved", "severity", "timestamp"),
        Index("ix_threat_events_target", "target_type", "target_id"),
    )

    def __repr__(self) -> str:
        return (
            f"<ThreatEvent type={self.event_type} "
            f"severity={self.severity} resolved={self.resolved}>"
        )

"""
TrustGuard — AccessRequest, Approval, and AccessWindow ORM models.

Tables
------
access_requests — a user's request to access a protected question paper.
approvals       — individual approver votes for an access request.
access_windows  — a time-bounded window during which access is permitted.

Quorum design
-------------
The security layer computes quorum status with:

    approved_count = (
        db.query(Approval)
          .filter(
              Approval.request_id == request_id,
              Approval.decision == ApprovalDecision.APPROVED,
          )
          .count()
    )
    quorum_met = approved_count >= access_request.required_approvals

No separate config table is needed: ``required_approvals`` is set at
request-creation time and is immutable once written.

Security notes
--------------
* UNIQUE (request_id, approved_by) on approvals prevents a single approver
  from casting multiple votes on the same request.
* CHECK (end_time > start_time) on access_windows is enforced at the
  database level.
* A UNIQUE constraint on access_windows.request_id guarantees one window
  per approved request.
"""
import enum
import uuid
from datetime import datetime
from typing import Optional, TYPE_CHECKING

if TYPE_CHECKING:
    from database.models.user import User
    from database.models.paper import QuestionPaper

from sqlalchemy import (
    CheckConstraint,
    DateTime,
    Enum,
    ForeignKey,
    Index,
    Integer,
    Text,
    UniqueConstraint,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship
from sqlalchemy import Uuid

from database.base import Base, TimestampMixin


# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------

class RequestType(str, enum.Enum):
    """The kind of access being requested."""
    VIEW = "VIEW"               # Read-only view of paper metadata / status
    RECONSTRUCT = "RECONSTRUCT" # Full reconstruction of the original paper
    EMERGENCY = "EMERGENCY"     # Break-glass; may bypass standard quorum


class RequestStatus(str, enum.Enum):
    """Lifecycle state of an access request."""
    PENDING = "PENDING"       # Awaiting approver votes
    APPROVED = "APPROVED"     # Quorum reached; access authorized
    REJECTED = "REJECTED"     # Quorum failed or majority rejected
    EXPIRED = "EXPIRED"       # Request timed out before quorum was reached
    WITHDRAWN = "WITHDRAWN"   # Requester cancelled the request


class ApprovalDecision(str, enum.Enum):
    """A single approver's vote."""
    APPROVED = "APPROVED"
    REJECTED = "REJECTED"


class WindowStatus(str, enum.Enum):
    """State of a time-bounded access window."""
    SCHEDULED = "SCHEDULED" # Window created; start_time is in the future
    ACTIVE = "ACTIVE"       # Current time is within [start_time, end_time]
    CLOSED = "CLOSED"       # end_time has passed; window ended normally
    REVOKED = "REVOKED"     # Window was terminated early by an administrator


# ---------------------------------------------------------------------------
# Models
# ---------------------------------------------------------------------------

class AccessRequest(Base, TimestampMixin):
    """
    A formal request by a user to access a protected question paper.

    ``required_approvals`` is the quorum threshold captured at submission
    time.  It does not change after creation.
    """
    __tablename__ = "access_requests"

    id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
    )
    paper_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("question_papers.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    requested_by: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("users.id", ondelete="RESTRICT"),
        nullable=False,
        index=True,
        comment="User submitting the access request",
    )
    request_type: Mapped[RequestType] = mapped_column(
        Enum(RequestType, name="requesttype", create_constraint=True),
        nullable=False,
    )
    status: Mapped[RequestStatus] = mapped_column(
        Enum(RequestStatus, name="requeststatus", create_constraint=True),
        nullable=False,
        default=RequestStatus.PENDING,
        server_default=RequestStatus.PENDING.value,
        index=True,
    )
    required_approvals: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
        default=2,
        server_default="2",
        comment="Quorum threshold: how many APPROVED votes are needed",
    )
    reason: Mapped[str] = mapped_column(
        Text,
        nullable=False,
        comment="Mandatory justification provided by the requester",
    )
    decided_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
        comment="Timestamp when status left PENDING (approved, rejected, etc.)",
    )

    # ── relationships ──────────────────────────────────────────────────────
    paper: Mapped["QuestionPaper"] = relationship(
        "QuestionPaper",
        back_populates="access_requests",
    )
    requester: Mapped["User"] = relationship(
        "User",
        back_populates="access_requests",
        foreign_keys=[requested_by],
    )
    approvals: Mapped[list["Approval"]] = relationship(
        "Approval",
        back_populates="request",
        cascade="all, delete-orphan",
    )
    access_window: Mapped[Optional["AccessWindow"]] = relationship(
        "AccessWindow",
        back_populates="request",
        uselist=False,
    )

    # ── indexes ────────────────────────────────────────────────────────────
    __table_args__ = (
        Index("ix_access_requests_paper_status", "paper_id", "status"),
    )

    def __repr__(self) -> str:
        return (
            f"<AccessRequest id={self.id} paper={self.paper_id} "
            f"type={self.request_type} status={self.status}>"
        )


class Approval(Base):
    """
    One approver's vote on an access request.

    UNIQUE (request_id, approved_by) prevents double-voting.
    The security layer counts rows with decision=APPROVED to determine
    whether the quorum threshold has been met.
    """
    __tablename__ = "approvals"

    id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
    )
    request_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("access_requests.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    approved_by: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("users.id", ondelete="RESTRICT"),
        nullable=False,
        index=True,
        comment="Approver who cast this vote",
    )
    decision: Mapped[ApprovalDecision] = mapped_column(
        Enum(ApprovalDecision, name="approvaldecision", create_constraint=True),
        nullable=False,
    )
    reason: Mapped[Optional[str]] = mapped_column(
        Text,
        nullable=True,
        comment="Optional justification for the approver's decision",
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        comment="Timestamp of the vote — immutable once cast",
    )

    # ── relationships ──────────────────────────────────────────────────────
    request: Mapped["AccessRequest"] = relationship(
        "AccessRequest",
        back_populates="approvals",
    )
    approver: Mapped["User"] = relationship(
        "User",
        back_populates="approvals",
        foreign_keys=[approved_by],
    )

    # ── constraints ────────────────────────────────────────────────────────
    __table_args__ = (
        UniqueConstraint(
            "request_id",
            "approved_by",
            name="uq_approvals_request_approver",
        ),
    )

    def __repr__(self) -> str:
        return (
            f"<Approval request={self.request_id} "
            f"by={self.approved_by} decision={self.decision}>"
        )


class AccessWindow(Base, TimestampMixin):
    """
    A time-bounded window during which a paper may be accessed.

    Created only after an access request reaches quorum.
    UNIQUE on ``request_id`` guarantees exactly one window per approval.
    CHECK (end_time > start_time) is enforced at the database level.
    """
    __tablename__ = "access_windows"

    id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
    )
    paper_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("question_papers.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    request_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("access_requests.id", ondelete="CASCADE"),
        nullable=False,
        unique=True,
        comment="One window per approved request — enforced by UNIQUE constraint",
    )
    start_time: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
    )
    end_time: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
    )
    status: Mapped[WindowStatus] = mapped_column(
        Enum(WindowStatus, name="windowstatus", create_constraint=True),
        nullable=False,
        default=WindowStatus.SCHEDULED,
        server_default=WindowStatus.SCHEDULED.value,
        index=True,
    )

    # ── relationships ──────────────────────────────────────────────────────
    paper: Mapped["QuestionPaper"] = relationship(
        "QuestionPaper",
        back_populates="access_windows",
    )
    request: Mapped["AccessRequest"] = relationship(
        "AccessRequest",
        back_populates="access_window",
    )

    # ── constraints and indexes ────────────────────────────────────────────
    __table_args__ = (
        CheckConstraint(
            "end_time > start_time",
            name="ck_access_windows_end_after_start",
        ),
        Index("ix_access_windows_paper_status", "paper_id", "status"),
        Index("ix_access_windows_time_range", "start_time", "end_time"),
    )

    def __repr__(self) -> str:
        return (
            f"<AccessWindow paper={self.paper_id} "
            f"status={self.status} [{self.start_time} → {self.end_time}]>"
        )

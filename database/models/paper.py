"""
TrustGuard — QuestionPaper ORM model and status lifecycle enum.

Table
-----
question_papers — metadata record for each protected examination paper.

Lifecycle
---------
CREATED → PROTECTED → FRAGMENTED → AWAITING_APPROVAL
       → AUTHORIZED → ACTIVE → EXPIRED | COMPLETED

Security notes
--------------
* No question-paper content is ever stored in this table.
* ``integrity_hash`` is a SHA-256/512 hex digest of the content manifest
  produced by the security/crypto layer.  The database merely persists it;
  verification logic lives in the security module.
* ``total_fragments`` is populated after fragmentation so the security layer
  can assert all shards are present before reconstruction.
"""
import enum
import uuid
from datetime import datetime
from typing import Optional, TYPE_CHECKING

if TYPE_CHECKING:
    from database.models.user import User
    from database.models.fragment import PaperFragment
    from database.models.access import AccessRequest, AccessWindow

from sqlalchemy import Enum, ForeignKey, Index, Integer, String, DateTime
from sqlalchemy.orm import Mapped, mapped_column, relationship
from sqlalchemy import Uuid

from database.base import Base, TimestampMixin


# ---------------------------------------------------------------------------
# Status lifecycle enum
# ---------------------------------------------------------------------------

class PaperStatus(str, enum.Enum):
    """
    Ordered lifecycle states for a question paper.

    CREATED          — Record created; paper not yet encrypted.
    PROTECTED        — Security layer has encrypted the paper content.
    FRAGMENTED       — Encrypted content has been sharded into fragments.
    AWAITING_APPROVAL— At least one access request is pending quorum.
    AUTHORIZED       — Quorum reached; paper may be scheduled for access.
    ACTIVE           — Access window is currently open.
    EXPIRED          — Access window closed without explicit completion.
    COMPLETED        — Paper lifecycle ended normally.
    """
    CREATED = "CREATED"
    PROTECTED = "PROTECTED"
    FRAGMENTED = "FRAGMENTED"
    AWAITING_APPROVAL = "AWAITING_APPROVAL"
    AUTHORIZED = "AUTHORIZED"
    ACTIVE = "ACTIVE"
    EXPIRED = "EXPIRED"
    COMPLETED = "COMPLETED"


# ---------------------------------------------------------------------------
# Model
# ---------------------------------------------------------------------------

class QuestionPaper(Base, TimestampMixin):
    """
    Metadata record for an examination question paper.

    Content is NEVER stored here — only metadata, status, and integrity
    references needed to orchestrate the security lifecycle.
    """
    __tablename__ = "question_papers"

    id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
    )
    exam_identifier: Mapped[str] = mapped_column(
        String(100),
        nullable=False,
        index=True,
        comment="Human-readable exam code, e.g. 'GATE-2026-CS'",
    )
    paper_name: Mapped[str] = mapped_column(
        String(255),
        nullable=False,
        comment="Descriptive title, e.g. 'Computer Science Paper I'",
    )
    status: Mapped[PaperStatus] = mapped_column(
        Enum(PaperStatus, name="paperstatus", create_constraint=True),
        nullable=False,
        default=PaperStatus.CREATED,
        server_default=PaperStatus.CREATED.value,
        index=True,
    )
    created_by: Mapped[Optional[uuid.UUID]] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("users.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
        comment="User who registered the paper record",
    )

    # ── Security / lifecycle timestamps ───────────────────────────────────
    protected_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
        comment="Set by the security layer when status transitions to PROTECTED",
    )
    fragmented_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
        comment="Set by the security layer when status transitions to FRAGMENTED",
    )
    completed_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
        comment="Set when status transitions to COMPLETED or EXPIRED",
    )

    # ── Integrity metadata (populated by security layer) ─────────────────
    integrity_hash: Mapped[Optional[str]] = mapped_column(
        String(128),
        nullable=True,
        comment="Hex-encoded SHA-256/512 digest of the original content manifest",
    )
    total_fragments: Mapped[Optional[int]] = mapped_column(
        Integer,
        nullable=True,
        comment="Number of shards produced during fragmentation",
    )

    # ── relationships ──────────────────────────────────────────────────────
    creator: Mapped[Optional["User"]] = relationship(
        "User",
        back_populates="question_papers",
        foreign_keys=[created_by],
    )
    fragments: Mapped[list["PaperFragment"]] = relationship(
        "PaperFragment",
        back_populates="paper",
        cascade="all, delete-orphan",
    )
    access_requests: Mapped[list["AccessRequest"]] = relationship(
        "AccessRequest",
        back_populates="paper",
        cascade="all, delete-orphan",
    )
    access_windows: Mapped[list["AccessWindow"]] = relationship(
        "AccessWindow",
        back_populates="paper",
        cascade="all, delete-orphan",
    )

    # ── composite indexes ──────────────────────────────────────────────────
    __table_args__ = (
        Index("ix_question_papers_status_exam", "status", "exam_identifier"),
    )

    def __repr__(self) -> str:
        return f"<QuestionPaper id={self.id} exam={self.exam_identifier!r} status={self.status}>"

"""
TrustGuard — PaperFragment ORM model and status enum.

Table
-----
paper_fragments — one row per encrypted shard of a protected question paper.

Security notes
--------------
* ``fragment_data`` is raw ciphertext (BYTEA).  Plaintext content is NEVER
  written to this column — the security/crypto layer must encrypt before
  calling the ORM.
* ``integrity_hash`` is the hash of this shard's ciphertext, allowing the
  security layer to detect tampering without decrypting.
* The UNIQUE constraint on (paper_id, fragment_index) ensures no duplicate
  shard indices can exist for the same paper — a prerequisite for
  deterministic reconstruction.
"""
import enum
import uuid
from typing import Optional, TYPE_CHECKING

if TYPE_CHECKING:
    from database.models.paper import QuestionPaper

from sqlalchemy import Enum, ForeignKey, Index, LargeBinary, SmallInteger, String, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column, relationship
from sqlalchemy import Uuid

from database.base import Base, TimestampMixin


# ---------------------------------------------------------------------------
# Status enum
# ---------------------------------------------------------------------------

class FragmentStatus(str, enum.Enum):
    """
    Lifecycle state of a single paper shard.

    PENDING   — Fragment record created; data not yet written.
    STORED    — Encrypted data successfully persisted.
    CORRUPTED — Integrity check failed; shard should not be used.
    DELETED   — Shard has been securely erased (soft-delete marker).
    """
    PENDING = "PENDING"
    STORED = "STORED"
    CORRUPTED = "CORRUPTED"
    DELETED = "DELETED"


# ---------------------------------------------------------------------------
# Model
# ---------------------------------------------------------------------------

class PaperFragment(Base, TimestampMixin):
    """
    One encrypted shard of a question paper.

    ``fragment_data`` holds the raw ciphertext bytes produced by the
    security layer.  This column must never contain plaintext.
    """
    __tablename__ = "paper_fragments"

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
    fragment_index: Mapped[int] = mapped_column(
        SmallInteger,
        nullable=False,
        comment="Zero-based shard index; (paper_id, fragment_index) must be unique",
    )
    fragment_data: Mapped[bytes] = mapped_column(
        LargeBinary,
        nullable=False,
        comment="Raw ciphertext bytes — NEVER plaintext question-paper content",
    )
    integrity_hash: Mapped[str] = mapped_column(
        String(128),
        nullable=False,
        comment="Hex-encoded hash of fragment_data for tamper detection",
    )
    status: Mapped[FragmentStatus] = mapped_column(
        Enum(FragmentStatus, name="fragmentstatus", create_constraint=True),
        nullable=False,
        default=FragmentStatus.PENDING,
        server_default=FragmentStatus.PENDING.value,
    )

    # ── relationships ──────────────────────────────────────────────────────
    paper: Mapped["QuestionPaper"] = relationship(
        "QuestionPaper",
        back_populates="fragments",
    )

    # ── constraints and indexes ────────────────────────────────────────────
    __table_args__ = (
        UniqueConstraint(
            "paper_id",
            "fragment_index",
            name="uq_paper_fragments_paper_index",
        ),
        # Note: ix_paper_fragments_paper_id is created via index=True on paper_id column above
    )

    def __repr__(self) -> str:
        return (
            f"<PaperFragment paper={self.paper_id} "
            f"index={self.fragment_index} status={self.status}>"
        )

"""
TrustGuard — User, Role, and UserRole ORM models.

Tables
------
users       — all system principals: officers, admins, system service accounts.
roles       — named permission groups (ADMIN, OFFICER, APPROVER, AUDITOR, SYSTEM).
user_roles  — many-to-many assignment with grant provenance (who granted the role).

Security notes
--------------
* ``password_hash`` stores only the result of a strong KDF (bcrypt / Argon2id).
  Plaintext passwords are NEVER stored.
* ``is_system`` flags non-human service accounts so audit logs can distinguish
  automated actions from user-initiated ones.
* ``granted_by`` in ``user_roles`` maintains a chain of custody for role grants;
  SET NULL on delete so we don't lose role records if the granter is removed.
"""
import uuid
from datetime import datetime
from typing import Optional, TYPE_CHECKING

if TYPE_CHECKING:
    from database.models.paper import QuestionPaper
    from database.models.access import AccessRequest, Approval
    from database.models.audit import AuditLog, ThreatEvent

from sqlalchemy import Boolean, DateTime, ForeignKey, String, Text, func
from sqlalchemy.orm import Mapped, mapped_column, relationship
from sqlalchemy import Uuid

from database.base import Base, TimestampMixin, _utcnow


class User(Base, TimestampMixin):
    """
    A human or service account that can interact with the TrustGuard system.
    """
    __tablename__ = "users"

    id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
    )
    email: Mapped[str] = mapped_column(
        String(255),
        unique=True,
        nullable=False,
        index=True,
        comment="Primary login identifier — must be unique across all users",
    )
    password_hash: Mapped[str] = mapped_column(
        String(255),
        nullable=False,
        comment="bcrypt / Argon2id hash — NEVER store plaintext",
    )
    full_name: Mapped[str] = mapped_column(String(255), nullable=False)
    is_active: Mapped[bool] = mapped_column(
        Boolean,
        nullable=False,
        default=True,
        server_default="true",
        comment="Inactive users cannot authenticate or perform any action",
    )
    is_system: Mapped[bool] = mapped_column(
        Boolean,
        nullable=False,
        default=False,
        server_default="false",
        comment="True for non-human service accounts (e.g. crypto engine)",
    )

    # ── relationships ──────────────────────────────────────────────────────
    user_roles: Mapped[list["UserRole"]] = relationship(
        "UserRole",
        back_populates="user",
        foreign_keys="UserRole.user_id",
        cascade="all, delete-orphan",
    )
    question_papers: Mapped[list["QuestionPaper"]] = relationship(
        "QuestionPaper",
        back_populates="creator",
        foreign_keys="QuestionPaper.created_by",
    )
    access_requests: Mapped[list["AccessRequest"]] = relationship(
        "AccessRequest",
        back_populates="requester",
        foreign_keys="AccessRequest.requested_by",
    )
    approvals: Mapped[list["Approval"]] = relationship(
        "Approval",
        back_populates="approver",
        foreign_keys="Approval.approved_by",
    )
    audit_logs: Mapped[list["AuditLog"]] = relationship(
        "AuditLog",
        back_populates="actor",
        foreign_keys="AuditLog.actor_id",
    )
    threat_events_as_actor: Mapped[list["ThreatEvent"]] = relationship(
        "ThreatEvent",
        back_populates="actor",
        foreign_keys="ThreatEvent.actor_id",
    )
    threat_events_resolved: Mapped[list["ThreatEvent"]] = relationship(
        "ThreatEvent",
        back_populates="resolver",
        foreign_keys="ThreatEvent.resolved_by",
    )

    def __repr__(self) -> str:
        return f"<User id={self.id} email={self.email!r}>"


class Role(Base):
    """
    A named permission group.  Canonical values: ADMIN, OFFICER, APPROVER,
    AUDITOR, SYSTEM.  Enforced at the application layer, not as a DB ENUM,
    so new roles can be added without a schema migration.
    """
    __tablename__ = "roles"

    id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
    )
    name: Mapped[str] = mapped_column(
        String(50),
        unique=True,
        nullable=False,
        comment="Canonical role name: ADMIN | OFFICER | APPROVER | AUDITOR | SYSTEM",
    )
    description: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    # ── relationships ──────────────────────────────────────────────────────
    user_roles: Mapped[list["UserRole"]] = relationship(
        "UserRole",
        back_populates="role",
    )

    def __repr__(self) -> str:
        return f"<Role name={self.name!r}>"


class UserRole(Base):
    """
    Junction table: assigns roles to users.

    Composite primary key (user_id, role_id) prevents duplicate assignments.
    ``granted_by`` records the admin who performed the grant for audit purposes.
    """
    __tablename__ = "user_roles"

    user_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("users.id", ondelete="CASCADE"),
        primary_key=True,
    )
    role_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("roles.id", ondelete="CASCADE"),
        primary_key=True,
    )
    granted_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        default=_utcnow,
        nullable=False,
    )
    granted_by: Mapped[Optional[uuid.UUID]] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("users.id", ondelete="SET NULL"),
        nullable=True,
        comment="Which admin granted this role; NULL if seeded or granter was deleted",
    )

    # ── relationships ──────────────────────────────────────────────────────
    user: Mapped["User"] = relationship(
        "User",
        back_populates="user_roles",
        foreign_keys=[user_id],
    )
    role: Mapped["Role"] = relationship("Role", back_populates="user_roles")
    granter: Mapped[Optional["User"]] = relationship(
        "User",
        foreign_keys=[granted_by],
    )

    def __repr__(self) -> str:
        return f"<UserRole user={self.user_id} role={self.role_id}>"

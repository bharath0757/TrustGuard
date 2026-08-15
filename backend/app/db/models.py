"""SQLAlchemy database models for TrustGuard metadata and audit persistence.

CRITICAL SECURITY CONSTRAINT:
No raw question paper content, unencrypted chunks, or raw master decryption keys
may ever be defined in or stored via these ORM models.
"""

from datetime import datetime, timezone
import uuid
from sqlalchemy import Column, DateTime, ForeignKey, Integer, String, Text
from sqlalchemy.orm import declarative_base, relationship

Base = declarative_base()


class User(Base):
    __tablename__ = "users"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    username = Column(String(50), unique=True, nullable=False, index=True)
    email = Column(String(100), unique=True, nullable=False, index=True)
    hashed_password = Column(String(255), nullable=False)
    role = Column(String(20), nullable=False)  # ADMIN, EXAM_SETTER, KEY_GUARDIAN, EXAM_CENTER, AUDITOR
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))

    # Relationships
    exams_created = relationship("Exam", back_populates="creator", lazy="selectin")
    guardian_assignments = relationship("KeyGuardianAssignment", back_populates="guardian", lazy="selectin")
    consensus_approvals = relationship("ConsensusApproval", back_populates="guardian", lazy="selectin")


class Exam(Base):
    __tablename__ = "exams"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    title = Column(String(150), nullable=False)
    course_code = Column(String(50), nullable=False, index=True)
    
    # Lifecycle states: DRAFT, EPHEMERAL_PAYLOAD_STAGED, CONSENSUS_PENDING, UNLOCKED, COMPLETED, EXPIRED, REVOKED
    status = Column(String(30), nullable=False, default="DRAFT", index=True)
    
    scheduled_start = Column(DateTime, nullable=False)
    scheduled_end = Column(DateTime, nullable=False)
    
    # Threshold Cryptography Quorum configuration (k-of-n)
    required_quorum = Column(Integer, nullable=False, default=2)  # k
    total_guardians = Column(Integer, nullable=False, default=3)  # n
    
    # Non-sensitive verification metadata (SHA-256 payload integrity hash ONLY)
    encrypted_payload_hash = Column(String(64), nullable=True)
    
    created_by = Column(String(36), ForeignKey("users.id"), nullable=False)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    updated_at = Column(DateTime, default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc))

    # Relationships
    creator = relationship("User", back_populates="exams_created", lazy="selectin")
    guardians = relationship("KeyGuardianAssignment", back_populates="exam", lazy="selectin", cascade="all, delete-orphan")
    approvals = relationship("ConsensusApproval", back_populates="exam", lazy="selectin", cascade="all, delete-orphan")


class KeyGuardianAssignment(Base):
    __tablename__ = "key_guardian_assignments"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    exam_id = Column(String(36), ForeignKey("exams.id"), nullable=False)
    guardian_id = Column(String(36), ForeignKey("users.id"), nullable=False)
    public_key_fingerprint = Column(String(64), nullable=False)
    assigned_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))

    # Relationships
    exam = relationship("Exam", back_populates="guardians", lazy="selectin")
    guardian = relationship("User", back_populates="guardian_assignments", lazy="selectin")


class ConsensusApproval(Base):
    __tablename__ = "consensus_approvals"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    exam_id = Column(String(36), ForeignKey("exams.id"), nullable=False)
    guardian_id = Column(String(36), ForeignKey("users.id"), nullable=False)
    approval_hash = Column(String(128), nullable=False)  # Cryptographic approval signature token
    approved_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))

    # Relationships
    exam = relationship("Exam", back_populates="approvals", lazy="selectin")
    guardian = relationship("User", back_populates="consensus_approvals", lazy="selectin")


class AuditEvent(Base):
    __tablename__ = "audit_events"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    exam_id = Column(String(36), nullable=True, index=True)
    actor_id = Column(String(36), nullable=True, index=True)
    action = Column(String(100), nullable=False, index=True)
    ip_address = Column(String(45), nullable=True)
    details_json = Column(Text, nullable=True)
    timestamp = Column(DateTime, default=lambda: datetime.now(timezone.utc), index=True)

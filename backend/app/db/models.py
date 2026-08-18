"""SQLAlchemy database models for TrustGuard metadata and audit persistence.

CRITICAL SECURITY CONSTRAINT:
No raw question paper content, unencrypted chunks, or raw master decryption keys
may ever be defined in or stored via these ORM models.
"""

from datetime import datetime, timezone
import uuid
from sqlalchemy import Column, DateTime, ForeignKey, Integer, String, Text, UniqueConstraint
from sqlalchemy.orm import declarative_base, relationship

Base = declarative_base()


class User(Base):
    __tablename__ = "users"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    username = Column(String(50), unique=True, nullable=False, index=True)
    email = Column(String(100), unique=True, nullable=False, index=True)
    hashed_password = Column(String(255), nullable=False)
    role = Column(String(20), nullable=False)  # ADMIN, EXAM_SETTER, KEY_GUARDIAN, EXAM_CENTER, AUDITOR, STUDENT, ATTACKER
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))

    # Relationships
    exams_created = relationship("Exam", back_populates="creator", lazy="selectin")
    guardian_assignments = relationship("KeyGuardianAssignment", back_populates="guardian", lazy="selectin")
    consensus_approvals = relationship("ConsensusApproval", back_populates="guardian", lazy="selectin")
    student_registrations = relationship("ExamStudent", back_populates="student", lazy="selectin")
    student_sessions = relationship("StudentExamSession", back_populates="student", lazy="selectin")


class UploadedPaper(Base):
    """Metadata record for an uploaded question paper asset.

    Content is NEVER stored here — only metadata, status, and integrity
    references needed to track the paper through the security lifecycle.
    """
    __tablename__ = "uploaded_papers"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    paper_name = Column(String(255), nullable=False)
    description = Column(Text, nullable=True)
    original_filename = Column(String(255), nullable=False)
    file_size = Column(Integer, nullable=True, comment="File size in bytes")
    file_hash = Column(String(128), nullable=True, comment="SHA-256 hash of uploaded file content")

    # Security lifecycle status
    encryption_status = Column(String(30), nullable=False, default="PENDING")   # PENDING, ENCRYPTED, FAILED
    integrity_status = Column(String(30), nullable=False, default="PENDING")    # PENDING, VERIFIED, FAILED
    fragment_status = Column(String(30), nullable=False, default="PENDING")     # PENDING, FRAGMENTED, FAILED
    protection_status = Column(String(30), nullable=False, default="UNPROTECTED")  # UNPROTECTED, PROTECTED, FAILED
    integrity_hash = Column(String(128), nullable=True, comment="SHA-256 integrity hash of encrypted content manifest")
    total_fragments = Column(Integer, nullable=True)

    created_by = Column(String(36), ForeignKey("users.id"), nullable=True)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    protected_at = Column(DateTime, nullable=True)
    staged_at = Column(DateTime, nullable=True)
    expires_at = Column(DateTime, nullable=True)
    released_at = Column(DateTime, nullable=True)
    destroyed_at = Column(DateTime, nullable=True)
    status = Column(String(30), nullable=False, default="DRAFT")  # DRAFT, STAGED, AWAITING_APPROVAL, AUTHORIZED, RELEASED, EXPIRED, DESTROYED
    encrypted_payload_hex = Column(Text, nullable=True, comment="Encrypted AES-GCM payload in hex format")

    # Relationships
    creator = relationship("User", foreign_keys=[created_by], lazy="selectin")
    exams = relationship("Exam", back_populates="paper", lazy="selectin")


class Exam(Base):
    __tablename__ = "exams"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    title = Column(String(150), nullable=False)
    course_code = Column(String(50), nullable=False, index=True)
    description = Column(Text, nullable=True)

    # Link to the protected question paper asset
    paper_id = Column(String(36), ForeignKey("uploaded_papers.id"), nullable=True, index=True)

    # Lifecycle states: DRAFT, READY, AUTHORIZED, EPHEMERAL_PAYLOAD_STAGED,
    #   CONSENSUS_PENDING, UNLOCKED, LIVE, COMPLETED, EXPIRED, REVOKED, CANCELLED
    status = Column(String(30), nullable=False, default="DRAFT", index=True)

    scheduled_start = Column(DateTime, nullable=False)
    scheduled_end = Column(DateTime, nullable=False)
    duration_minutes = Column(Integer, nullable=False, default=60)

    # Threshold Cryptography Quorum configuration (k-of-n)
    required_quorum = Column(Integer, nullable=False, default=2)  # k
    total_guardians = Column(Integer, nullable=False, default=3)  # n

    # Non-sensitive verification metadata (SHA-256 payload integrity hash ONLY)
    encrypted_payload_hash = Column(String(64), nullable=True)

    # Exam session timestamps (server-authoritative)
    started_at = Column(DateTime, nullable=True, comment="Server timestamp when exam went LIVE")
    ended_at = Column(DateTime, nullable=True, comment="Server timestamp when exam was COMPLETED")

    created_by = Column(String(36), ForeignKey("users.id"), nullable=False)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    updated_at = Column(DateTime, default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc))

    # Relationships
    creator = relationship("User", back_populates="exams_created", lazy="selectin")
    paper = relationship("UploadedPaper", back_populates="exams", lazy="selectin")
    guardians = relationship("KeyGuardianAssignment", back_populates="exam", lazy="selectin", cascade="all, delete-orphan")
    students = relationship("ExamStudent", back_populates="exam", lazy="selectin", cascade="all, delete-orphan")
    approvals = relationship("ConsensusApproval", back_populates="exam", lazy="selectin", cascade="all, delete-orphan")
    sessions = relationship("ExamSession", back_populates="exam", lazy="selectin", cascade="all, delete-orphan")
    questions = relationship("Question", back_populates="exam", lazy="selectin", cascade="all, delete-orphan")
    student_sessions = relationship("StudentExamSession", back_populates="exam", lazy="selectin", cascade="all, delete-orphan")


class Question(Base):
    """Clean structured question model.

    CRITICAL SECURITY CONSTRAINT:
    correct_answer is stored securely server-side only and MUST NEVER
    be sent to student clients.
    """
    __tablename__ = "questions"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    exam_id = Column(String(36), ForeignKey("exams.id", ondelete="CASCADE"), nullable=False, index=True)
    question_number = Column(Integer, nullable=False, default=1)
    question_text = Column(Text, nullable=False)
    options = Column(Text, nullable=False)  # JSON-serialized list of option objects: [{"key": "A", "text": "..."}, ...]
    correct_answer = Column(String(50), nullable=False)  # Stored securely server-side only!
    marks = Column(Integer, nullable=False, default=1)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))

    # Relationships
    exam = relationship("Exam", back_populates="questions", lazy="selectin")


class ExamStudent(Base):
    __tablename__ = "exam_students"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    exam_id = Column(String(36), ForeignKey("exams.id"), nullable=False, index=True)
    student_id = Column(String(36), ForeignKey("users.id"), nullable=False, index=True)
    registration_status = Column(String(20), nullable=False, default="REGISTERED")
    registered_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))

    # Relationships
    exam = relationship("Exam", back_populates="students", lazy="selectin")
    student = relationship("User", back_populates="student_registrations", lazy="selectin")


class StudentExamSession(Base):
    """Individual candidate examination session.

    Enforces server-authoritative timer and tracks real candidate exam progress.
    States: NOT_STARTED, IN_PROGRESS, SUBMITTED, EXPIRED
    """
    __tablename__ = "student_exam_sessions"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    exam_id = Column(String(36), ForeignKey("exams.id", ondelete="CASCADE"), nullable=False, index=True)
    student_id = Column(String(36), ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)
    status = Column(String(20), nullable=False, default="NOT_STARTED", index=True)  # NOT_STARTED, IN_PROGRESS, SUBMITTED, EXPIRED

    started_at = Column(DateTime, nullable=True)
    expires_at = Column(DateTime, nullable=True)
    submitted_at = Column(DateTime, nullable=True)
    score = Column(Integer, nullable=True)
    max_score = Column(Integer, nullable=True)

    # JSON map of question_id -> student chosen option key (e.g. {"Q1_ID": "A", "Q2_ID": "C"})
    answers_json = Column(Text, nullable=True, default="{}")
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))

    # Relationships
    exam = relationship("Exam", back_populates="student_sessions", lazy="selectin")
    student = relationship("User", back_populates="student_sessions", lazy="selectin")

    __table_args__ = (
        UniqueConstraint("exam_id", "student_id", name="uq_student_exam_session"),
    )


class ExamSession(Base):
    """An active exam session tracking live state and candidate activity.

    Created when an exam transitions to LIVE. Closed when exam ends.
    Candidate sessions are simulated for the prototype.
    """
    __tablename__ = "exam_sessions"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    exam_id = Column(String(36), ForeignKey("exams.id"), nullable=False, index=True)

    # Session state: ACTIVE, COMPLETED, CANCELLED
    state = Column(String(20), nullable=False, default="ACTIVE")

    started_at = Column(DateTime, nullable=False, default=lambda: datetime.now(timezone.utc))
    ended_at = Column(DateTime, nullable=True)

    # Simulated candidate/session counters
    active_sessions = Column(Integer, nullable=False, default=0)
    total_sessions = Column(Integer, nullable=False, default=0)

    # Aggregated security state: NORMAL, WARNING, CRITICAL
    security_state = Column(String(20), nullable=False, default="NORMAL")

    # Relationships
    exam = relationship("Exam", back_populates="sessions", lazy="selectin")


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

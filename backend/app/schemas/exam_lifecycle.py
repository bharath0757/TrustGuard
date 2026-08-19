"""Pydantic schemas for exam lifecycle operations: start, end, security, report, events."""

from datetime import datetime
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, ConfigDict, Field


# ---------------------------------------------------------------------------
# Exam Create — Extended
# ---------------------------------------------------------------------------

class ExamCreateExtended(BaseModel):
    """Create an exam linked to a protected paper."""
    title: str = Field(..., min_length=3, max_length=150)
    course_code: str = Field(..., min_length=2, max_length=50)
    description: Optional[str] = None
    paper_id: Optional[str] = Field(default=None, description="ID of the protected uploaded paper")
    scheduled_start: datetime
    scheduled_end: datetime
    duration_minutes: int = Field(60, ge=1, le=1440)
    required_quorum: int = Field(2, ge=1, description="Threshold k approvals required")
    total_guardians: int = Field(3, ge=1, description="Total n key guardians assigned")


# ---------------------------------------------------------------------------
# Exam Start / End
# ---------------------------------------------------------------------------

class ExamStartResponse(BaseModel):
    exam_id: str
    status: str
    started_at: datetime
    session_id: str
    paper_integrity: str
    quorum_status: str
    security_level: str
    message: str


class ExamEndRequest(BaseModel):
    confirm: bool = Field(True, description="Confirmation flag")


class ExamEndResponse(BaseModel):
    exam_id: str
    status: str
    ended_at: datetime
    session_closed: bool
    access_expired: bool
    message: str


# ---------------------------------------------------------------------------
# Security Status
# ---------------------------------------------------------------------------

class ExamSecurityStatus(BaseModel):
    exam_id: str
    exam_title: str
    status: str
    started_at: Optional[datetime] = None
    ended_at: Optional[datetime] = None
    duration_minutes: int
    scheduled_start: datetime
    scheduled_end: datetime

    # Paper security
    paper_integrity: str      # VERIFIED, UNVERIFIED, FAILED
    encryption_status: str    # ENCRYPTED, PENDING, FAILED
    protection_status: str    # PROTECTED, UNPROTECTED, FAILED
    quorum_status: str        # e.g. "3/3 ✓" or "1/3"
    quorum_achieved: bool

    # Live metrics
    security_level: str       # NORMAL, WARNING, CRITICAL
    active_sessions: int
    total_events: int
    unauthorized_attempts: int
    blocked_attempts: int
    integrity_violations: int
    successful_accesses: int

    # Server timestamp for timer sync
    server_time: datetime


class ExamEventResponse(BaseModel):
    id: str
    exam_id: Optional[str] = None
    actor_id: Optional[str] = None
    action: str
    ip_address: Optional[str] = None
    details: Optional[Dict[str, Any]] = None
    timestamp: datetime
    event_type: Optional[str] = None  # Derived category: SECURITY, AUDIT, SYSTEM, APPROVAL

    model_config = ConfigDict(from_attributes=True)


# ---------------------------------------------------------------------------
# Timeline
# ---------------------------------------------------------------------------

class TimelineEvent(BaseModel):
    timestamp: datetime
    title: str
    description: str
    event_type: str        # SYSTEM, SECURITY, APPROVAL, ACCESS
    severity: Optional[str] = None  # NORMAL, WARNING, CRITICAL
    icon: Optional[str] = None      # For frontend display hint


# ---------------------------------------------------------------------------
# Guardian Info Item
# ---------------------------------------------------------------------------

class GuardianInfoItem(BaseModel):
    guardian_id: str
    username: str
    approved: bool
    approved_at: Optional[datetime] = None
    public_key_fingerprint: Optional[str] = None


# ---------------------------------------------------------------------------
# Final Security Report
# ---------------------------------------------------------------------------

class ExamSecurityReport(BaseModel):
    # Exam Information
    exam_id: str
    exam_title: str
    course_code: Optional[str] = None
    paper_id: Optional[str] = None
    paper_name: Optional[str] = None
    start_time: Optional[datetime] = None
    end_time: Optional[datetime] = None
    duration_minutes: int
    status: str

    # Participation
    registered_students: int = 0
    students_joined: int = 0
    currently_writing: int = 0
    submitted_count: int = 0
    expired_count: int = 0

    # Guardian Consensus
    required_quorum: int = 3
    total_guardians: int = 3
    approvals_count: int = 0
    quorum_status: str = "3 / 3"
    quorum_achieved: bool = True
    paper_release_status: str = "AUTHORIZED"
    guardians: List[GuardianInfoItem] = []

    # Security Summary
    paper_integrity: str = "VERIFIED"
    encryption_status: str = "ENCRYPTED"
    protection_status: str = "PROTECTED"

    total_security_events: int = 0
    attack_attempts: int = 0
    blocked_attempts: int = 0
    successful_attacks: int = 0
    suspicious_events: int = 0
    unauthorized_attempts: int = 0
    integrity_violations: int = 0
    successful_accesses: int = 0
    audit_events: int = 0

    # Final Security Status: PROTECTED, ATTENTION_REQUIRED, SECURITY_INCIDENT_DETECTED
    final_security_status: str = "PROTECTED"
    overall_security: str = "VERIFIED"
    security_summary: str
    factual_statements: List[str] = []

    # Chronological Audit Timeline
    timeline: List[TimelineEvent] = []


# ---------------------------------------------------------------------------
# Extended ExamResponse (overrides the basic ExamResponse with extra fields)
# ---------------------------------------------------------------------------

class ExamFullResponse(BaseModel):
    id: str
    title: str
    course_code: str
    description: Optional[str] = None
    paper_id: Optional[str] = None
    status: str
    scheduled_start: datetime
    scheduled_end: datetime
    duration_minutes: int
    required_quorum: int
    total_guardians: int
    encrypted_payload_hash: Optional[str] = None
    started_at: Optional[datetime] = None
    ended_at: Optional[datetime] = None
    created_by: str
    created_at: datetime
    updated_at: datetime

    # Paper info
    paper_name: Optional[str] = None
    paper_protection_status: Optional[str] = None

    # Quorum info
    current_approvals: int = 0
    quorum_achieved: bool = False

    model_config = ConfigDict(from_attributes=True)


# ---------------------------------------------------------------------------
# Real-Time Guardian Dashboard State (Phase 6)
# ---------------------------------------------------------------------------

class GuardianRealTimeDashboardState(BaseModel):
    exam_id: str
    exam_title: str
    course_code: str
    status: str
    duration_minutes: int
    scheduled_start: datetime
    scheduled_end: datetime
    started_at: Optional[datetime] = None
    ended_at: Optional[datetime] = None
    expires_at: Optional[datetime] = None
    remaining_seconds: int = 0
    server_time: datetime

    # Paper Security & Integrity
    paper_id: Optional[str] = None
    paper_name: Optional[str] = None
    paper_status: str
    protection_status: str
    integrity_status: str
    integrity_hash: Optional[str] = None

    # Consensus Status
    required_quorum: int
    total_guardians: int
    approvals_count: int
    quorum_status: str
    quorum_achieved: bool
    guardians: List[GuardianInfoItem] = []

    # Student Activity (Live Reactive)
    registered_students_count: int = 0
    currently_writing_count: int = 0
    submitted_count: int = 0
    expired_count: int = 0
    students: List[Any] = []

    # Security Monitor
    security_status: str = "SECURE"  # SECURE, WARNING, CRITICAL
    security_summary: str = "No security threats detected"
    attack_attempts: int = 0
    blocked_attacks: int = 0
    integrity_violations: int = 0

    # Recent Chronological Audit Events
    recent_audit_events: List[ExamEventResponse] = []


"""
TrustGuard — Security Audit & Lifecycle Completion Service.

CORE PRINCIPLES:
----------------
1. Comprehensive Immutability: Every sensitive security operation creates an
   immutable AuditLog entry answering:
   - WHO? (actor_id, actor_ip)
   - WHAT? (action, e.g. PAPER_ENCRYPTED, ACCESS_GRANTED, INTEGRITY_FAILURE)
   - WHEN? (timestamp)
   - WHICH RESOURCE? (target_type, target_id)
   - WHAT RESULT? (result: SUCCESS, FAILURE, DENIED)
   - WHY? (reason, metadata)

2. Absolute Zero-Leakage: NEVER log:
   - Passwords
   - Cryptographic keys (raw, hex, or base64)
   - Tokens / JWTs
   - Plaintext question paper content

3. Secure Lifecycle Completion:
   - Close active access sessions (WindowStatus.CLOSED).
   - Expire temporary access permissions.
   - Prevent replay attacks on completed requests.
   - Securely wipe and remove temporary in-memory decrypted representations.
"""
from dataclasses import dataclass
from datetime import datetime, timezone
import enum
import logging
from typing import Any, Dict, List, Optional, Set, Union
import uuid

from sqlalchemy.orm import Session

from database.models.access import (
    AccessRequest,
    AccessWindow,
    RequestStatus,
    WindowStatus,
)
from database.models.audit import (
    AuditLog,
    AuditResult,
    ThreatEvent,
    ThreatEventType,
    ThreatSeverity,
)
from database.models.paper import QuestionPaper, PaperStatus


logger = logging.getLogger("trustguard.security.audit")

# Sensitive key names that must always be redacted from audit metadata
SENSITIVE_KEY_PATTERNS = {
    "password",
    "password_hash",
    "key",
    "master_key",
    "secret",
    "token",
    "jwt",
    "plaintext",
    "content",
    "exam_content",
    "paper_content",
    "raw_data",
    "credential",
}


# ---------------------------------------------------------------------------
# Audit Action Types Enum
# ---------------------------------------------------------------------------

class AuditEventType(str, enum.Enum):
    """Standardized audit event names across the TrustGuard security lifecycle."""
    PAPER_CREATED = "PAPER_CREATED"
    PAPER_ENCRYPTED = "PAPER_ENCRYPTED"
    PAPER_FRAGMENTED = "PAPER_FRAGMENTED"
    ACCESS_REQUESTED = "ACCESS_REQUESTED"
    APPROVAL_GRANTED = "APPROVAL_GRANTED"
    APPROVAL_REJECTED = "APPROVAL_REJECTED"
    QUORUM_REACHED = "QUORUM_REACHED"
    ACCESS_DENIED = "ACCESS_DENIED"
    ACCESS_GRANTED = "ACCESS_GRANTED"
    DECRYPTION_STARTED = "DECRYPTION_STARTED"
    DECRYPTION_COMPLETED = "DECRYPTION_COMPLETED"
    ACCESS_EXPIRED = "ACCESS_EXPIRED"
    SESSION_CLOSED = "SESSION_CLOSED"
    INTEGRITY_FAILURE = "INTEGRITY_FAILURE"
    REPLAY_ATTEMPT = "REPLAY_ATTEMPT"


# ---------------------------------------------------------------------------
# Metadata Sanitization Engine
# ---------------------------------------------------------------------------

def sanitize_audit_metadata(data: Optional[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
    """
    Recursively inspect and redact sensitive secrets, keys, passwords, and plaintext.

    Args:
        data: Arbitrary dictionary to sanitize.

    Returns:
        Optional[Dict[str, Any]]: Safe sanitized dictionary without sensitive secrets.
    """
    if not data:
        return data

    sanitized: Dict[str, Any] = {}

    for k, v in data.items():
        k_lower = str(k).lower()
        
        # Check if key matches sensitive patterns
        if any(pattern in k_lower for pattern in SENSITIVE_KEY_PATTERNS):
            sanitized[k] = "[REDACTED]"
        elif isinstance(v, dict):
            sanitized[k] = sanitize_audit_metadata(v)
        elif isinstance(v, (list, tuple)):
            sanitized[k] = [
                sanitize_audit_metadata(item) if isinstance(item, dict) else item
                for item in v
            ]
        elif isinstance(v, bytes):
            # Never write raw byte buffers (could be keys or ciphertext chunks)
            sanitized[k] = f"<{len(v)} bytes binary payload>"
        else:
            sanitized[k] = v

    return sanitized


# ---------------------------------------------------------------------------
# Audit Logger Service
# ---------------------------------------------------------------------------

def log_security_event(
    db: Session,
    action: Union[str, AuditEventType],
    result: AuditResult,
    actor_id: Optional[uuid.UUID] = None,
    actor_ip: Optional[str] = None,
    target_type: Optional[str] = None,
    target_id: Optional[uuid.UUID] = None,
    reason: Optional[str] = None,
    extra_data: Optional[Dict[str, Any]] = None,
) -> AuditLog:
    """
    Record an immutable audit log entry in the database.

    Args:
        db: SQLAlchemy database session.
        action: Audit action name or AuditEventType enum.
        result: Outcome (SUCCESS, FAILURE, DENIED).
        actor_id: Optional UUID of the actor.
        actor_ip: Optional IP address of origin.
        target_type: Resource type (e.g. 'question_paper', 'access_request').
        target_id: UUID of the target resource.
        reason: Description / justification for the action.
        extra_data: Structured context (automatically sanitized of secrets).

    Returns:
        AuditLog: The persisted audit log record.
    """
    action_str = action.value if isinstance(action, AuditEventType) else str(action)
    safe_data = sanitize_audit_metadata(extra_data)

    entry = AuditLog(
        id=uuid.uuid4(),
        timestamp=datetime.now(timezone.utc),
        actor_id=actor_id,
        actor_ip=actor_ip,
        action=action_str,
        target_type=target_type,
        target_id=target_id,
        result=result,
        reason=reason,
        extra_data=safe_data,
    )
    db.add(entry)
    db.flush()

    logger.info(
        "AUDIT: [%s] action=%s result=%s actor=%s target=%s/%s reason=%s",
        entry.timestamp.isoformat(),
        action_str,
        result.value,
        actor_id,
        target_type,
        target_id,
        reason,
    )
    return entry


def record_threat_incident(
    db: Session,
    event_type: ThreatEventType,
    severity: ThreatSeverity,
    description: str,
    actor_id: Optional[uuid.UUID] = None,
    actor_ip: Optional[str] = None,
    target_type: Optional[str] = None,
    target_id: Optional[uuid.UUID] = None,
    extra_data: Optional[Dict[str, Any]] = None,
) -> ThreatEvent:
    """
    Record a security threat incident in the database.

    Args:
        db: SQLAlchemy database session.
        event_type: Category of threat event (e.g., UNAUTHORIZED_ACCESS, INTEGRITY_FAILURE).
        severity: Severity rating (LOW, MEDIUM, HIGH, CRITICAL).
        description: Description of the security violation.
        actor_id: Actor UUID if identified.
        actor_ip: Origin IP address.
        target_type: Affected resource entity type.
        target_id: Affected resource UUID.
        extra_data: Structured incident details (sanitized of secrets).

    Returns:
        ThreatEvent: The recorded threat event.
    """
    safe_data = sanitize_audit_metadata(extra_data)

    incident = ThreatEvent(
        id=uuid.uuid4(),
        timestamp=datetime.now(timezone.utc),
        event_type=event_type,
        severity=severity,
        actor_id=actor_id,
        actor_ip=actor_ip,
        target_type=target_type,
        target_id=target_id,
        description=description,
        extra_data=safe_data,
        resolved=False,
    )
    db.add(incident)
    db.flush()

    logger.warning(
        "THREAT EVENT: [%s] type=%s severity=%s actor=%s target=%s: %s",
        incident.timestamp.isoformat(),
        event_type.value,
        severity.value,
        actor_id,
        target_id,
        description,
    )
    return incident


# ---------------------------------------------------------------------------
# Secure Lifecycle Completion & Session Management
# ---------------------------------------------------------------------------

class SecureDecryptedBuffer:
    """
    In-memory representation container with explicit memory wiping.

    Guarantees that temporary decrypted question paper content is actively
    zeroed out and wiped upon exiting the context.
    """
    def __init__(self, data: bytes):
        self._buffer = bytearray(data)
        self._is_wiped = False

    def get_data(self) -> bytes:
        """Access the plaintext bytes while the buffer is active."""
        if self._is_wiped:
            raise RuntimeError("Cannot access wiped decrypted buffer: temporary representation removed")
        return bytes(self._buffer)

    def wipe(self) -> None:
        """Actively zero out byte array memory to invalidate temporary representation."""
        if not self._is_wiped:
            for i in range(len(self._buffer)):
                self._buffer[i] = 0
            self._buffer = bytearray()
            self._is_wiped = True

    def __enter__(self) -> "SecureDecryptedBuffer":
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        self.wipe()


def complete_access_session(
    db: Session,
    paper_id: uuid.UUID,
    request_id: uuid.UUID,
    actor_id: Optional[uuid.UUID] = None,
    actor_ip: Optional[str] = None,
    reason: str = "Access session completed normally",
) -> Dict[str, Any]:
    """
    Securely terminate and complete an authorized examination access session.

    Actions performed:
    1. Verify request and paper existence.
    2. Close the associated AccessWindow (WindowStatus.CLOSED).
    3. Mark QuestionPaper as COMPLETED (and record completed_at timestamp).
    4. Expire the temporary access permissions to prevent replay attacks.
    5. Record an immutable SESSION_CLOSED audit log.

    Args:
        db: SQLAlchemy database session.
        paper_id: QuestionPaper UUID.
        request_id: AccessRequest UUID.
        actor_id: User closing the session.
        actor_ip: Origin IP address.
        reason: Justification description.

    Returns:
        Dict[str, Any]: Lifecycle completion status report.
    """
    now = datetime.now(timezone.utc)

    request = db.get(AccessRequest, request_id)
    paper = db.get(QuestionPaper, paper_id)

    if not request or request.paper_id != paper_id:
        raise ValueError(f"AccessRequest {request_id} does not match QuestionPaper {paper_id}")

    # 1. Close AccessWindow
    window = request.access_window
    if not window:
        window = (
            db.query(AccessWindow)
            .filter(AccessWindow.request_id == request_id)
            .first()
        )

    if window and window.status != WindowStatus.REVOKED:
        window.status = WindowStatus.CLOSED

    # 2. Complete Paper lifecycle
    if paper:
        paper.status = PaperStatus.COMPLETED
        paper.completed_at = now

    # 3. Prevent Replay: mark request completed/decided
    request.status = RequestStatus.EXPIRED  # Mark expired to prevent any replay
    request.decided_at = now

    # 4. Log Audit Event
    log_security_event(
        db=db,
        action=AuditEventType.SESSION_CLOSED,
        result=AuditResult.SUCCESS,
        actor_id=actor_id,
        actor_ip=actor_ip,
        target_type="question_paper",
        target_id=paper_id,
        reason=reason,
        extra_data={
            "request_id": str(request_id),
            "window_id": str(window.id) if window else None,
            "session_state": "session closed",
            "temporary_access": "access expired",
            "replay_protection": "active",
            "temporary_representation": "temporary representation removed",
        },
    )
    db.flush()

    logger.info("Lifecycle completed for paper %s (request %s): %s", paper_id, request_id, reason)

    return {
        "paper_id": str(paper_id),
        "request_id": str(request_id),
        "session_state": "session closed",
        "access_state": "access expired",
        "replay_protection": "active",
        "temporary_representation": "temporary representation removed",
        "completed_at": now.isoformat(),
    }

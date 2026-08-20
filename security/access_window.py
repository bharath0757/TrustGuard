"""
TrustGuard — Just-In-Time (JIT) Access Validation & Access Window Service.

ACCESS DECISION FORMULA:
------------------------
Identity (Authenticated, active user)
+
Permission (Authorized role)
+
Valid Request (Active access request for target paper)
+
Quorum (Multi-party approvals met)
+
Valid Time Window (Current time is within [start_time, end_time])
+
Integrity (All fragments verified with intact SHA-256 digests)
================================================================
ALLOW

Otherwise:
DENY (Default-to-Deny)

Time Window Rules:
- BEFORE WINDOW (now < start_time)       -> DENY
- DURING WINDOW (start <= now <= end)    -> ALLOW (only if ALL other conditions valid)
- AFTER WINDOW  (now > end_time)         -> DENY
"""
from dataclasses import dataclass, field
from datetime import datetime, timezone
import enum
import logging
from typing import Any, Dict, List, Optional, Set, Tuple
import uuid

from sqlalchemy.orm import Session

from database.models.access import (
    AccessRequest,
    AccessWindow,
    RequestStatus,
    WindowStatus,
)
from database.models.audit import (
    AuditResult,
    ThreatEventType,
    ThreatSeverity,
)
from database.models.paper import QuestionPaper, PaperStatus
from database.models.fragment import PaperFragment
from database.models.user import User
from security.audit import (
    AuditEventType,
    log_security_event,
    record_threat_incident,
    SecureDecryptedBuffer,
)
from security.crypto.fragmentation import (
    FragmentValidationError,
    validate_fragments,
    reconstruct_and_decrypt_paper,
)
from security.quorum import (
    calculate_quorum_counts,
    get_user_role_names,
    is_user_authorized_approver,
    DEFAULT_APPROVER_ROLES,
)


logger = logging.getLogger("trustguard.security.jit")

DEFAULT_ACCESS_ROLES: Set[str] = {"OFFICER", "ADMIN", "APPROVER"}


# ---------------------------------------------------------------------------
# Enums and Result Models
# ---------------------------------------------------------------------------

class AccessDecision(str, enum.Enum):
    """JIT Access control outcome."""
    ALLOW = "ALLOW"
    DENY = "DENY"


class WindowTimeState(str, enum.Enum):
    """Relative temporal state of an access window."""
    BEFORE_WINDOW = "BEFORE_WINDOW"  # now < start_time
    DURING_WINDOW = "DURING_WINDOW"  # start_time <= now <= end_time
    AFTER_WINDOW = "AFTER_WINDOW"    # now > end_time


@dataclass
class AccessValidationResult:
    """Detailed result of a JIT access evaluation."""
    decision: AccessDecision
    is_allowed: bool
    reason: str
    user_id: uuid.UUID
    paper_id: uuid.UUID
    request_id: Optional[uuid.UUID] = None
    window_id: Optional[uuid.UUID] = None
    window_state: Optional[WindowTimeState] = None
    checks: Dict[str, bool] = field(default_factory=dict)


# ---------------------------------------------------------------------------
# Custom Exceptions
# ---------------------------------------------------------------------------

class AccessControlError(Exception):
    """Base exception for access control failures."""
    pass


class WindowScheduleError(AccessControlError):
    """Raised when access window parameters or timings are invalid."""
    pass


class JITAccessDeniedError(AccessControlError):
    """Raised when JIT access validation fails."""
    pass


# ---------------------------------------------------------------------------
# Helper: Time Normalization
# ---------------------------------------------------------------------------

def _normalize_dt(dt: datetime) -> datetime:
    """Ensure datetime object is timezone-aware (UTC)."""
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


# ---------------------------------------------------------------------------
# Access Window Service
# ---------------------------------------------------------------------------

def create_access_window(
    db: Session,
    request_id: uuid.UUID,
    start_time: datetime,
    end_time: datetime,
    current_time: Optional[datetime] = None,
) -> AccessWindow:
    """
    Create and persist a time-bounded AccessWindow for an approved AccessRequest.

    Args:
        db: SQLAlchemy database session.
        request_id: UUID of the approved AccessRequest.
        start_time: Window start timestamp.
        end_time: Window end timestamp (must be > start_time).
        current_time: Optional reference time for testing (defaults to now).

    Returns:
        AccessWindow: The created window record.

    Raises:
        WindowScheduleError: If request is not approved, already has a window,
                             or start_time >= end_time.
    """
    now = _normalize_dt(current_time or datetime.now(timezone.utc))
    st = _normalize_dt(start_time)
    et = _normalize_dt(end_time)

    if et <= st:
        raise WindowScheduleError(
            f"Invalid window timing: end_time ({et}) must be strictly after start_time ({st})"
        )

    request = db.get(AccessRequest, request_id)
    if not request:
        raise WindowScheduleError(f"AccessRequest with ID {request_id} not found")

    if request.status != RequestStatus.APPROVED:
        raise WindowScheduleError(
            f"Cannot create access window for request in '{request.status.value}' state. "
            f"Request must be APPROVED first."
        )

    # Check for existing window
    existing_window = (
        db.query(AccessWindow)
        .filter(AccessWindow.request_id == request_id)
        .first()
    )
    if existing_window:
        raise WindowScheduleError(
            f"An access window already exists for request {request_id} (Window ID: {existing_window.id})"
        )

    # Determine initial status
    if now < st:
        initial_status = WindowStatus.SCHEDULED
    elif st <= now <= et:
        initial_status = WindowStatus.ACTIVE
    else:
        initial_status = WindowStatus.CLOSED

    window = AccessWindow(
        id=uuid.uuid4(),
        paper_id=request.paper_id,
        request_id=request_id,
        start_time=st,
        end_time=et,
        status=initial_status,
    )
    db.add(window)
    db.flush()

    logger.info(
        "Created access window %s for request %s [%s → %s] status=%s",
        window.id,
        request_id,
        st.isoformat(),
        et.isoformat(),
        initial_status.value,
    )
    return window


def evaluate_window_time(
    window: AccessWindow,
    current_time: Optional[datetime] = None,
) -> WindowTimeState:
    """
    Evaluate whether current time is BEFORE, DURING, or AFTER the access window.

    Args:
        window: AccessWindow instance.
        current_time: Reference time (defaults to utcnow).

    Returns:
        WindowTimeState: BEFORE_WINDOW, DURING_WINDOW, or AFTER_WINDOW.
    """
    now = _normalize_dt(current_time or datetime.now(timezone.utc))
    st = _normalize_dt(window.start_time)
    et = _normalize_dt(window.end_time)

    if now < st:
        return WindowTimeState.BEFORE_WINDOW
    elif st <= now <= et:
        return WindowTimeState.DURING_WINDOW
    else:
        return WindowTimeState.AFTER_WINDOW


def sync_window_status(
    db: Session,
    window: AccessWindow,
    current_time: Optional[datetime] = None,
) -> WindowStatus:
    """
    Synchronize window and question paper status with the current timestamp.

    Args:
        db: SQLAlchemy database session.
        window: AccessWindow instance.
        current_time: Reference time (defaults to utcnow).

    Returns:
        WindowStatus: The updated window status.
    """
    if window.status == WindowStatus.REVOKED:
        return WindowStatus.REVOKED

    time_state = evaluate_window_time(window, current_time)
    paper = db.get(QuestionPaper, window.paper_id)

    if time_state == WindowTimeState.BEFORE_WINDOW:
        window.status = WindowStatus.SCHEDULED
    elif time_state == WindowTimeState.DURING_WINDOW:
        window.status = WindowStatus.ACTIVE
        if paper and paper.status == PaperStatus.AUTHORIZED:
            paper.status = PaperStatus.ACTIVE
    else:  # AFTER_WINDOW
        window.status = WindowStatus.CLOSED
        if paper and paper.status == PaperStatus.ACTIVE:
            paper.status = PaperStatus.COMPLETED

    db.flush()
    return window.status


# ---------------------------------------------------------------------------
# JIT Access Validation Engine
# ---------------------------------------------------------------------------

def validate_jit_access(
    db: Session,
    user_id: uuid.UUID,
    paper_id: uuid.UUID,
    request_id: Optional[uuid.UUID] = None,
    current_time: Optional[datetime] = None,
    actor_ip: Optional[str] = None,
    allowed_roles: Optional[Set[str]] = None,
    emit_audit_logs: bool = True,
) -> AccessValidationResult:
    """
    Evaluate Just-In-Time (JIT) access authorization for a protected question paper.

    Evaluates:
    1. Identity: User exists and is active.
    2. Permission: User holds an authorized role.
    3. Valid Request: Request exists, matches paper, and matches requester.
    4. Quorum: Request is APPROVED and approved_count >= required_approvals.
    5. Time Window: Current time is strictly within the authorized [start, end] window.
    6. Integrity: All shards exist, are untampered, and match individual SHA-256 hashes.

    DEFAULT TO DENY: Returns DENY on any condition failure.

    Args:
        db: SQLAlchemy database session.
        user_id: Requesting user UUID.
        paper_id: Target QuestionPaper UUID.
        request_id: Optional specific AccessRequest UUID.
        current_time: Reference time (defaults to utcnow).
        actor_ip: Request origin IP.
        allowed_roles: Set of authorized role names (defaults to DEFAULT_ACCESS_ROLES).
        emit_audit_logs: Whether to write audit logs and threat events automatically.

    Returns:
        AccessValidationResult: Comprehensive evaluation report.
    """
    now = _normalize_dt(current_time or datetime.now(timezone.utc))
    roles_to_check = allowed_roles if allowed_roles is not None else DEFAULT_ACCESS_ROLES

    checks: Dict[str, bool] = {
        "identity_valid": False,
        "permission_valid": False,
        "request_valid": False,
        "quorum_valid": False,
        "time_window_valid": False,
        "integrity_valid": False,
    }

    def _deny(
        reason: str,
        audit_event: AuditEventType = AuditEventType.ACCESS_DENIED,
        threat_type: Optional[ThreatEventType] = None,
        threat_severity: ThreatSeverity = ThreatSeverity.MEDIUM,
        extra_info: Optional[Dict[str, Any]] = None,
        window_state: Optional[WindowTimeState] = None,
        window_id: Optional[uuid.UUID] = None,
        req_id: Optional[uuid.UUID] = None,
    ) -> AccessValidationResult:
        if emit_audit_logs:
            log_security_event(
                db=db,
                action=audit_event,
                result=AuditResult.DENIED,
                actor_id=user_id,
                actor_ip=actor_ip,
                target_type="question_paper",
                target_id=paper_id,
                reason=reason,
                extra_data=extra_info or {"checks": checks},
            )
            if threat_type:
                record_threat_incident(
                    db=db,
                    event_type=threat_type,
                    severity=threat_severity,
                    description=reason,
                    actor_id=user_id,
                    actor_ip=actor_ip,
                    target_type="question_paper",
                    target_id=paper_id,
                    extra_data=extra_info,
                )
        return AccessValidationResult(
            decision=AccessDecision.DENY,
            is_allowed=False,
            reason=reason,
            user_id=user_id,
            paper_id=paper_id,
            request_id=req_id or request_id or (access_req.id if 'access_req' in locals() and access_req else None),
            window_id=window_id or (window.id if 'window' in locals() and window else None),
            window_state=window_state or (time_state if 'time_state' in locals() else None),
            checks=checks,
        )

    # 1. Identity Check
    user = db.get(User, user_id)
    if not user or not user.is_active:
        return _deny(
            "Identity check failed: User is unknown or inactive",
            threat_type=ThreatEventType.UNAUTHORIZED_ACCESS,
            threat_severity=ThreatSeverity.HIGH,
        )
    checks["identity_valid"] = True

    # 2. Permission Check
    user_roles = get_user_role_names(db, user_id)
    if not (user_roles & roles_to_check):
        return _deny(
            f"Permission check failed: User roles {user_roles} lack authorized access roles {roles_to_check}",
            threat_type=ThreatEventType.DENIED_OPERATION,
            threat_severity=ThreatSeverity.MEDIUM,
        )
    checks["permission_valid"] = True

    # 3. Valid Request Check
    if request_id is not None:
        access_req = db.get(AccessRequest, request_id)
        if not access_req or access_req.paper_id != paper_id:
            return _deny(
                "Request check failed: Access request not found for target paper",
                threat_type=ThreatEventType.UNAUTHORIZED_ACCESS,
                threat_severity=ThreatSeverity.HIGH,
            )
    else:
        access_req = (
            db.query(AccessRequest)
            .filter(
                AccessRequest.paper_id == paper_id,
                AccessRequest.requested_by == user_id,
                AccessRequest.status == RequestStatus.APPROVED,
            )
            .order_by(AccessRequest.created_at.desc())
            .first()
        )
        if not access_req:
            access_req = (
                db.query(AccessRequest)
                .filter(
                    AccessRequest.paper_id == paper_id,
                    AccessRequest.status == RequestStatus.APPROVED,
                )
                .order_by(AccessRequest.created_at.desc())
                .first()
            )

    if not access_req:
        return _deny(
            "Request check failed: No valid access request found",
            threat_type=ThreatEventType.UNAUTHORIZED_ACCESS,
            threat_severity=ThreatSeverity.MEDIUM,
        )

    # Check for replay / completed request
    if access_req.status in (RequestStatus.EXPIRED, RequestStatus.WITHDRAWN):
        return _deny(
            f"Request check failed: Attempting to access using {access_req.status.value} request (replay prevented)",
            audit_event=AuditEventType.REPLAY_ATTEMPT,
            threat_type=ThreatEventType.REPLAY_ATTEMPT,
            threat_severity=ThreatSeverity.HIGH,
        )

    checks["request_valid"] = True
    actual_req_id = access_req.id

    # 4. Quorum Check
    if access_req.status != RequestStatus.APPROVED:
        return _deny(
            f"Quorum check failed: Access request is in '{access_req.status.value}' state, not APPROVED",
            threat_type=ThreatEventType.INVALID_QUORUM,
            threat_severity=ThreatSeverity.HIGH,
        )

    approved_count, _, required = calculate_quorum_counts(db, actual_req_id)
    if approved_count < required:
        return _deny(
            f"Quorum check failed: Approvals ({approved_count}/{required}) below required threshold",
            threat_type=ThreatEventType.INVALID_QUORUM,
            threat_severity=ThreatSeverity.HIGH,
        )
    checks["quorum_valid"] = True

    # 5. Time Window Check
    window = access_req.access_window
    if not window:
        window = (
            db.query(AccessWindow)
            .filter(AccessWindow.request_id == actual_req_id)
            .first()
        )

    if not window:
        return _deny("Time window check failed: No AccessWindow scheduled for this request")

    if window.status == WindowStatus.REVOKED:
        return _deny(
            "Time window check failed: AccessWindow has been REVOKED",
            threat_type=ThreatEventType.DENIED_OPERATION,
            threat_severity=ThreatSeverity.HIGH,
        )

    time_state = evaluate_window_time(window, now)
    sync_window_status(db, window, now)

    if time_state == WindowTimeState.BEFORE_WINDOW:
        return _deny(
            f"Time window check failed: BEFORE_WINDOW (window opens at {window.start_time.isoformat()})",
            extra_info={"window_id": str(window.id), "start_time": window.start_time.isoformat()},
            window_state=time_state,
            window_id=window.id,
            req_id=actual_req_id,
        )
    elif time_state == WindowTimeState.AFTER_WINDOW:
        return _deny(
            f"Time window check failed: AFTER_WINDOW (window closed at {window.end_time.isoformat()})",
            audit_event=AuditEventType.ACCESS_EXPIRED,
            extra_info={"window_id": str(window.id), "end_time": window.end_time.isoformat()},
            window_state=time_state,
            window_id=window.id,
            req_id=actual_req_id,
        )

    checks["time_window_valid"] = True

    # 6. Integrity Check
    paper = db.get(QuestionPaper, paper_id)
    if not paper:
        return _deny("Integrity check failed: QuestionPaper not found")

    fragments = db.query(PaperFragment).filter_by(paper_id=paper_id).all()
    try:
        validate_fragments(
            fragments,
            expected_paper_id=paper_id,
            expected_count=paper.total_fragments,
        )
    except FragmentValidationError as exc:
        return _deny(
            f"Integrity check failed: {str(exc)}",
            audit_event=AuditEventType.INTEGRITY_FAILURE,
            threat_type=ThreatEventType.INTEGRITY_FAILURE,
            threat_severity=ThreatSeverity.CRITICAL,
        )
    checks["integrity_valid"] = True

    # All conditions satisfied!
    if emit_audit_logs:
        log_security_event(
            db=db,
            action=AuditEventType.ACCESS_GRANTED,
            result=AuditResult.SUCCESS,
            actor_id=user_id,
            actor_ip=actor_ip,
            target_type="question_paper",
            target_id=paper_id,
            reason="All security conditions satisfied (Identity, Permission, Request, Quorum, Time Window, Integrity)",
            extra_data={
                "request_id": str(actual_req_id),
                "window_id": str(window.id),
                "checks": checks,
            },
        )

    logger.info(
        "JIT Access ALLOWED for user %s on paper %s (request: %s, window: %s)",
        user_id,
        paper_id,
        actual_req_id,
        window.id,
    )
    return AccessValidationResult(
        decision=AccessDecision.ALLOW,
        is_allowed=True,
        reason="All security conditions satisfied (Identity, Permission, Request, Quorum, Time Window, Integrity)",
        user_id=user_id,
        paper_id=paper_id,
        request_id=actual_req_id,
        window_id=window.id,
        window_state=time_state,
        checks=checks,
    )


# ---------------------------------------------------------------------------
# High-Level Execution Gateway
# ---------------------------------------------------------------------------

def execute_jit_paper_access(
    db: Session,
    user_id: uuid.UUID,
    paper_id: uuid.UUID,
    key: bytes,
    request_id: Optional[uuid.UUID] = None,
    current_time: Optional[datetime] = None,
    actor_ip: Optional[str] = None,
) -> bytes:
    """
    Perform full Just-In-Time access verification, log security audits,
    and securely reconstruct/decrypt the question paper.

    Args:
        db: SQLAlchemy database session.
        user_id: Requesting user UUID.
        paper_id: Target QuestionPaper UUID.
        key: 32-byte AES-256 master key.
        request_id: Optional specific AccessRequest UUID.
        current_time: Reference time for temporal checks.
        actor_ip: Origin IP address.

    Returns:
        bytes: Decrypted plaintext examination paper.

    Raises:
        JITAccessDeniedError: If any security validation check fails.
    """
    validation_result = validate_jit_access(
        db=db,
        user_id=user_id,
        paper_id=paper_id,
        request_id=request_id,
        current_time=current_time,
        actor_ip=actor_ip,
        emit_audit_logs=True,
    )

    if not validation_result.is_allowed:
        logger.warning(
            "JIT Access DENIED for user %s on paper %s: %s",
            user_id,
            paper_id,
            validation_result.reason,
        )
        raise JITAccessDeniedError(f"Access DENIED: {validation_result.reason}")

    # Log decryption start
    log_security_event(
        db=db,
        action=AuditEventType.DECRYPTION_STARTED,
        result=AuditResult.SUCCESS,
        actor_id=user_id,
        actor_ip=actor_ip,
        target_type="question_paper",
        target_id=paper_id,
        reason="Beginning cryptographic shard assembly and AEAD decryption",
        extra_data={"request_id": str(validation_result.request_id)},
    )

    paper = db.get(QuestionPaper, paper_id)
    plaintext = reconstruct_and_decrypt_paper(db, paper, key)

    # Log decryption completion (never logging plaintext or keys!)
    log_security_event(
        db=db,
        action=AuditEventType.DECRYPTION_COMPLETED,
        result=AuditResult.SUCCESS,
        actor_id=user_id,
        actor_ip=actor_ip,
        target_type="question_paper",
        target_id=paper_id,
        reason="Cryptographic reconstruction and AEAD decryption completed successfully",
        extra_data={
            "request_id": str(validation_result.request_id),
            "payload_size_bytes": len(plaintext),
        },
    )

    return plaintext

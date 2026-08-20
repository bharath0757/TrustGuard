"""
TrustGuard — Centralized Security Service Interface for Backend Integration.

This module provides clean, high-level service interfaces for FastAPI routes and backend
controllers. The backend can invoke these functions directly without managing internal
cryptographic algorithms, key manipulation, or shard indexing.

EXPOSED SERVICE INTERFACES:
---------------------------
1.  protect_paper()          — Encrypt plaintext paper content and generate manifest hash
2.  fragment_paper()         — Partition encrypted ciphertext into N authenticated shards
3.  validate_fragments()     — Verify shard ownership, completeness, index continuity, & hashes
4.  create_access_request()  — Register formal multi-party access request (PENDING)
5.  check_quorum()           — Evaluate multi-party approval votes against quorum threshold
6.  is_access_window_valid() — Check temporal validity (BEFORE, DURING, AFTER) of access window
7.  authorize_access()       — 6-factor JIT access validation (Identity + Role + Req + Quorum + Time + Integrity)
8.  reconstruct_paper()      — Validate and assemble stored shards into protected ciphertext
9.  decrypt_paper()          — Authenticate and decrypt protected ciphertext payload into plaintext
10. complete_access()        — Securely close access window, expire permissions, & prevent replay
11. create_audit_event()     — Record immutable, sanitized audit log entry

SECURITY GUARANTEES:
- Zero Plaintext at Rest: Question papers are encrypted before sharding or database storage.
- Zero Leakage in Logs: Passwords, keys, tokens, and exam content are automatically redacted.
- Default to Deny: All access evaluations deny access unless all security criteria pass.
"""
from datetime import datetime, timezone
import logging
from typing import Any, Dict, List, Optional, Sequence, Set, Tuple, Union
import uuid

from sqlalchemy.orm import Session

from database.models.access import (
    AccessRequest,
    AccessWindow,
    Approval,
    ApprovalDecision,
    RequestStatus,
    RequestType,
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
from database.models.fragment import PaperFragment, FragmentStatus
from database.models.user import User

from security.crypto.encryption import (
    encrypt,
    decrypt,
    DecryptionFailedError,
)
from security.crypto.key_manager import get_master_key
from security.crypto.integrity import generate_integrity_hash
from security.crypto.fragmentation import (
    FragmentPayload,
    FragmentLike,
    FragmentValidationError,
    FragmentPaperMismatchError,
    FragmentCountMismatchError,
    DuplicateFragmentError,
    MissingFragmentError,
    CorruptedFragmentError,
    FragmentIntegrityError,
    fragment_ciphertext,
    validate_fragments as _validate_fragments_core,
    reconstruct_ciphertext,
    protect_and_fragment_paper,
    reconstruct_and_decrypt_paper,
    retrieve_paper_fragments,
)
from security.quorum import (
    QuorumResult,
    QuorumDecision,
    QuorumError,
    QuorumValidationError,
    UnauthorizedApproverError,
    InvalidApproverRoleError,
    DuplicateApprovalError,
    RequestNotPendingError,
    SelfApprovalError,
    AccessDeniedError,
    DEFAULT_APPROVER_ROLES,
    create_access_request as _create_access_request_core,
    cast_approval_vote,
    evaluate_quorum,
    calculate_quorum_counts,
    expire_access_request,
    check_paper_access_authorization,
    assert_paper_access_authorized,
)
from security.access_window import (
    AccessDecision,
    WindowTimeState,
    AccessValidationResult,
    AccessControlError,
    WindowScheduleError,
    JITAccessDeniedError,
    DEFAULT_ACCESS_ROLES,
    create_access_window,
    evaluate_window_time,
    sync_window_status,
    validate_jit_access,
    execute_jit_paper_access,
)
from security.audit import (
    AuditEventType,
    sanitize_audit_metadata,
    log_security_event,
    record_threat_incident,
    SecureDecryptedBuffer,
    complete_access_session,
)


logger = logging.getLogger("trustguard.security.service")


# ===========================================================================
# 1. protect_paper()
# ===========================================================================

def protect_paper(
    db: Session,
    paper_id: uuid.UUID,
    plaintext_data: bytes,
    key: Optional[bytes] = None,
    actor_id: Optional[uuid.UUID] = None,
    actor_ip: Optional[str] = None,
) -> QuestionPaper:
    """
    Encrypt examination paper content using AES-256-GCM and store manifest hash.

    Args:
        db: SQLAlchemy database session.
        paper_id: Target QuestionPaper UUID.
        plaintext_data: Raw question paper content (bytes).
        key: Optional 32-byte master key (defaults to get_master_key()).
        actor_id: User performing the protection action.
        actor_ip: Origin IP address.

    Returns:
        QuestionPaper: Updated QuestionPaper record in PROTECTED status.

    Raises:
        ValueError: If paper is not found, data is not bytes, or key is invalid.
    """
    if not isinstance(plaintext_data, bytes):
        raise ValueError("Plaintext data must be bytes")

    paper = db.get(QuestionPaper, paper_id)
    if not paper:
        raise ValueError(f"QuestionPaper {paper_id} not found")

    encryption_key = key or get_master_key()
    now = datetime.now(timezone.utc)

    # 1. Compute pre-fragmentation manifest hash
    manifest_hash = generate_integrity_hash(plaintext_data)
    paper.integrity_hash = manifest_hash

    # 2. Encrypt plaintext
    ciphertext = encrypt(plaintext_data, encryption_key)
    paper.status = PaperStatus.PROTECTED
    paper.protected_at = now

    # Store encrypted representation temporarily in paper object context for fragmentation
    setattr(paper, "_protected_ciphertext", ciphertext)

    # 3. Log Audit Event
    log_security_event(
        db=db,
        action=AuditEventType.PAPER_ENCRYPTED,
        result=AuditResult.SUCCESS,
        actor_id=actor_id,
        actor_ip=actor_ip,
        target_type="question_paper",
        target_id=paper.id,
        reason="Plaintext question paper encrypted using AES-256-GCM AEAD",
        extra_data={"manifest_hash": manifest_hash},
    )

    db.flush()
    logger.info("QuestionPaper %s encrypted (manifest hash: %s)", paper.id, manifest_hash)
    return paper


# ===========================================================================
# 2. fragment_paper()
# ===========================================================================

def fragment_paper(
    db: Session,
    paper_id: uuid.UUID,
    num_fragments: int = 5,
    ciphertext_payload: Optional[bytes] = None,
    actor_id: Optional[uuid.UUID] = None,
    actor_ip: Optional[str] = None,
) -> List[PaperFragment]:
    """
    Partition encrypted ciphertext into N deterministic shards and store in database.

    Args:
        db: SQLAlchemy database session.
        paper_id: QuestionPaper UUID.
        num_fragments: Number of shards to produce (must be >= 1, default: 5).
        ciphertext_payload: Optional pre-encrypted ciphertext bytes. If omitted,
                            uses cached ciphertext from protect_paper.
        actor_id: User executing fragmentation.
        actor_ip: Origin IP address.

    Returns:
        List[PaperFragment]: Persisted shard records with status STORED.

    Raises:
        ValueError: If paper is not found or not in PROTECTED status.
    """
    paper = db.get(QuestionPaper, paper_id)
    if not paper:
        raise ValueError(f"QuestionPaper {paper_id} not found")

    payload = ciphertext_payload or getattr(paper, "_protected_ciphertext", None)
    if not payload:
        raise ValueError(
            f"QuestionPaper {paper_id} has no encrypted payload to fragment. "
            f"Call protect_paper() first or provide ciphertext_payload."
        )

    now = datetime.now(timezone.utc)

    # 1. Shard ciphertext (Encrypted Fragment Distribution)
    shards = fragment_ciphertext(payload, num_fragments, paper_id=paper.id)

    # 2. Persist shards
    db_fragments: List[PaperFragment] = []
    for shard in shards:
        frag = PaperFragment(
            id=uuid.uuid4(),
            paper_id=paper.id,
            fragment_index=shard.fragment_index,
            fragment_data=shard.fragment_data,
            integrity_hash=shard.integrity_hash,
            status=FragmentStatus.STORED,
        )
        db.add(frag)
        db_fragments.append(frag)

    # 3. Transition Paper state
    paper.status = PaperStatus.FRAGMENTED
    paper.total_fragments = num_fragments
    paper.fragmented_at = now

    # 4. Log Audit Event
    log_security_event(
        db=db,
        action=AuditEventType.PAPER_FRAGMENTED,
        result=AuditResult.SUCCESS,
        actor_id=actor_id,
        actor_ip=actor_ip,
        target_type="question_paper",
        target_id=paper.id,
        reason=f"Encrypted ciphertext sliced into {num_fragments} deterministic shards",
        extra_data={"total_fragments": num_fragments},
    )

    db.flush()
    logger.info("QuestionPaper %s fragmented into %d shards", paper.id, num_fragments)
    return db_fragments


# ===========================================================================
# 3. validate_fragments()
# ===========================================================================

def validate_fragments(
    fragments: Sequence[FragmentLike],
    expected_paper_id: Optional[uuid.UUID] = None,
    expected_count: Optional[int] = None,
) -> List[FragmentLike]:
    """
    Validate fragment ownership, count, continuous index permutation, and SHA-256 hashes.

    Args:
        fragments: Sequence of PaperFragment or FragmentPayload instances.
        expected_paper_id: Expected QuestionPaper UUID.
        expected_count: Expected total fragment count (paper.total_fragments).

    Returns:
        List[FragmentLike]: Validated fragments sorted by fragment_index.

    Raises:
        FragmentValidationError: If any shard is missing, duplicate, foreign, corrupted,
                                 or has a hash mismatch.
    """
    return _validate_fragments_core(
        fragments=fragments,
        expected_paper_id=expected_paper_id,
        expected_count=expected_count,
    )


# ===========================================================================
# 4. create_access_request()
# ===========================================================================

def create_access_request(
    db: Session,
    paper_id: uuid.UUID,
    requested_by: uuid.UUID,
    request_type: RequestType = RequestType.RECONSTRUCT,
    reason: str = "Formal request for examination paper access",
    required_approvals: int = 3,
    actor_ip: Optional[str] = None,
) -> AccessRequest:
    """
    Register a formal multi-party access request in PENDING state.

    Args:
        db: SQLAlchemy database session.
        paper_id: Target QuestionPaper UUID.
        requested_by: Requesting user UUID.
        request_type: Access type (RECONSTRUCT, VIEW, EMERGENCY).
        reason: Mandatory justification.
        required_approvals: Multi-party approval threshold (default: 3).
        actor_ip: Origin IP address.

    Returns:
        AccessRequest: Created request in PENDING status.

    Raises:
        QuorumValidationError: If user or paper is invalid.
    """
    req = _create_access_request_core(
        db=db,
        paper_id=paper_id,
        requested_by=requested_by,
        request_type=request_type,
        reason=reason,
        required_approvals=required_approvals,
    )

    log_security_event(
        db=db,
        action=AuditEventType.ACCESS_REQUESTED,
        result=AuditResult.SUCCESS,
        actor_id=requested_by,
        actor_ip=actor_ip,
        target_type="access_request",
        target_id=req.id,
        reason=reason,
        extra_data={
            "paper_id": str(paper_id),
            "request_type": request_type.value,
            "required_approvals": required_approvals,
        },
    )

    db.flush()
    return req


# ===========================================================================
# 5. check_quorum()
# ===========================================================================

def check_quorum(
    db: Session,
    request_id: uuid.UUID,
    reject_on_single_rejection: bool = False,
) -> QuorumResult:
    """
    Evaluate multi-party approver votes for an AccessRequest and update lifecycle state.

    Args:
        db: SQLAlchemy database session.
        request_id: AccessRequest UUID.
        reject_on_single_rejection: If True, a single rejection marks request REJECTED.

    Returns:
        QuorumResult: Outcome container with is_authorized, approved_count, required_approvals.
    """
    return evaluate_quorum(
        db=db,
        request_id=request_id,
        reject_on_single_rejection=reject_on_single_rejection,
    )


# ===========================================================================
# 6. is_access_window_valid()
# ===========================================================================

def is_access_window_valid(
    db: Session,
    window_id: uuid.UUID,
    current_time: Optional[datetime] = None,
) -> Tuple[bool, WindowTimeState]:
    """
    Check if an AccessWindow is currently open and valid at the given timestamp.

    Args:
        db: SQLAlchemy database session.
        window_id: AccessWindow UUID.
        current_time: Reference timestamp (defaults to utcnow).

    Returns:
        Tuple[bool, WindowTimeState]: (is_valid, time_state)
            - is_valid is True only when status is not REVOKED and time is DURING_WINDOW.
    """
    window = db.get(AccessWindow, window_id)
    if not window or window.status == WindowStatus.REVOKED:
        return False, WindowTimeState.AFTER_WINDOW

    time_state = evaluate_window_time(window, current_time)
    sync_window_status(db, window, current_time)

    is_valid = (time_state == WindowTimeState.DURING_WINDOW and window.status != WindowStatus.REVOKED)
    return is_valid, time_state


# ===========================================================================
# 7. authorize_access()
# ===========================================================================

def authorize_access(
    db: Session,
    user_id: uuid.UUID,
    paper_id: uuid.UUID,
    request_id: Optional[uuid.UUID] = None,
    current_time: Optional[datetime] = None,
    actor_ip: Optional[str] = None,
    allowed_roles: Optional[Set[str]] = None,
) -> AccessValidationResult:
    """
    Execute full 6-factor JIT access validation (Identity + Role + Request + Quorum + Time + Integrity).

    Args:
        db: SQLAlchemy database session.
        user_id: Requesting user UUID.
        paper_id: Target QuestionPaper UUID.
        request_id: Optional specific AccessRequest UUID.
        current_time: Reference timestamp.
        actor_ip: Origin IP address.
        allowed_roles: Set of authorized role names.

    Returns:
        AccessValidationResult: Result container with decision (ALLOW / DENY), reason, and checks.
    """
    return validate_jit_access(
        db=db,
        user_id=user_id,
        paper_id=paper_id,
        request_id=request_id,
        current_time=current_time,
        actor_ip=actor_ip,
        allowed_roles=allowed_roles,
        emit_audit_logs=True,
    )


# ===========================================================================
# 8. reconstruct_paper()
# ===========================================================================

def reconstruct_paper(
    db: Session,
    paper_id: uuid.UUID,
    fragments: Optional[List[PaperFragment]] = None,
) -> bytes:
    """
    Retrieve, validate, and assemble stored shards into the protected ciphertext representation.

    Args:
        db: SQLAlchemy database session.
        paper_id: Target QuestionPaper UUID.
        fragments: Optional pre-retrieved shard list. If omitted, queries database.

    Returns:
        bytes: The reconstructed AES-256-GCM protected ciphertext representation.

    Raises:
        FragmentValidationError: If shards fail validation or are corrupted.
        ValueError: If paper is not found.
    """
    paper = db.get(QuestionPaper, paper_id)
    if not paper:
        raise ValueError(f"QuestionPaper {paper_id} not found")

    shards = fragments if fragments is not None else retrieve_paper_fragments(db, paper_id)
    
    return reconstruct_ciphertext(
        shards,
        expected_paper_id=paper_id,
        expected_count=paper.total_fragments,
    )


# ===========================================================================
# 9. decrypt_paper()
# ===========================================================================

def decrypt_paper(
    ciphertext_payload: bytes,
    key: Optional[bytes] = None,
    expected_manifest_hash: Optional[str] = None,
) -> bytes:
    """
    Authenticate and decrypt an AES-256-GCM payload and verify pre-fragmentation manifest hash.

    Args:
        ciphertext_payload: Reconstructed [12-byte Nonce] + [Ciphertext + 16-byte Tag] payload.
        key: Optional 32-byte master key (defaults to get_master_key()).
        expected_manifest_hash: Optional canonical SHA-256 hash to verify plaintext integrity.

    Returns:
        bytes: Decrypted plaintext examination paper content.

    Raises:
        DecryptionFailedError: If key is invalid or ciphertext/tag was tampered with.
        FragmentIntegrityError: If recovered plaintext does not match expected_manifest_hash.
    """
    decryption_key = key or get_master_key()
    plaintext = decrypt(ciphertext_payload, decryption_key)

    if expected_manifest_hash:
        computed_hash = generate_integrity_hash(plaintext)
        if computed_hash != expected_manifest_hash:
            raise FragmentIntegrityError(
                f"Decrypted manifest integrity mismatch. "
                f"Expected: {expected_manifest_hash}, Computed: {computed_hash}"
            )

    return plaintext


# ===========================================================================
# 10. complete_access()
# ===========================================================================

def complete_access(
    db: Session,
    paper_id: uuid.UUID,
    request_id: uuid.UUID,
    actor_id: Optional[uuid.UUID] = None,
    actor_ip: Optional[str] = None,
    reason: str = "Access session completed normally",
) -> Dict[str, Any]:
    """
    Close access window, expire permissions, prevent replay attacks, and complete lifecycle.

    Args:
        db: SQLAlchemy database session.
        paper_id: QuestionPaper UUID.
        request_id: AccessRequest UUID.
        actor_id: User terminating the session.
        actor_ip: Origin IP address.
        reason: Explanation for session termination.

    Returns:
        Dict[str, Any]: Completion report confirming session closure and replay protection.
    """
    return complete_access_session(
        db=db,
        paper_id=paper_id,
        request_id=request_id,
        actor_id=actor_id,
        actor_ip=actor_ip,
        reason=reason,
    )


# ===========================================================================
# 11. create_audit_event()
# ===========================================================================

def create_audit_event(
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
    Record an immutable, sanitized audit log entry capturing WHO, WHAT, WHEN, WHICH, RESULT, and WHY.

    Args:
        db: SQLAlchemy database session.
        action: Audit action name or AuditEventType enum.
        result: Outcome (AuditResult.SUCCESS, FAILURE, DENIED).
        actor_id: Optional User UUID.
        actor_ip: Origin IP address.
        target_type: Target entity type (e.g. 'question_paper').
        target_id: Target entity UUID.
        reason: Description / explanation.
        extra_data: Structured metadata dictionary (automatically sanitized).

    Returns:
        AuditLog: The persisted audit log row.
    """
    return log_security_event(
        db=db,
        action=action,
        result=result,
        actor_id=actor_id,
        actor_ip=actor_ip,
        target_type=target_type,
        target_id=target_id,
        reason=reason,
        extra_data=extra_data,
    )


# ===========================================================================
# End-to-End Orchestrated Delivery Helpers
# ===========================================================================

def ingest_and_protect_paper(
    db: Session,
    exam_identifier: str,
    paper_name: str,
    plaintext_data: bytes,
    key: Optional[bytes] = None,
    creator_id: Optional[uuid.UUID] = None,
    num_fragments: int = 5,
    actor_ip: Optional[str] = None,
) -> QuestionPaper:
    """Convenience workflow: creates, encrypts, and fragments a paper with full audit logging."""
    encryption_key = key or get_master_key()

    paper = QuestionPaper(
        id=uuid.uuid4(),
        exam_identifier=exam_identifier,
        paper_name=paper_name,
        status=PaperStatus.CREATED,
        created_by=creator_id,
    )
    db.add(paper)
    db.flush()

    create_audit_event(
        db=db,
        action=AuditEventType.PAPER_CREATED,
        result=AuditResult.SUCCESS,
        actor_id=creator_id,
        actor_ip=actor_ip,
        target_type="question_paper",
        target_id=paper.id,
        reason=f"Registered metadata for {exam_identifier} ('{paper_name}')",
        extra_data={"exam_identifier": exam_identifier},
    )

    protect_paper(
        db=db,
        paper_id=paper.id,
        plaintext_data=plaintext_data,
        key=encryption_key,
        actor_id=creator_id,
        actor_ip=actor_ip,
    )

    fragment_paper(
        db=db,
        paper_id=paper.id,
        num_fragments=num_fragments,
        actor_id=creator_id,
        actor_ip=actor_ip,
    )

    db.flush()
    return paper


def submit_access_request(
    db: Session,
    paper_id: uuid.UUID,
    requested_by: uuid.UUID,
    request_type: RequestType = RequestType.RECONSTRUCT,
    reason: str = "Authorized delivery for examination session",
    required_approvals: int = 3,
    actor_ip: Optional[str] = None,
) -> AccessRequest:
    """Convenience workflow: submits request and logs audit event."""
    return create_access_request(
        db=db,
        paper_id=paper_id,
        requested_by=requested_by,
        request_type=request_type,
        reason=reason,
        required_approvals=required_approvals,
        actor_ip=actor_ip,
    )


def approve_access_request(
    db: Session,
    request_id: uuid.UUID,
    approver_id: uuid.UUID,
    decision: ApprovalDecision = ApprovalDecision.APPROVED,
    reason: Optional[str] = None,
    allowed_roles: Optional[Set[str]] = None,
    actor_ip: Optional[str] = None,
    reject_on_single_rejection: bool = False,
) -> Tuple[Approval, QuorumResult]:
    """Convenience workflow: casts vote, logs audit event, and evaluates quorum."""
    vote, quorum_res = cast_approval_vote(
        db=db,
        request_id=request_id,
        approver_id=approver_id,
        decision=decision,
        reason=reason,
        allowed_roles=allowed_roles,
        reject_on_single_rejection=reject_on_single_rejection,
    )

    audit_action = (
        AuditEventType.APPROVAL_GRANTED
        if decision == ApprovalDecision.APPROVED
        else AuditEventType.APPROVAL_REJECTED
    )

    create_audit_event(
        db=db,
        action=audit_action,
        result=AuditResult.SUCCESS,
        actor_id=approver_id,
        actor_ip=actor_ip,
        target_type="access_request",
        target_id=request_id,
        reason=reason or f"Vote cast: {decision.value}",
        extra_data={
            "decision": decision.value,
            "approved_count": quorum_res.approved_count,
            "required_approvals": quorum_res.required_approvals,
            "quorum_decision": quorum_res.decision.value,
        },
    )

    if quorum_res.is_authorized:
        create_audit_event(
            db=db,
            action=AuditEventType.QUORUM_REACHED,
            result=AuditResult.SUCCESS,
            actor_id=approver_id,
            actor_ip=actor_ip,
            target_type="access_request",
            target_id=request_id,
            reason=f"Multi-party quorum threshold satisfied ({quorum_res.approved_count}/{quorum_res.required_approvals} approvals)",
            extra_data={
                "paper_id": str(quorum_res.paper_id),
                "approved_count": quorum_res.approved_count,
                "required_approvals": quorum_res.required_approvals,
            },
        )

    db.flush()
    return vote, quorum_res


def schedule_access_window(
    db: Session,
    request_id: uuid.UUID,
    start_time: datetime,
    end_time: datetime,
    current_time: Optional[datetime] = None,
    actor_id: Optional[uuid.UUID] = None,
    actor_ip: Optional[str] = None,
) -> AccessWindow:
    """Convenience workflow: creates window and logs audit event."""
    window = create_access_window(
        db=db,
        request_id=request_id,
        start_time=start_time,
        end_time=end_time,
        current_time=current_time,
    )

    create_audit_event(
        db=db,
        action="ACCESS_WINDOW_SCHEDULED",
        result=AuditResult.SUCCESS,
        actor_id=actor_id,
        actor_ip=actor_ip,
        target_type="access_window",
        target_id=window.id,
        reason=f"Access window scheduled from {start_time.isoformat()} to {end_time.isoformat()}",
        extra_data={
            "request_id": str(request_id),
            "paper_id": str(window.paper_id),
            "start_time": start_time.isoformat(),
            "end_time": end_time.isoformat(),
        },
    )

    db.flush()
    return window


def deliver_question_paper_jit(
    db: Session,
    user_id: uuid.UUID,
    paper_id: uuid.UUID,
    key: Optional[bytes] = None,
    request_id: Optional[uuid.UUID] = None,
    current_time: Optional[datetime] = None,
    actor_ip: Optional[str] = None,
) -> SecureDecryptedBuffer:
    """
    Convenience workflow: executes JIT access authorization, decrypts paper,
    and returns a SecureDecryptedBuffer for memory-safe handling.
    """
    decryption_key = key or get_master_key()
    plaintext = execute_jit_paper_access(
        db=db,
        user_id=user_id,
        paper_id=paper_id,
        key=decryption_key,
        request_id=request_id,
        current_time=current_time,
        actor_ip=actor_ip,
    )
    return SecureDecryptedBuffer(plaintext)


def close_and_finalize_session(
    db: Session,
    paper_id: uuid.UUID,
    request_id: uuid.UUID,
    actor_id: Optional[uuid.UUID] = None,
    actor_ip: Optional[str] = None,
    reason: str = "Examination session completed normally",
) -> Dict[str, Any]:
    """Convenience alias for complete_access."""
    return complete_access(
        db=db,
        paper_id=paper_id,
        request_id=request_id,
        actor_id=actor_id,
        actor_ip=actor_ip,
        reason=reason,
    )

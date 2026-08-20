"""
TrustGuard Security Module.

Provides:
- Authenticated Encryption (AES-256-GCM)
- Integrity Hashing (SHA-256)
- Encrypted Fragment Distribution (sharding, validation, reconstruction)
- Quorum Authorization & Multi-Party Approval Service
- Just-In-Time (JIT) Access Validation & Access Window Service
- Security Audit Logging & Secure Lifecycle Completion
- Centralized Service Interface for Backend Controllers
"""
from security.crypto import (
    encrypt,
    decrypt,
    generate_integrity_hash,
    get_master_key,
    fragment_ciphertext,
    reconstruct_ciphertext,
    protect_and_fragment_paper,
    reconstruct_and_decrypt_paper,
    retrieve_paper_fragments,
)
from security.quorum import (
    QuorumDecision,
    QuorumResult,
    QuorumError,
    QuorumValidationError,
    UnauthorizedApproverError,
    InvalidApproverRoleError,
    DuplicateApprovalError,
    RequestNotPendingError,
    SelfApprovalError,
    AccessDeniedError,
    DEFAULT_APPROVER_ROLES,
    get_user_role_names,
    is_user_authorized_approver,
    calculate_quorum_counts,
    evaluate_quorum,
    cast_approval_vote,
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
from security.service import (
    # 11 Primary Service Interfaces for Backend Integration
    protect_paper,
    fragment_paper,
    validate_fragments,
    create_access_request,
    check_quorum,
    is_access_window_valid,
    authorize_access,
    reconstruct_paper,
    decrypt_paper,
    complete_access,
    create_audit_event,
    # High-level convenience workflows
    ingest_and_protect_paper,
    submit_access_request,
    approve_access_request,
    schedule_access_window,
    deliver_question_paper_jit,
    close_and_finalize_session,
)

__all__ = [
    # 11 Primary Service Interfaces for Backend Integration
    "protect_paper",
    "fragment_paper",
    "validate_fragments",
    "create_access_request",
    "check_quorum",
    "is_access_window_valid",
    "authorize_access",
    "reconstruct_paper",
    "decrypt_paper",
    "complete_access",
    "create_audit_event",
    # High-Level Orchestrated Workflows
    "ingest_and_protect_paper",
    "submit_access_request",
    "approve_access_request",
    "schedule_access_window",
    "deliver_question_paper_jit",
    "close_and_finalize_session",
    # Core Cryptography & Fragmentation
    "encrypt",
    "decrypt",
    "generate_integrity_hash",
    "get_master_key",
    "fragment_ciphertext",
    "reconstruct_ciphertext",
    "protect_and_fragment_paper",
    "reconstruct_and_decrypt_paper",
    "retrieve_paper_fragments",
    # Quorum Authorization
    "QuorumDecision",
    "QuorumResult",
    "QuorumError",
    "QuorumValidationError",
    "UnauthorizedApproverError",
    "InvalidApproverRoleError",
    "DuplicateApprovalError",
    "RequestNotPendingError",
    "SelfApprovalError",
    "AccessDeniedError",
    "DEFAULT_APPROVER_ROLES",
    "get_user_role_names",
    "is_user_authorized_approver",
    "calculate_quorum_counts",
    "evaluate_quorum",
    "cast_approval_vote",
    "expire_access_request",
    "check_paper_access_authorization",
    "assert_paper_access_authorized",
    # JIT Access & Access Window
    "AccessDecision",
    "WindowTimeState",
    "AccessValidationResult",
    "AccessControlError",
    "WindowScheduleError",
    "JITAccessDeniedError",
    "DEFAULT_ACCESS_ROLES",
    "create_access_window",
    "evaluate_window_time",
    "sync_window_status",
    "validate_jit_access",
    "execute_jit_paper_access",
    # Audit & Lifecycle Completion
    "AuditEventType",
    "sanitize_audit_metadata",
    "log_security_event",
    "record_threat_incident",
    "SecureDecryptedBuffer",
    "complete_access_session",
]

# TrustGuard — Security Service Interface Developer Guide

This document defines the official, stable service interfaces provided by the `security` module for the backend API controllers and route handlers.

The backend developer should call these services directly. **Do NOT re-implement or duplicate cryptographic logic, hashing, nonce generation, or shard math inside FastAPI route handlers.**

---

## 1. Quick Integration Overview

```python
from security import (
    # 11 Primary Service Interfaces
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
    # Result & Enum Models
    AccessDecision,
    WindowTimeState,
    AuditEventType,
    AuditResult,
    QuorumDecision,
    # Exceptions
    JITAccessDeniedError,
    FragmentValidationError,
    DuplicateApprovalError,
    InvalidApproverRoleError,
)
```

---

## 2. Detailed Service Specifications

---

### `1. protect_paper()`
Encrypts raw question paper content using AES-256-GCM and generates a canonical SHA-256 manifest hash.

```python
def protect_paper(
    db: Session,
    paper_id: uuid.UUID,
    plaintext_data: bytes,
    key: Optional[bytes] = None,
    actor_id: Optional[uuid.UUID] = None,
    actor_ip: Optional[str] = None,
) -> QuestionPaper:
```

- **Expected Input**:
  - `db`: Active SQLAlchemy database session.
  - `paper_id`: UUID of existing `QuestionPaper` record.
  - `plaintext_data`: Raw question paper content (`bytes`).
  - `key` *(Optional)*: 32-byte AES-256 master key. If omitted, uses environment key via `get_master_key()`.
  - `actor_id` *(Optional)*: UUID of user performing protection.
  - `actor_ip` *(Optional)*: Client IP address for audit trail.
- **Expected Output**:
  - Returns updated `QuestionPaper` instance in `PaperStatus.PROTECTED` status with `integrity_hash` and `protected_at` populated.
- **Possible Exceptions**:
  - `ValueError`: If paper is not found, `plaintext_data` is not `bytes`, or key is invalid length.
- **Authorization Requirements**:
  - Requester must hold `ADMIN` or `OFFICER` role.
- **Security Considerations**:
  - Plaintext is never stored in database or logs. Nonce (12 bytes) is generated using OS CSPRNG (`os.urandom`).

---

### `2. fragment_paper()`
Slices encrypted ciphertext into $N$ deterministic shards and stores them in `paper_fragments`.

```python
def fragment_paper(
    db: Session,
    paper_id: uuid.UUID,
    num_fragments: int = 5,
    ciphertext_payload: Optional[bytes] = None,
    actor_id: Optional[uuid.UUID] = None,
    actor_ip: Optional[str] = None,
) -> List[PaperFragment]:
```

- **Expected Input**:
  - `db`: Active SQLAlchemy session.
  - `paper_id`: UUID of protected `QuestionPaper`.
  - `num_fragments`: Number of shards to produce ($N \ge 1$, default: 5).
  - `ciphertext_payload` *(Optional)*: Ciphertext bytes if not cached on paper object.
  - `actor_id`, `actor_ip` *(Optional)*: Audit metadata.
- **Expected Output**:
  - Returns `List[PaperFragment]` with status `FragmentStatus.STORED`, continuous indices `[0 ... N-1]`, and individual SHA-256 digests.
- **Possible Exceptions**:
  - `ValueError`: If paper not found or has no encrypted ciphertext payload.
- **Authorization Requirements**:
  - Requester must hold `ADMIN` or `OFFICER` role.
- **Security Considerations**:
  - Slices only encrypted ciphertext. Never fragments plaintext.

---

### `3. validate_fragments()`
Validates shard completeness, index permutation $[0 \dots N-1]$, paper ownership, and individual SHA-256 hashes.

```python
def validate_fragments(
    fragments: Sequence[PaperFragment | FragmentPayload],
    expected_paper_id: Optional[uuid.UUID] = None,
    expected_count: Optional[int] = None,
) -> List[PaperFragment | FragmentPayload]:
```

- **Expected Input**:
  - `fragments`: Sequence of `PaperFragment` or `FragmentPayload` objects.
  - `expected_paper_id` *(Optional)*: Expected `QuestionPaper.id`.
  - `expected_count` *(Optional)*: Expected total shard count ($N$).
- **Expected Output**:
  - Returns sorted `List[FragmentLike]` ordered by `fragment_index` ($0$ to $N-1$).
- **Possible Exceptions**:
  - `MissingFragmentError`: Missing one or more shard indices.
  - `DuplicateFragmentError`: Duplicate shard index detected.
  - `FragmentPaperMismatchError`: Shard belonging to different paper ID.
  - `FragmentCountMismatchError`: Fragment count differs from expected.
  - `FragmentIntegrityError`: SHA-256 digest of shard data does not match stored tag.
- **Security Considerations**:
  - Mandatory pre-reconstruction gatekeeper. Blocks assembly if even a single bit was tampered with.

---

### `4. create_access_request()`
Registers a formal multi-party access request in `PENDING` state.

```python
def create_access_request(
    db: Session,
    paper_id: uuid.UUID,
    requested_by: uuid.UUID,
    request_type: RequestType = RequestType.RECONSTRUCT,
    reason: str = "Formal request for examination paper access",
    required_approvals: int = 3,
    actor_ip: Optional[str] = None,
) -> AccessRequest:
```

- **Expected Input**:
  - `paper_id`: Target `QuestionPaper.id`.
  - `requested_by`: User UUID submitting the request.
  - `request_type`: `RequestType.RECONSTRUCT`, `VIEW`, or `EMERGENCY`.
  - `reason`: Mandatory non-empty business justification string.
  - `required_approvals`: Quorum threshold ($M \ge 1$, default: 3).
- **Expected Output**:
  - Returns created `AccessRequest` in `RequestStatus.PENDING` status.
- **Possible Exceptions**:
  - `QuorumValidationError`: If user is inactive, paper is missing, or required approvals $< 1$.
- **Authorization Requirements**:
  - Authenticated active user with `OFFICER` or `ADMIN` role.

---

### `5. check_quorum()`
Evaluates current multi-party approver votes for an `AccessRequest` against the required threshold.

```python
def check_quorum(
    db: Session,
    request_id: uuid.UUID,
    reject_on_single_rejection: bool = False,
) -> QuorumResult:
```

- **Expected Input**:
  - `request_id`: UUID of `AccessRequest`.
  - `reject_on_single_rejection`: If `True`, a single rejection transitions request to `REJECTED`.
- **Expected Output**:
  - Returns `QuorumResult` dataclass:
    - `is_authorized: bool`
    - `decision: QuorumDecision` (`AUTHORIZED`, `REJECTED`, `PENDING`)
    - `approved_count: int`
    - `rejected_count: int`
    - `required_approvals: int`
- **Side Effects**:
  - Automatically transitions `AccessRequest.status` to `APPROVED` or `REJECTED` and `QuestionPaper.status` to `AUTHORIZED` when quorum is reached.

---

### `6. is_access_window_valid()`
Evaluates whether an access window is currently active and within `[start_time, end_time]`.

```python
def is_access_window_valid(
    db: Session,
    window_id: uuid.UUID,
    current_time: Optional[datetime] = None,
) -> Tuple[bool, WindowTimeState]:
```

- **Expected Input**:
  - `window_id`: UUID of `AccessWindow`.
  - `current_time` *(Optional)*: Reference timestamp (defaults to `utcnow`).
- **Expected Output**:
  - Returns `(is_valid: bool, time_state: WindowTimeState)`:
    - `BEFORE_WINDOW` $\rightarrow$ `is_valid = False`
    - `DURING_WINDOW` $\rightarrow$ `is_valid = True` (if not revoked)
    - `AFTER_WINDOW` $\rightarrow$ `is_valid = False`

---

### `7. authorize_access()`
Evaluates full 6-factor JIT access validation (`Identity + Permission + Request + Quorum + Time Window + Integrity`).

```python
def authorize_access(
    db: Session,
    user_id: uuid.UUID,
    paper_id: uuid.UUID,
    request_id: Optional[uuid.UUID] = None,
    current_time: Optional[datetime] = None,
    actor_ip: Optional[str] = None,
    allowed_roles: Optional[Set[str]] = None,
) -> AccessValidationResult:
```

- **Expected Input**:
  - `user_id`: Accessing user UUID.
  - `paper_id`: Target `QuestionPaper.id`.
  - `request_id` *(Optional)*: Specific `AccessRequest.id`.
  - `current_time` *(Optional)*: Reference time.
- **Expected Output**:
  - Returns `AccessValidationResult`:
    - `decision`: `AccessDecision.ALLOW` or `AccessDecision.DENY`
    - `is_allowed`: `True` / `False`
    - `reason`: Descriptive explanation
    - `checks`: Dict mapping each factor (`identity_valid`, `quorum_valid`, `time_window_valid`, etc.) to bool.
- **Security Considerations**:
  - Default-to-Deny: If any condition fails, returns `DENY` and logs `AuditLog(ACCESS_DENIED)` and `ThreatEvent`.

---

### `8. reconstruct_paper()`
Retrieves and reassembles stored shards into protected AES-256-GCM ciphertext.

```python
def reconstruct_paper(
    db: Session,
    paper_id: uuid.UUID,
    fragments: Optional[List[PaperFragment]] = None,
) -> bytes:
```

- **Expected Input**:
  - `paper_id`: `QuestionPaper.id`.
  - `fragments` *(Optional)*: Pre-queried shard list.
- **Expected Output**:
  - Returns complete `bytes` of protected payload `[12-byte Nonce] + [Ciphertext + 16-byte Tag]`.
- **Possible Exceptions**:
  - `FragmentValidationError`: If any shard is corrupted, missing, duplicate, or tampered with.

---

### `9. decrypt_paper()`
Authenticates and decrypts ciphertext payload and verifies canonical pre-fragmentation SHA-256 hash.

```python
def decrypt_paper(
    ciphertext_payload: bytes,
    key: Optional[bytes] = None,
    expected_manifest_hash: Optional[str] = None,
) -> bytes:
```

- **Expected Input**:
  - `ciphertext_payload`: Reassembled protected bytes.
  - `key` *(Optional)*: 32-byte AES-256 master key.
  - `expected_manifest_hash` *(Optional)*: `QuestionPaper.integrity_hash`.
- **Expected Output**:
  - Returns decrypted plaintext examination paper `bytes`.
- **Possible Exceptions**:
  - `DecryptionFailedError`: Cryptographic authentication tag mismatch or invalid key.
  - `FragmentIntegrityError`: Manifest hash mismatch after decryption.

---

### `10. complete_access()`
Concludes an access session, expires permissions, prevents replay, and records audit logs.

```python
def complete_access(
    db: Session,
    paper_id: uuid.UUID,
    request_id: uuid.UUID,
    actor_id: Optional[uuid.UUID] = None,
    actor_ip: Optional[str] = None,
    reason: str = "Access session completed normally",
) -> Dict[str, Any]:
```

- **Expected Input**:
  - `paper_id`: Target `QuestionPaper.id`.
  - `request_id`: `AccessRequest.id` to finalize.
  - `reason`: Justification for session termination.
- **Expected Output**:
  - Returns dict confirming:
    - `"session_state": "session closed"`
    - `"access_state": "access expired"`
    - `"replay_protection": "active"`
- **Security Considerations**:
  - Transitions `AccessWindow` to `CLOSED` and `AccessRequest` to `EXPIRED`. Any subsequent replay attempt is blocked and flagged as `ThreatEventType.REPLAY_ATTEMPT`.

---

### `11. create_audit_event()`
Records an immutable audit log entry with automatic secret redaction.

```python
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
```

- **Expected Input**:
  - `action`: Event name or `AuditEventType` enum (e.g. `ACCESS_GRANTED`, `PAPER_ENCRYPTED`).
  - `result`: `AuditResult.SUCCESS`, `FAILURE`, or `DENIED`.
  - `extra_data`: Arbitrary context dictionary.
- **Expected Output**:
  - Returns persisted `AuditLog` row.
- **Security Considerations**:
  - Passwords, keys, tokens, and plaintext exam contents in `extra_data` are automatically replaced with `"[REDACTED]"`.

---

## 3. Recommended FastAPI Route Pattern

```python
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from database.session import get_db
from security import (
    deliver_question_paper_jit,
    complete_access,
    JITAccessDeniedError,
)

router = APIRouter(prefix="/api/papers", tags=["Question Papers"])

@router.post("/{paper_id}/access")
def access_paper_endpoint(
    paper_id: str,
    db: Session = Depends(get_db),
    current_user = Depends(get_current_user),
):
    try:
        # Deliver via memory-safe buffer context manager
        with deliver_question_paper_jit(
            db=db,
            user_id=current_user.id,
            paper_id=uuid.UUID(paper_id),
        ) as buf:
            plaintext = buf.get_data()
            # Perform authorized in-memory operation (e.g. render / print)
            return {"status": "success", "length_bytes": len(plaintext)}
        # Buffer is automatically zeroed and wiped upon leaving block
    except JITAccessDeniedError as exc:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=str(exc),
        )
```

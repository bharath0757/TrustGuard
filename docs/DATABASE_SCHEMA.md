# TrustGuard — Database Schema Reference

> Branch: `feature/security-crypto` | ORM: SQLAlchemy 2.x | Migrations: Alembic | DB: PostgreSQL 15

---

## Lifecycle Overview

```
Question Paper
    │
    ▼ CREATED
    │  (metadata record created)
    ▼ PROTECTED
    │  (security layer encrypts content; integrity_hash set)
    ▼ FRAGMENTED
    │  (encrypted content sharded into paper_fragments; total_fragments set)
    ▼ AWAITING_APPROVAL
    │  (access_request submitted; approvers notified)
    ▼ AUTHORIZED
    │  (quorum met: COUNT(approvals WHERE decision=APPROVED) >= required_approvals)
    ▼ ACTIVE
    │  (access_window.status = ACTIVE; paper accessible within time window)
    ├──▶ EXPIRED   (window closed without explicit completion)
    └──▶ COMPLETED (lifecycle ended normally)
```

---

## Entity-Relationship Summary

```
users ──< user_roles >── roles
  │
  ├──< question_papers (created_by)
  │       │
  │       ├──< paper_fragments
  │       ├──< access_requests (requested_by → users)
  │       │       │
  │       │       ├──< approvals (approved_by → users)
  │       │       └──1 access_windows
  │       └──< access_windows
  │
  ├──< audit_logs (actor_id)
  └──< threat_events (actor_id, resolved_by)
```

No circular foreign key relationships exist.

---

## Table Definitions

### `users`
All system principals: human officers, admins, and non-human service accounts.

| Column | Type | Constraints | Notes |
|---|---|---|---|
| `id` | UUID | PK | |
| `email` | VARCHAR(255) | UNIQUE NOT NULL | Login identifier |
| `password_hash` | VARCHAR(255) | NOT NULL | bcrypt/Argon2id — **never plaintext** |
| `full_name` | VARCHAR(255) | NOT NULL | |
| `is_active` | BOOLEAN | NOT NULL DEFAULT true | Inactive = cannot authenticate |
| `is_system` | BOOLEAN | NOT NULL DEFAULT false | Non-human service account flag |
| `created_at` | TIMESTAMPTZ | NOT NULL | |
| `updated_at` | TIMESTAMPTZ | NOT NULL | |

**Indexes**: `email` (unique)

---

### `roles`
Named permission groups. Canonical values: `ADMIN`, `OFFICER`, `APPROVER`, `AUDITOR`, `SYSTEM`.

| Column | Type | Constraints | Notes |
|---|---|---|---|
| `id` | UUID | PK | |
| `name` | VARCHAR(50) | UNIQUE NOT NULL | Role identifier |
| `description` | TEXT | | |

---

### `user_roles`
Many-to-many assignment of roles to users with grant provenance.

| Column | Type | Constraints | Notes |
|---|---|---|---|
| `user_id` | UUID | PK, FK→users CASCADE | |
| `role_id` | UUID | PK, FK→roles CASCADE | |
| `granted_at` | TIMESTAMPTZ | NOT NULL | |
| `granted_by` | UUID | FK→users SET NULL | Admin who granted the role |

**Primary Key**: `(user_id, role_id)` — prevents duplicate role assignments.

---

### `question_papers`
Metadata record for each examination question paper. **No content ever stored here.**

| Column | Type | Constraints | Notes |
|---|---|---|---|
| `id` | UUID | PK | |
| `exam_identifier` | VARCHAR(100) | NOT NULL | e.g. `GATE-2026-CS` |
| `paper_name` | VARCHAR(255) | NOT NULL | |
| `status` | ENUM(paperstatus) | NOT NULL DEFAULT 'CREATED' | 8-state lifecycle |
| `created_by` | UUID | FK→users SET NULL | |
| `protected_at` | TIMESTAMPTZ | | Set on PROTECTED transition |
| `fragmented_at` | TIMESTAMPTZ | | Set on FRAGMENTED transition |
| `completed_at` | TIMESTAMPTZ | | Set on COMPLETED/EXPIRED |
| `integrity_hash` | VARCHAR(128) | | SHA-256/512 hex of content manifest |
| `total_fragments` | INTEGER | | Set after fragmentation |
| `created_at` | TIMESTAMPTZ | NOT NULL | |
| `updated_at` | TIMESTAMPTZ | NOT NULL | |

**ENUM `paperstatus`**: `CREATED`, `PROTECTED`, `FRAGMENTED`, `AWAITING_APPROVAL`, `AUTHORIZED`, `ACTIVE`, `EXPIRED`, `COMPLETED`

**Indexes**: `status`, `exam_identifier`, `created_by`, `(status, exam_identifier)`

---

### `paper_fragments`
Encrypted shards of a question paper.

| Column | Type | Constraints | Notes |
|---|---|---|---|
| `id` | UUID | PK | |
| `paper_id` | UUID | FK→question_papers CASCADE NOT NULL | |
| `fragment_index` | SMALLINT | NOT NULL | Zero-based shard index |
| `fragment_data` | BYTEA | NOT NULL | Raw ciphertext — **never plaintext** |
| `integrity_hash` | VARCHAR(128) | NOT NULL | Hash of `fragment_data` |
| `status` | ENUM(fragmentstatus) | NOT NULL DEFAULT 'PENDING' | |
| `created_at` | TIMESTAMPTZ | NOT NULL | |
| `updated_at` | TIMESTAMPTZ | NOT NULL | |

**ENUM `fragmentstatus`**: `PENDING`, `STORED`, `CORRUPTED`, `DELETED`

**Unique**: `(paper_id, fragment_index)` — no duplicate shards per paper.  
**Index**: `paper_id`

---

### `access_requests`
Formal request by a user to access a protected paper.

| Column | Type | Constraints | Notes |
|---|---|---|---|
| `id` | UUID | PK | |
| `paper_id` | UUID | FK→question_papers CASCADE NOT NULL | |
| `requested_by` | UUID | FK→users RESTRICT NOT NULL | |
| `request_type` | ENUM(requesttype) | NOT NULL | |
| `status` | ENUM(requeststatus) | NOT NULL DEFAULT 'PENDING' | |
| `required_approvals` | INTEGER | NOT NULL DEFAULT 2 | **Quorum threshold** |
| `reason` | TEXT | NOT NULL | Mandatory justification |
| `decided_at` | TIMESTAMPTZ | | When status left PENDING |
| `created_at` | TIMESTAMPTZ | NOT NULL | |
| `updated_at` | TIMESTAMPTZ | NOT NULL | |

**ENUM `requesttype`**: `VIEW`, `RECONSTRUCT`, `EMERGENCY`  
**ENUM `requeststatus`**: `PENDING`, `APPROVED`, `REJECTED`, `EXPIRED`, `WITHDRAWN`

**Indexes**: `paper_id`, `requested_by`, `status`, `(paper_id, status)`

---

### `approvals`
Individual approver votes on an access request.

| Column | Type | Constraints | Notes |
|---|---|---|---|
| `id` | UUID | PK | |
| `request_id` | UUID | FK→access_requests CASCADE NOT NULL | |
| `approved_by` | UUID | FK→users RESTRICT NOT NULL | |
| `decision` | ENUM(approvaldecision) | NOT NULL | |
| `reason` | TEXT | | Optional justification |
| `created_at` | TIMESTAMPTZ | NOT NULL | Vote timestamp — immutable |

**ENUM `approvaldecision`**: `APPROVED`, `REJECTED`

**Unique**: `(request_id, approved_by)` — one vote per approver per request.

**Quorum query**:
```sql
SELECT COUNT(*) FROM approvals
WHERE request_id = :rid AND decision = 'APPROVED';
-- Compare against access_requests.required_approvals
```

---

### `access_windows`
Time-bounded window during which a paper may be accessed.

| Column | Type | Constraints | Notes |
|---|---|---|---|
| `id` | UUID | PK | |
| `paper_id` | UUID | FK→question_papers CASCADE NOT NULL | |
| `request_id` | UUID | FK→access_requests CASCADE UNIQUE NOT NULL | One window per request |
| `start_time` | TIMESTAMPTZ | NOT NULL | |
| `end_time` | TIMESTAMPTZ | NOT NULL | |
| `status` | ENUM(windowstatus) | NOT NULL DEFAULT 'SCHEDULED' | |
| `created_at` | TIMESTAMPTZ | NOT NULL | |
| `updated_at` | TIMESTAMPTZ | NOT NULL | |

**ENUM `windowstatus`**: `SCHEDULED`, `ACTIVE`, `CLOSED`, `REVOKED`

**Check**: `end_time > start_time` — enforced at the database level.  
**Unique**: `request_id` — exactly one window per approved request.  
**Indexes**: `paper_id`, `status`, `(paper_id, status)`, `(start_time, end_time)`

---

### `audit_logs`
**Append-only, immutable** record of every system action.

> [!IMPORTANT]
> This table has **no `updated_at` column** by design. Rows must never be updated after insert.

| Column | Type | Constraints | Notes |
|---|---|---|---|
| `id` | UUID | PK | |
| `timestamp` | TIMESTAMPTZ | NOT NULL server_default=now() | Event time — immutable |
| `actor_id` | UUID | FK→users SET NULL NULLABLE | NULL for system/unauthenticated |
| `actor_ip` | INET | | Source IP (IPv4 or IPv6) |
| `action` | VARCHAR(100) | NOT NULL | e.g. `paper.status_changed` |
| `target_type` | VARCHAR(50) | | e.g. `question_paper` |
| `target_id` | UUID | | UUID of affected entity |
| `result` | ENUM(auditresult) | NOT NULL | |
| `reason` | TEXT | | Explanation of result |
| `extra_data` | JSONB | | Arbitrary structured context |

**ENUM `auditresult`**: `SUCCESS`, `FAILURE`, `DENIED`

**Indexes**: `timestamp DESC`, `actor_id`, `action`, `(target_type, target_id)`

---

### `threat_events`
Security incidents raised by detection logic or the attack simulator.

| Column | Type | Constraints | Notes |
|---|---|---|---|
| `id` | UUID | PK | |
| `timestamp` | TIMESTAMPTZ | NOT NULL | |
| `event_type` | ENUM(threateventtype) | NOT NULL | |
| `severity` | ENUM(threatseverity) | NOT NULL | |
| `actor_id` | UUID | FK→users SET NULL NULLABLE | |
| `actor_ip` | INET | | |
| `target_type` | VARCHAR(50) | | |
| `target_id` | UUID | | |
| `description` | TEXT | NOT NULL | |
| `extra_data` | JSONB | | |
| `resolved` | BOOLEAN | NOT NULL DEFAULT false | |
| `resolved_at` | TIMESTAMPTZ | | |
| `resolved_by` | UUID | FK→users SET NULL NULLABLE | |

**ENUM `threateventtype`**: `UNAUTHORIZED_ACCESS`, `INVALID_QUORUM`, `INTEGRITY_FAILURE`, `DENIED_OPERATION`, `REPLAY_ATTEMPT`, `BRUTE_FORCE`  
**ENUM `threatseverity`**: `LOW`, `MEDIUM`, `HIGH`, `CRITICAL`

**Indexes**: `timestamp DESC`, `event_type`, `severity`, `resolved`, `actor_id`, `(target_type, target_id)`  
**Partial index** (PostgreSQL): unresolved events by severity for dashboard queries.

---

## Indexes Summary

| Table | Index | Columns |
|---|---|---|
| users | ix_users_email | email |
| question_papers | ix_question_papers_status | status |
| question_papers | ix_question_papers_exam | exam_identifier |
| question_papers | ix_question_papers_created_by | created_by |
| question_papers | ix_question_papers_status_exam | (status, exam_identifier) |
| paper_fragments | ix_paper_fragments_paper_id | paper_id |
| access_requests | ix_access_requests_paper | paper_id |
| access_requests | ix_access_requests_user | requested_by |
| access_requests | ix_access_requests_status | status |
| access_requests | ix_access_requests_paper_status | (paper_id, status) |
| approvals | ix_approvals_request | request_id |
| approvals | ix_approvals_approver | approved_by |
| access_windows | ix_access_windows_paper | paper_id |
| access_windows | ix_access_windows_status | status |
| access_windows | ix_access_windows_paper_status | (paper_id, status) |
| access_windows | ix_access_windows_time_range | (start_time, end_time) |
| audit_logs | ix_audit_logs_timestamp_desc | timestamp DESC |
| audit_logs | ix_audit_logs_actor_id | actor_id |
| audit_logs | ix_audit_logs_action | action |
| audit_logs | ix_audit_logs_target | (target_type, target_id) |
| threat_events | ix_threat_events_timestamp | timestamp |
| threat_events | ix_threat_events_event_type | event_type |
| threat_events | ix_threat_events_severity | severity |
| threat_events | ix_threat_events_resolved | resolved |
| threat_events | ix_threat_events_actor_id | actor_id |
| threat_events | ix_threat_events_target | (target_type, target_id) |

---

## Constraints Summary

| Table | Constraint | Type | Definition |
|---|---|---|---|
| users | uq_users_email | UNIQUE | email |
| roles | uq_roles_name | UNIQUE | name |
| user_roles | PK | PRIMARY KEY | (user_id, role_id) |
| paper_fragments | uq_paper_fragments_paper_index | UNIQUE | (paper_id, fragment_index) |
| approvals | uq_approvals_request_approver | UNIQUE | (request_id, approved_by) |
| access_windows | uq_access_windows_request | UNIQUE | request_id |
| access_windows | ck_access_windows_end_after_start | CHECK | end_time > start_time |

---

## Migration

```bash
# Initial schema (run once against a fresh database)
alembic upgrade head

# Check migration history
alembic history --verbose

# Generate a new migration after model changes
alembic revision --autogenerate -m "describe change"
```

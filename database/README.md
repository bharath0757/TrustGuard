# Database Module

**Owner**: @SECURITY_USERNAME

This module defines the PostgreSQL schema for TrustGuard using **SQLAlchemy 2.x** (ORM) and **Alembic** (migrations). It covers the complete question-paper security lifecycle from creation through audit.

---

## Directory Structure

```
database/
├── __init__.py             # Package — re-exports Base, engine, SessionLocal, get_db
├── base.py                 # DeclarativeBase + TimestampMixin
├── session.py              # Engine, SessionLocal, get_db() FastAPI dependency
├── models/
│   ├── __init__.py         # Re-exports all models (ensures Base.metadata is populated)
│   ├── user.py             # User, Role, UserRole
│   ├── paper.py            # QuestionPaper, PaperStatus
│   ├── fragment.py         # PaperFragment, FragmentStatus
│   ├── access.py           # AccessRequest, Approval, AccessWindow (+ enums)
│   └── audit.py            # AuditLog, ThreatEvent (+ enums)
└── migrations/
    ├── env.py              # Alembic environment
    ├── script.py.mako      # Migration script template
    └── versions/
        └── 0001_initial_schema.py   # Creates all 10 tables
```

---

## Tables (10)

| Table | Purpose |
|---|---|
| `users` | All system principals (officers, admins, service accounts) |
| `roles` | Named permission groups |
| `user_roles` | Many-to-many user↔role with grant provenance |
| `question_papers` | Paper metadata + 8-state lifecycle |
| `paper_fragments` | Encrypted shards (BYTEA) with integrity hashes |
| `access_requests` | Formal access requests with quorum threshold |
| `approvals` | Individual approver votes |
| `access_windows` | Time-bounded access periods |
| `audit_logs` | Immutable append-only event log |
| `threat_events` | Security incidents with resolution tracking |

---

## Responsibilities
- Database schemas and migrations
- Secure storage of encrypted fragment data (BYTEA — never plaintext)
- Audit trail persistence (immutable `audit_logs`)
- State tracking for question papers (`PaperStatus` 8-state lifecycle)
- Quorum calculation support (approvals COUNT vs `required_approvals`)

---

## Running Migrations

```bash
# From the project root (D:\TrustGuard)
export DATABASE_URL="postgresql://user:password@localhost:5432/trustguard"

# Apply all migrations
alembic upgrade head

# Roll back one migration
alembic downgrade -1

# Check current revision
alembic current
```

---

## Running Model Tests

```bash
# From project root — no running PostgreSQL needed (uses SQLite in-memory)
pip install -r backend/requirements.txt
pytest tests/database/ -v
```

---

## Security Rules

1. **Never store plaintext question-paper content** — `fragment_data` holds ciphertext only.
2. **Never store passwords in plaintext** — `users.password_hash` stores KDF output only.
3. **Never modify audit log rows** — `audit_logs` has no `updated_at`; rows are immutable.
4. **Encryption keys are NOT stored** in any table — managed by the security layer.

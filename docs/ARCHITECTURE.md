# TrustGuard Architecture

## High-Level Flow

```
React Frontend
      ↓
FastAPI Backend (Route Controllers & Dependency Injection)
      ↓
Security Service Boundaries (security/service.py)
  ├── Authenticated Encryption (AES-256-GCM)
  ├── Encrypted Fragment Distribution (SHA-256 Sharding)
  ├── Multi-Party Quorum Authorization (Multi-Party Approval Engine)
  ├── Just-In-Time Access Validation (6-Factor Security Formula)
  └── Audit Logging & Secure Lifecycle Completion
      ↓
Database Models & Audit Persistence (SQLAlchemy / PostgreSQL)
```

## Service Boundaries

The backend layer communicates with security components strictly through high-level service interfaces defined in [`docs/SECURITY_SERVICE_GUIDE.md`](file:///d:/TrustGuard/docs/SECURITY_SERVICE_GUIDE.md). Route handlers never manipulate cryptographic nonces, raw key material, or shard math directly.

# TrustGuard Backend API

Zero-Trust Ephemeral Examination Question-Paper Distribution System built with FastAPI.

## Key Features & Security Design

1. **Zero Persistent Plaintext Storage**: Plaintext question papers and decryption keys are **never** stored in PostgreSQL. Database holds non-sensitive metadata (SHA-256 hash, schedules, guardian assignments, audit logs).
2. **Ephemeral RAM Storage**: Encrypted payload chunks and temporary key shares reside in memory (Redis with TTL or thread-safe RAM fallback store).
3. **Multi-Party Threshold Consensus ($k$-of-$n$)**: Exam status remains locked until $k$ out of $n$ designated Key Guardians submit cryptographic approvals.
4. **Just-In-Time (JIT) Ephemeral Streaming**: Delivers encrypted streams from RAM via FastAPI `StreamingResponse` with time-lock validation and dynamic traceability watermarking.
5. **Crypto Adapter Architecture**: Cryptographic primitives are cleanly encapsulated under `app/crypto_wrapper/interface.py`, ready for integration by the cryptography team.

---

## Installation & Setup

### Prerequisites
- Python 3.10+
- (Optional) Redis server (if Redis is not running, TrustGuard automatically falls back to an in-memory TTL store).

### 1. Install Dependencies
```bash
cd backend
pip install -r requirements.txt
```

### 2. Environment Configuration
(Optional) Create a `.env` file in `backend/`:
```env
SECRET_KEY=trustguard_secure_jwt_secret_key_2026
DATABASE_URL=sqlite+aiosqlite:///./trustguard.db
REDIS_URL=redis://localhost:6379/0
```

---

## Running the Automated Test Suite

Run pytest targeting the `tests/` directory:

```bash
pytest backend/tests
```

Or from inside `backend/`:
```bash
pytest tests/
```

---

## Running the Backend Server

Start the local FastAPI development server:

```bash
python backend/main.py
```

Or using `uvicorn` directly:
```bash
uvicorn backend.main:app --host 0.0.0.0 --port 8000 --reload
```

The server will be accessible at `http://localhost:8000`.

---

## API Documentation & Endpoints

Interactive OpenAPI Swagger documentation:
- **Swagger UI**: `http://localhost:8000/docs`
- **ReDoc**: `http://localhost:8000/redoc`

### Base Endpoints
- `GET /`: Welcome message & online status
- `GET /health`: System health check

### API v1 Endpoints (`/api/v1`)
- **Authentication**: `POST /auth/register`, `POST /auth/login`, `GET /auth/me`
- **Exams**: `POST /exams/`, `GET /exams/`, `GET /exams/{id}`, `POST /exams/{id}/guardians`, `POST /exams/{id}/stage-payload`
- **Consensus**: `POST /consensus/{id}/approve`, `GET /consensus/{id}/status`
- **Distribution**: `GET /distribution/{id}/stream`, `POST /distribution/{id}/purge`
- **Audit**: `GET /audit/events`, `POST /audit/events`

# TrustGuard

**TrustGuard** is a Zero-Trust cybersecurity prototype designed to protect high-stakes examination question papers from unauthorized access, premature leakage, and single-point-of-compromise vulnerabilities.

---

## Architecture Overview

* `frontend/`: React 19 + Vite dashboard with multi-party approval controls, threat alerts, audit trail, and attack simulator.
* `backend/`: FastAPI REST API service with JWT authentication, role-based access control, ephemeral distribution, and health monitoring.
* `security/`: Cryptographic engine implementing AES-256-GCM authenticated encryption, SHA-256 sharding, k-of-n quorum consensus, 6-factor JIT access validation, and memory-safe buffers.
* `database/`: PostgreSQL / SQLite SQLAlchemy ORM models, Alembic migrations, and seed scripts.
* `attack-simulator/`: Controlled cyberattack simulation module.
* `scripts/`: Diagnostic and verification utilities (`scripts/verify_setup.py`).
* `tests/`: Comprehensive unit, integration, and security failure test suites (130+ tests).

---

## Quick Start (Docker Compose)

The easiest way to run the complete TrustGuard stack:

```bash
# 1. Clone the repository and configure environment
cp .env.example .env

# 2. Build and launch all services (PostgreSQL, Backend API, Frontend Dashboard)
docker-compose up --build
```

Services will be accessible at:
* **Frontend Dashboard**: `http://localhost:5173`
* **Backend REST API**: `http://localhost:8000`
* **API Interactive Docs**: `http://localhost:8000/docs`
* **Health Endpoint**: `http://localhost:8000/health`
* **PostgreSQL Database**: `localhost:5432`

---

## Local Bare-Metal Development Setup

### 1. Prerequisites
* Python 3.9+ with `pip`
* Node.js 18+ with `npm`
* PostgreSQL 15+ (or automatic local SQLite fallback for standalone testing)
* Redis (optional; automatically falls back to in-memory TTL store)

### 2. Environment Configuration
```bash
cp .env.example .env
```

Generate a secure 32-byte master key for development:
```bash
python -c "import secrets, base64; print(base64.b64encode(secrets.token_bytes(32)).decode())"
```
Paste this value into `.env` under `TRUSTGUARD_MASTER_KEY`.

### 3. Install Python Dependencies
```bash
pip install -e .
pip install -r backend/requirements.txt
```

### 4. Database Setup & Migrations
```bash
# Apply migrations (PostgreSQL)
alembic upgrade head

# Seed development data
python -m database.seed
```

### 5. Start Backend Service
```bash
cd backend
uvicorn main:app --host 0.0.0.0 --port 8000 --reload
```

### 6. Start Frontend Dashboard
```bash
cd frontend
npm install
npm run dev
```

---

## Verification & Health Checks

Verify your end-to-end setup and dependencies in one step:
```bash
python scripts/verify_setup.py
```

Run the automated test suites:
```bash
# Run security & database test suite
pytest tests

# Run backend API test suite
pytest backend/tests
```

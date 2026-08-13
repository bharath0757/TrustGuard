# TrustGuard

TrustGuard is a Zero-Trust cybersecurity prototype designed for protecting high-stakes examination question papers.

## Project Objective
The goal is to implement a secure lifecycle for question papers that enforces Zero-Trust principles, including multi-party authorization, cryptographic fragmentation, and just-in-time access, while maintaining a tamper-proof audit trail.

## High-Level Architecture
- **React Frontend**: User dashboards and interfaces
- **FastAPI Backend**: Orchestration, API, and access control
- **Security & Cryptography**: Encryption and quorum logic
- **Database / Audit**: PostgreSQL storage for fragments and immutable logs
- **Attack Simulator**: Controlled testing of security defenses

## Repository Structure
- `/frontend/` - React/Vite/Tailwind UI
- `/backend/` - FastAPI backend
- `/security/` - Cryptography and Zero-Trust logic
- `/database/` - PostgreSQL schemas and migrations
- `/attack-simulator/` - Simulated threats
- `/tests/` - Integration and E2E tests
- `/docs/` - Architecture, API specs, and development guides

## Team Ownership
- `/frontend/` → @FRONTEND_USERNAME
- `/backend/` → @BACKEND_USERNAME
- `/security/` → @SECURITY_USERNAME
- `/database/` → @SECURITY_USERNAME
- `/attack-simulator/` → @TESTING_USERNAME
- `/tests/` → @TESTING_USERNAME
- `/docs/` → @TEAM_LEAD_USERNAME

## Getting Started

### Prerequisites
- Docker and Docker Compose
- Git
- Python 3.10+
- Node.js 18+

### Clone the Repository
```bash
git clone https://github.com/bharath0757/TrustGuard.git
cd TrustGuard
```

### Running Locally
We use Docker Compose to simplify local development.
1. Copy the example environment file: `cp .env.example .env`
2. Run the services: `docker-compose up --build`

### Git Workflow & Rules
- **No Direct Pushes**: Nobody directly pushes to `main`.
- **Feature Branches**: Developers work on feature branches (e.g., `feature/frontend`).
- **Pull Requests**: Pull requests are required to merge into `develop` or `main`.
- **Reviews**: Security and database changes require explicit review.
- **Testing**: All tests must pass before merging.
- **Security**: NEVER commit secrets or actual `.env` files.

For full developer instructions, please see [Development Guide](docs/DEVELOPMENT_GUIDE.md).

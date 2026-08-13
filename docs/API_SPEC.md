# API Specification (DRAFT / PLANNED)

This document contains the initial planned API structure.
*Note: Do not implement all these endpoints yet. They are marked as PLANNED / CONTRACT DRAFT.*

## Authentication
- `POST /api/auth/login`

## Question Papers
- `POST /api/papers`
- `GET /api/papers`
- `POST /api/papers/{id}/encrypt`
- `POST /api/papers/{id}/fragment`
- `POST /api/papers/{id}/approve`
- `GET /api/papers/{id}/quorum`
- `POST /api/papers/{id}/decrypt`

## Security & Attacks
- `POST /api/attacks/simulate`
- `GET /api/threats`

## Audit & Monitoring
- `GET /api/audit`
- `GET /api/dashboard`

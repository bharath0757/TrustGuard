# TrustGuard Backend

This is the backend service for TrustGuard, a Zero-Trust cybersecurity prototype for protecting high-stakes examination question papers.

## Project Structure

* `database/`: PostgreSQL database schema, SQLAlchemy ORM models, Alembic migrations, and seed scripts.
* `security/`: Cryptographic layer for encrypting, decrypting, and fragmenting exam papers. (TODO)
* `backend/`: FastAPI application providing the REST API. (TODO)

## Database Setup

The database requires PostgreSQL 15+. 

### 1. Environment Variables

Copy the `.env.example` file to `.env`:

```bash
cp .env.example .env
```

Ensure the `DATABASE_URL` matches your local setup. If you use Docker, the default values will work out of the box.

### 2. Start PostgreSQL

Use Docker Compose to spin up the PostgreSQL database:

```bash
docker-compose up -d postgres
```

### 3. Run Migrations

To create the tables in your empty database, run the Alembic migrations:

```bash
alembic upgrade head
```

### 4. Seed Development Data

To populate the database with safe development data (users, roles, sample papers, etc.), run the seed script:

```bash
python -m database.seed
```

**Security Note:** The seed script uses fake password hashes and random byte sequences for fragment data. It does not contain any real credentials or actual examination content.

## Testing

The database models are fully covered by tests that run against an in-memory SQLite database, meaning you can run tests without a running PostgreSQL instance.

Run the tests using pytest:

```bash
pytest tests/database/ -v
```

"""
TrustGuard Environment, Backend, Database, and Cryptographic Health Verification Script.

Run this script to validate end-to-end integration readiness:
    python scripts/verify_setup.py

Checks performed:
1. Environment variables & secret configuration
2. Cryptographic master key and AES-256-GCM cipher readiness
3. Database connectivity and ORM schema readiness
4. Backend API application startup & health check endpoints
5. Ephemeral RAM data store (Redis / in-memory fallback)
6. Frontend build asset presence
"""

import os
import sys
import asyncio
from pathlib import Path

# Add project root and backend to sys.path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))
sys.path.insert(0, str(PROJECT_ROOT / "backend"))


def print_step(title: str):
    print(f"\n[*] {title}")


def print_pass(msg: str):
    print(f"    [PASS] {msg}")


def print_warn(msg: str):
    print(f"    [WARN] {msg}")


def print_fail(msg: str):
    print(f"    [FAIL] {msg}")


async def verify_environment():
    print_step("Checking Environment Variables & Secret Configuration...")
    db_url = os.environ.get("DATABASE_URL")
    if db_url:
        print_pass("DATABASE_URL is set (credentials sanitized for display)")
    else:
        print_warn("DATABASE_URL not set in active shell (using local SQLite fallback sqlite+aiosqlite:///./trustguard.db)")

    master_key = os.environ.get("TRUSTGUARD_MASTER_KEY")
    if master_key:
        print_pass("TRUSTGUARD_MASTER_KEY is configured")
    else:
        print_warn("TRUSTGUARD_MASTER_KEY not in env (using test/development key generator)")

    app_env = os.environ.get("APP_ENV", "development")
    print_pass(f"APP_ENV: {app_env}")
    return True


async def verify_crypto():
    print_step("Checking Cryptographic Engine & Master Key...")
    try:
        from security.crypto.key_manager import generate_master_key, get_master_key
        from security.crypto.encryption import encrypt, decrypt
        from security.crypto.integrity import generate_integrity_hash

        if not os.environ.get("TRUSTGUARD_MASTER_KEY"):
            ephemeral_key = generate_master_key()
            os.environ["TRUSTGUARD_MASTER_KEY"] = ephemeral_key
            print_warn("TRUSTGUARD_MASTER_KEY generated dynamically for session testing")

        key = get_master_key()
        assert len(key) == 32, "Key length must be 32 bytes"
        print_pass("Master encryption key loaded and validated (32-byte AES-256 key)")

        test_data = b"TrustGuard Zero-Trust Question Paper Verification"
        encrypted_payload = encrypt(test_data, key=key)
        decrypted = decrypt(encrypted_payload, key=key)
        assert decrypted == test_data, "Decryption roundtrip verification failed"
        print_pass("AES-256-GCM encryption & authenticated decryption verified")

        h = generate_integrity_hash(test_data)
        assert h.startswith("sha256:") and len(h) == 71, "SHA-256 digest format mismatch"
        print_pass("SHA-256 cryptographic integrity hashing verified (sha256:<hex>)")
    except Exception as e:
        print_fail(f"Cryptographic engine error: {e}")
        return False
    return True


async def verify_database():
    print_step("Checking Database Connectivity & Schema...")
    try:
        from backend.app.db.database import engine, get_db, init_db
        from sqlalchemy import text

        await init_db()
        print_pass("Database schema initialized / verified")

        async for session in get_db():
            result = await session.execute(text("SELECT 1"))
            val = result.scalar()
            assert val == 1, "SELECT 1 test failed"
            print_pass("Database query execution verified (SELECT 1 OK)")
            break
    except Exception as e:
        print_fail(f"Database error: {e}")
        return False
    return True


async def verify_ephemeral_store():
    print_step("Checking Ephemeral RAM Store (Redis / Fallback)...")
    try:
        from backend.app.db.ephemeral import get_ephemeral_store
        store = get_ephemeral_store()

        test_chunks = [b"chunk_0_data", b"chunk_1_data"]
        await store.store_payload_chunks("test-exam-001", test_chunks, ttl_seconds=60)
        retrieved = await store.get_payload_chunks("test-exam-001")
        assert retrieved == test_chunks, "Ephemeral chunk retrieval mismatch"
        await store.purge_exam_data("test-exam-001")
        purged = await store.get_payload_chunks("test-exam-001")
        assert len(purged) == 0, "Ephemeral purge failed"

        mode = "In-Memory TTL Fallback" if store._use_fallback else "Redis"
        print_pass(f"Ephemeral RAM store verified ({mode})")
        return True
    except Exception as e:
        print_fail(f"Ephemeral store error: {e}")
        return False


async def verify_backend_api():
    print_step("Checking Backend FastAPI App & Health Endpoints...")
    try:
        from httpx import ASGITransport, AsyncClient
        from backend.main import app

        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            root_res = await client.get("/")
            assert root_res.status_code == 200
            print_pass(f"GET / -> 200 OK ({root_res.json().get('status')})")

            health_res = await client.get("/health")
            assert health_res.status_code == 200
            data = health_res.json()
            print_pass(f"GET /health -> 200 OK (Status: {data.get('status')}, DB: {data.get('database')}, Ephemeral: {data.get('ephemeral_store')})")

            v1_health_res = await client.get("/api/v1/health")
            assert v1_health_res.status_code == 200
            print_pass("GET /api/v1/health -> 200 OK")
        return True
    except Exception as e:
        print_fail(f"Backend API verification error: {e}")
        return False


async def verify_frontend_build():
    print_step("Checking Frontend Build Artifacts...")
    dist_dir = PROJECT_ROOT / "frontend" / "dist"
    index_html = dist_dir / "index.html"
    if index_html.exists():
        print_pass(f"Frontend production bundle verified in {dist_dir.name}/")
    else:
        print_warn("Frontend dist/ not built yet. Run 'npm run build' inside frontend/ directory.")
    return True


async def main():
    print("=" * 70)
    print("      TrustGuard End-to-End System Health & Verification Engine      ")
    print("=" * 70)

    results = [
        await verify_environment(),
        await verify_crypto(),
        await verify_database(),
        await verify_ephemeral_store(),
        await verify_backend_api(),
        await verify_frontend_build(),
    ]

    print("\n" + "=" * 70)
    if all(results):
        print(" [OK] ALL INTEGRATION CHECKS PASSED: SYSTEM IS READY FOR STARTUP")
    else:
        print(" [!] SOME INTEGRATION CHECKS FAILED OR GENERATED WARNINGS")
    print("=" * 70)


if __name__ == "__main__":
    asyncio.run(main())

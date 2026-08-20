"""TrustGuard Backend Main Entrypoint."""

import logging
from contextlib import asynccontextmanager
from fastapi import Depends, FastAPI, Response, status
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.router import api_router
from app.core.config import settings
from app.db.database import get_db, get_database_engine, init_db

# Configure backend logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger("trustguard.main")


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan context manager for setup and teardown."""
    logger.info("TrustGuard starting up (v%s)...", settings.VERSION)
    try:
        await init_db()
        logger.info("Database schema verified and ready.")
    except Exception as exc:
        logger.error("Error initializing database schema during startup: %s", exc, exc_info=True)
        # In serverless environments, avoid killing worker if DB is warming up
    yield
    logger.info("TrustGuard shutting down...")


app = FastAPI(
    title="TrustGuard API",
    description="Zero-Trust Ephemeral Question-Paper Distribution Backend API",
    version=settings.VERSION,
    lifespan=lifespan,
)

# Enable CORS for frontend compatibility
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Register API Router under /api/v1
app.include_router(api_router, prefix="/api/v1")


@app.get("/")
@app.get("/api")
def read_root():
    return {
        "title": "TrustGuard API",
        "status": "online",
        "message": "Welcome to TrustGuard Zero-Trust Distribution API",
        "documentation": "/docs",
        "version": settings.VERSION,
    }


@app.get("/health")
@app.get("/api/health")
async def root_health_check(response: Response, db: AsyncSession = Depends(get_db)):
    """Root health check for load balancers and deployment monitoring with live DB verification."""
    engine_dialect = "unknown"
    try:
        engine = get_database_engine()
        engine_dialect = engine.dialect.name
    except Exception:
        pass

    try:
        result = await db.execute(text("SELECT 1"))
        val = result.scalar()
        if val != 1:
            raise ValueError(f"Unexpected query scalar: {val}")

        return {
            "status": "healthy",
            "database": "connected",
            "engine": engine_dialect,
            "version": settings.VERSION,
        }
    except Exception as exc:
        logger.error("Root health check failed: %s", exc, exc_info=True)
        response.status_code = status.HTTP_503_SERVICE_UNAVAILABLE
        return {
            "status": "unhealthy",
            "database": "disconnected",
            "engine": engine_dialect,
            "error": "Database connectivity check failed",
            "version": settings.VERSION,
        }


if __name__ == "__main__":
    import uvicorn

    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)

"""Database and system health check API endpoints."""

import logging
from fastapi import APIRouter, Depends, Response, status
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.db.database import get_db, get_database_engine

logger = logging.getLogger("trustguard.health")

router = APIRouter(tags=["Health"])


@router.get("/health")
async def health_check(response: Response, db: AsyncSession = Depends(get_db)):
    """Comprehensive health check endpoint that executes a real database query.
    
    Verifies that the database is reachable and responsive by executing 'SELECT 1'.
    """
    engine_dialect = "unknown"
    try:
        engine = get_database_engine()
        engine_dialect = engine.dialect.name
    except Exception:
        pass

    try:
        # Execute real SELECT 1 against database
        result = await db.execute(text("SELECT 1"))
        val = result.scalar()
        if val != 1:
            raise ValueError(f"Unexpected query result: {val}")

        return {
            "status": "healthy",
            "database": "connected",
            "engine": engine_dialect,
            "version": settings.VERSION,
        }
    except Exception as exc:
        logger.error("Database health check failed: %s", exc, exc_info=True)
        response.status_code = status.HTTP_503_SERVICE_UNAVAILABLE
        return {
            "status": "unhealthy",
            "database": "disconnected",
            "engine": engine_dialect,
            "error": "Database connectivity check failed",
            "version": settings.VERSION,
        }

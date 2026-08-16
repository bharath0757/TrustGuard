"""TrustGuard Backend Main Entrypoint."""

from contextlib import asynccontextmanager
from datetime import datetime, timezone
from fastapi import Depends, FastAPI
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession
from app.api.router import api_router
from app.core.config import settings
from app.db.database import get_db, init_db
from app.db.ephemeral import get_ephemeral_store


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan context manager for setup and teardown."""
    # Initialize DB schema on startup
    await init_db()
    yield


app = FastAPI(
    title="TrustGuard API",
    description="Zero-Trust Ephemeral Question-Paper Distribution Backend API",
    version=settings.VERSION,
    lifespan=lifespan,
)

# Configure CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Register API Router
app.include_router(api_router, prefix=settings.API_V1_STR)


@app.get("/")
def read_root():
    return {"message": "Welcome to TrustGuard API", "status": "online"}


@app.get("/health")
@app.get("/api/v1/health")
async def health_check(db: AsyncSession = Depends(get_db)):
    """System health check endpoint verifying Backend, Database, and Ephemeral RAM."""
    db_status = "connected"
    try:
        await db.execute(text("SELECT 1"))
    except Exception:
        db_status = "unavailable"

    ephemeral = get_ephemeral_store()
    ephemeral_mode = "memory_fallback" if ephemeral._use_fallback else "ready"

    is_healthy = db_status == "connected"

    return {
        "status": "healthy" if is_healthy else "degraded",
        "service": "TrustGuard Backend API",
        "version": settings.VERSION,
        "database": db_status,
        "ephemeral_store": ephemeral_mode,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


if __name__ == "__main__":
    import uvicorn

    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)

"""TrustGuard Backend Main Entrypoint."""

from contextlib import asynccontextmanager
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from app.api.router import api_router
from app.core.config import settings
from app.db.database import init_db


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

# Enable CORS for frontend compatibility
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Register API Router
app.include_router(api_router, prefix="/api/v1")


@app.get("/")
@app.get("/api")
def read_root():
    return {
        "title": "TrustGuard API",
        "status": "online",
        "message": "Welcome to TrustGuard Zero-Trust Distribution API",
        "documentation": "/docs",
    }


@app.get("/health")
@app.get("/api/health")
def health_check():
    return {"status": "ok", "message": "TrustGuard API is running"}


if __name__ == "__main__":
    import uvicorn

    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)

"""TrustGuard Backend Main Entrypoint."""

from contextlib import asynccontextmanager
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.api.router import api_router
from app.db.database import init_db


@asynccontextmanager
async def lifespan(app: FastAPI):
    await init_db()
    yield


app = FastAPI(
    title="TrustGuard API",
    description="Zero-Trust Cybersecurity Question Paper Distribution API",
    version="0.1.0",
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
@app.get("/api/v1/health")
def health_check():
    return {"status": "ok", "database": "connected", "message": "TrustGuard API is running"}


if __name__ == "__main__":
    import uvicorn

    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)

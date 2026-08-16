"""TrustGuard Backend Main Entrypoint."""

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

app = FastAPI(
    title="TrustGuard API",
    description="Zero-Trust Cybersecurity Question Paper Distribution API",
    version="0.1.0",
)

# Enable CORS for frontend compatibility
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


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

from fastapi import FastAPI

app = FastAPI(title="TrustGuard API", description="Zero-Trust cybersecurity prototype API")

@app.get("/health")
def health_check():
    return {"status": "ok", "message": "TrustGuard API is running"}

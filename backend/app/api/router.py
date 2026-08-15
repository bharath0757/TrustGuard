"""V1 API Router Aggregator."""

from fastapi import APIRouter
from app.api.v1 import audit, auth, consensus, distribution, exams

api_router = APIRouter()
api_router.include_router(auth.router)
api_router.include_router(exams.router)
api_router.include_router(consensus.router)
api_router.include_router(distribution.router)
api_router.include_router(audit.router)

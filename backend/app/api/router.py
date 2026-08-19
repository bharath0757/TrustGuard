"""V1 API Router Aggregator."""

from fastapi import APIRouter
from app.api.v1 import audit, auth, blockchain, consensus, distribution, exams, simulation, papers, exam_lifecycle, users, student, ws, attack_simulator

api_router = APIRouter()
api_router.include_router(auth.router)
api_router.include_router(users.router)
api_router.include_router(exams.router)
api_router.include_router(consensus.router)
api_router.include_router(distribution.router)
api_router.include_router(blockchain.router)
api_router.include_router(audit.router)
api_router.include_router(simulation.router)
api_router.include_router(simulation.router, prefix="/attacks")  # Alias for attacks prefix
api_router.include_router(attack_simulator.router)
api_router.include_router(papers.router)
api_router.include_router(exam_lifecycle.router)
api_router.include_router(student.router)
api_router.include_router(ws.router)

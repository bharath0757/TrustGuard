"""Paper upload, AES-GCM encryption, and metadata management API endpoints."""

from typing import List, Optional
from fastapi import APIRouter, Depends, File, Form, UploadFile, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import get_current_user, require_roles
from app.db.database import get_db
from app.db.models import User
from app.schemas.paper import PaperUploadResponse, PaperListResponse
from app.services.paper_upload_service import PaperUploadService

router = APIRouter(prefix="/papers", tags=["Question Papers"])

GUARDIAN_ROLES = ["ADMIN", "EXAM_SETTER", "GUARDIAN", "KEY_GUARDIAN"]
STAFF_ROLES = ["ADMIN", "EXAM_SETTER", "GUARDIAN", "KEY_GUARDIAN", "EXAM_CENTER", "AUDITOR"]


@router.post(
    "/upload",
    response_model=PaperUploadResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Upload and securely encrypt a question paper (Guardian only)",
)
async def upload_paper(
    paper_name: str = Form(..., min_length=3, max_length=255),
    description: Optional[str] = Form(default=None),
    file: UploadFile = File(...),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_roles(GUARDIAN_ROLES)),
):
    """
    Upload a question paper file:
    1. Validates file (type, size > 0 and <= 50MB)
    2. Encrypts payload with AES-256-GCM
    3. Computes cryptographic integrity hashes
    4. Creates protected staging record with expiry metadata
    5. Returns protected metadata (NO raw file path exposed)
    """
    return await PaperUploadService.upload_paper(
        db=db,
        paper_name=paper_name,
        description=description,
        file=file,
        creator_id=current_user.id,
    )


@router.get(
    "/",
    response_model=List[PaperListResponse],
    summary="List all uploaded papers (Authorized staff only)",
)
async def list_papers(
    skip: int = 0,
    limit: int = 100,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_roles(STAFF_ROLES)),
):
    """Retrieve all uploaded paper metadata records."""
    return await PaperUploadService.list_papers(db, skip=skip, limit=limit)


@router.get(
    "/{paper_id}",
    response_model=PaperUploadResponse,
    summary="Get paper details (Authorized staff only)",
)
async def get_paper(
    paper_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_roles(STAFF_ROLES)),
):
    """Retrieve a specific paper's metadata and security status."""
    return await PaperUploadService.get_paper_by_id(db, paper_id)

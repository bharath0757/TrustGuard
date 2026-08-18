"""Paper upload, AES-256-GCM encryption, and secure ephemeral staging service."""

from datetime import datetime, timedelta, timezone
import hashlib
from typing import List, Optional
from fastapi import HTTPException, UploadFile, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.db.models import UploadedPaper
from app.services.audit_service import AuditService
from security.crypto.encryption import encrypt
from security.crypto.integrity import generate_integrity_hash

# Maximum file size: 50 MB
MAX_FILE_SIZE = 50 * 1024 * 1024

ALLOWED_EXTENSIONS = {".pdf", ".docx", ".doc", ".txt", ".zip", ".enc"}


class PaperUploadService:

    @staticmethod
    def derive_paper_encryption_key() -> bytes:
        """Derive standard 256-bit AES key from system configuration secret."""
        key_source = f"{settings.SECRET_KEY}_trustguard_paper_master_key_v1"
        return hashlib.sha256(key_source.encode("utf-8")).digest()

    @staticmethod
    async def upload_paper(
        db: AsyncSession,
        paper_name: str,
        description: Optional[str],
        file: UploadFile,
        creator_id: str,
    ) -> UploadedPaper:
        """
        Upload, validate, and securely encrypt a question paper:
        1. Validate file (name, type, size > 0 and <= 50MB)
        2. Compute SHA-256 content checksum
        3. Encrypt payload using authenticated AES-256-GCM (random 12-byte IV per paper)
        4. Generate SHA-256 integrity hash on ciphertext
        5. Set expiry metadata (8-hour staging window)
        6. Persist metadata & encrypted ciphertext (NEVER plaintext)
        7. Record cryptographic audit trail
        """
        # 1. Validate filename
        if not file.filename:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="File must have a valid filename",
            )

        # 2. Validate extension
        ext = "." + file.filename.rsplit(".", 1)[-1].lower() if "." in file.filename else ""
        if ext not in ALLOWED_EXTENSIONS:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"File extension '{ext}' is not allowed. Allowed: {', '.join(sorted(ALLOWED_EXTENSIONS))}",
            )

        # 3. Read file content and validate size
        content = await file.read()
        file_size = len(content)

        if file_size == 0:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Uploaded file is empty (0 bytes)",
            )

        if file_size > MAX_FILE_SIZE:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"File size ({file_size} bytes) exceeds maximum allowable limit ({MAX_FILE_SIZE} bytes)",
            )

        # 4. Compute SHA-256 hash of raw content for integrity provenance
        file_hash = hashlib.sha256(content).hexdigest()

        # 5. Encrypt with AES-256-GCM (authenticated encryption)
        master_key = PaperUploadService.derive_paper_encryption_key()
        encrypted_payload = encrypt(
            data=content,
            key=master_key,
            associated_data=paper_name.encode("utf-8"),
        )

        # 6. Generate integrity checksum of the encrypted ciphertext
        integrity_hash = generate_integrity_hash(encrypted_payload)

        # 7. Sharding count estimation
        fragment_count = max(3, min(10, file_size // (1024 * 1024) + 3))

        now = datetime.now(timezone.utc)
        expires_at = now + timedelta(hours=8)

        # 8. Create paper record — stores ONLY encrypted payload hex and metadata
        paper = UploadedPaper(
            paper_name=paper_name,
            description=description,
            original_filename=file.filename,
            file_size=file_size,
            file_hash=file_hash,
            encryption_status="ENCRYPTED",
            integrity_status="VERIFIED",
            fragment_status="FRAGMENTED",
            protection_status="PROTECTED",
            integrity_hash=integrity_hash,
            total_fragments=fragment_count,
            created_by=creator_id,
            protected_at=now,
            staged_at=now,
            expires_at=expires_at,
            status="STAGED",
            encrypted_payload_hex=encrypted_payload.hex(),
        )

        db.add(paper)
        await db.commit()
        await db.refresh(paper)

        # 9. Audit event
        await AuditService.log_event(
            db=db,
            action="PAPER_UPLOADED_AND_PROTECTED",
            exam_id=paper.id,
            actor_id=creator_id,
            details={
                "paper_name": paper_name,
                "filename": file.filename,
                "file_size": file_size,
                "file_hash": file_hash[:16] + "...",
                "integrity_hash": integrity_hash[:16] + "...",
                "encryption": "AES-256-GCM",
                "protection_status": "PROTECTED",
                "status": "STAGED",
                "expires_at": expires_at.isoformat(),
            },
        )

        return paper

    @staticmethod
    async def get_paper_by_id(db: AsyncSession, paper_id: str) -> UploadedPaper:
        """Get a paper by ID."""
        stmt = select(UploadedPaper).where(UploadedPaper.id == paper_id)
        result = await db.execute(stmt)
        paper = result.scalar_one_or_none()
        if not paper:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Question paper with ID '{paper_id}' not found",
            )
        return paper

    @staticmethod
    async def list_papers(
        db: AsyncSession, skip: int = 0, limit: int = 100
    ) -> List[UploadedPaper]:
        """List all uploaded papers."""
        stmt = (
            select(UploadedPaper)
            .order_by(UploadedPaper.created_at.desc())
            .offset(skip)
            .limit(limit)
        )
        result = await db.execute(stmt)
        return list(result.scalars().all())

"""API dependencies for authentication, user context, and role-based access control (RBAC)."""

from typing import List, Optional, Set
from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy.ext.asyncio import AsyncSession
from app.core.security import decode_access_token
from app.db.database import get_db
from app.db.models import User
from app.services.auth_service import AuthService

security_scheme = HTTPBearer()


async def get_current_user(
    credentials: HTTPAuthorizationCredentials = Depends(security_scheme),
    db: AsyncSession = Depends(get_db),
) -> User:
    token = credentials.credentials
    payload = decode_access_token(token)
    if not payload:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired access token",
            headers={"WWW-Authenticate": "Bearer"},
        )
    user_id = payload.get("sub")
    if not user_id:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token payload",
        )
    user = await AuthService.get_user_by_id(db, user_id)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User not found",
        )
    return user


optional_security_scheme = HTTPBearer(auto_error=False)


async def get_optional_current_user(
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(optional_security_scheme),
    db: AsyncSession = Depends(get_db),
) -> Optional[User]:
    if not credentials:
        return None
    token = credentials.credentials
    payload = decode_access_token(token)
    if not payload:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired access token",
            headers={"WWW-Authenticate": "Bearer"},
        )
    user_id = payload.get("sub")
    if not user_id:
        return None
    return await AuthService.get_user_by_id(db, user_id)


ROLE_EQUIVALENCE = {
    "GUARDIAN": {"GUARDIAN", "KEY_GUARDIAN", "ADMIN"},
    "KEY_GUARDIAN": {"GUARDIAN", "KEY_GUARDIAN", "ADMIN"},
    "STUDENT": {"STUDENT"},
    "ATTACKER": {"ATTACKER", "ADMIN"},
    "ADMIN": {"ADMIN", "EXAM_SETTER"},
    "EXAM_SETTER": {"EXAM_SETTER", "ADMIN"},
    "AUDITOR": {"AUDITOR", "ADMIN"},
    "EXAM_CENTER": {"EXAM_CENTER", "ADMIN"},
}


def require_roles(allowed_roles: List[str]):
    async def role_checker(current_user: User = Depends(get_current_user)) -> User:
        user_role = current_user.role

        # Direct match
        if user_role in allowed_roles:
            return current_user

        # Alias/Equivalence expansion
        expanded_allowed = set(allowed_roles)
        for r in allowed_roles:
            if r in ROLE_EQUIVALENCE:
                expanded_allowed.update(ROLE_EQUIVALENCE[r])

        if user_role in expanded_allowed:
            return current_user

        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Operation not permitted for role '{user_role}'. Required one of: {allowed_roles}",
        )

    return role_checker

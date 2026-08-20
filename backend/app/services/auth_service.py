"""Authentication service for user management and JWT access control."""

import logging
from typing import Optional
from fastapi import HTTPException, status
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError, SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import create_access_token, hash_password, verify_password
from app.db.models import User
from app.schemas.auth import UserRegister

logger = logging.getLogger("trustguard.auth_service")


class AuthService:

    @staticmethod
    async def register_user(db: AsyncSession, user_in: UserRegister) -> User:
        """Register a new user account with duplicate prevention and safe error handling."""
        logger.info("Registering user: %s (role: %s)", user_in.username, user_in.role)
        try:
            # Check if username or email already exists
            stmt = select(User).where((User.username == user_in.username) | (User.email == user_in.email))
            result = await db.execute(stmt)
            existing = result.scalar_one_or_none()
            if existing:
                logger.warning("Registration failed: user with username '%s' or email '%s' already exists", user_in.username, user_in.email)
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="User with this username or email already exists",
                )

            db_user = User(
                username=user_in.username,
                email=user_in.email,
                hashed_password=hash_password(user_in.password),
                role=user_in.role,
            )
            db.add(db_user)
            await db.commit()
            await db.refresh(db_user)
            logger.info("User registered successfully: %s (id: %s)", db_user.username, db_user.id)
            return db_user
        except HTTPException:
            raise
        except IntegrityError as e:
            await db.rollback()
            logger.warning("Database IntegrityError during user registration: %s", e)
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="User with this username or email already exists",
            )
        except SQLAlchemyError as e:
            await db.rollback()
            logger.error("Database error during user registration for '%s': %s", user_in.username, e, exc_info=True)
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Internal database error during user registration",
            )
        except Exception as e:
            await db.rollback()
            logger.error("Unexpected error during user registration: %s", e, exc_info=True)
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Unexpected error occurred during registration",
            )

    @staticmethod
    async def authenticate_user(db: AsyncSession, username: str, password: str) -> User:
        """Authenticate user by username and password with constant-time verification."""
        try:
            stmt = select(User).where(User.username == username)
            result = await db.execute(stmt)
            user = result.scalar_one_or_none()
            if not user or not verify_password(password, user.hashed_password):
                logger.warning("Authentication failed for username: %s", username)
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Invalid username or password",
                    headers={"WWW-Authenticate": "Bearer"},
                )
            logger.info("User authenticated successfully: %s (role: %s)", user.username, user.role)
            return user
        except HTTPException:
            raise
        except SQLAlchemyError as e:
            logger.error("Database error during authentication for '%s': %s", username, e, exc_info=True)
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Internal database error during authentication",
            )
        except Exception as e:
            logger.error("Unexpected error during authentication: %s", e, exc_info=True)
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Unexpected error occurred during authentication",
            )

    @staticmethod
    async def create_user_token(user: User) -> dict:
        access_token = create_access_token(
            data={"sub": user.id, "username": user.username, "role": user.role}
        )
        return {
            "access_token": access_token,
            "token_type": "bearer",
            "role": user.role,
            "user_id": user.id,
        }

    @staticmethod
    async def get_user_by_id(db: AsyncSession, user_id: str) -> Optional[User]:
        try:
            stmt = select(User).where(User.id == user_id)
            result = await db.execute(stmt)
            return result.scalar_one_or_none()
        except SQLAlchemyError as e:
            logger.error("Database error looking up user ID '%s': %s", user_id, e, exc_info=True)
            return None

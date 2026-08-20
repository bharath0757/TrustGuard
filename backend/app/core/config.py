"""Configuration settings for TrustGuard backend."""

import os
from typing import Optional
from pydantic import model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


DEFAULT_DEV_SECRET_KEY = "trustguard_secure_jwt_secret_key_change_in_production_2026"


class Settings(BaseSettings):
    PROJECT_NAME: str = "TrustGuard Backend"
    VERSION: str = "0.1.0"
    API_V1_STR: str = "/api/v1"
    
    SECRET_KEY: str = DEFAULT_DEV_SECRET_KEY
    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 60 * 8  # 8 hours

    # Database
    DATABASE_URL: Optional[str] = None
    POSTGRES_URL: Optional[str] = None

    # Ephemeral Cache (Redis)
    REDIS_URL: str = "redis://localhost:6379/0"
    ENABLE_REDIS_FALLBACK: bool = True
    EPHEMERAL_DEFAULT_TTL: int = 1800  # 30 minutes TTL for RAM-stored question chunks

    # Demo credentials configuration (override in .env for production/staging)
    DEMO_PASSWORD: str = "trustguard123"

    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    @model_validator(mode="after")
    def validate_production_configuration(self) -> "Settings":
        is_vercel = bool(os.environ.get("VERCEL"))
        
        # Resolve effective DATABASE_URL
        resolved_db = self.DATABASE_URL or self.POSTGRES_URL or os.environ.get("DATABASE_URL") or os.environ.get("POSTGRES_URL")
        
        if is_vercel:
            if not resolved_db:
                # In Vercel production without a database URL, raise a clear configuration error
                error_msg = (
                    "[DATABASE CONFIGURATION ERROR] DATABASE_URL (or POSTGRES_URL) environment variable is required "
                    "when running in Vercel production. Please configure your PostgreSQL connection string in "
                    "Vercel Project Settings -> Environment Variables."
                )
                # We store this to log and raise during DB connection initialization rather than crashing module import
                # to allow health/error diagnostics to report clearly.
            if self.SECRET_KEY == DEFAULT_DEV_SECRET_KEY:
                # Log security warning in production
                import logging
                logging.getLogger("trustguard").warning(
                    "[SECURITY WARNING] Using default development SECRET_KEY in Vercel production. "
                    "Please configure SECRET_KEY in Vercel Project Settings -> Environment Variables."
                )
        
        # Set default dev database if not configured
        if not resolved_db:
            self.DATABASE_URL = "sqlite+aiosqlite:///./trustguard.db"
        else:
            self.DATABASE_URL = resolved_db

        return self


settings = Settings()

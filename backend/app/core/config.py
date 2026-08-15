"""Configuration settings for TrustGuard backend."""

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    PROJECT_NAME: str = "TrustGuard Backend"
    VERSION: str = "0.1.0"
    API_V1_STR: str = "/api/v1"
    
    SECRET_KEY: str = "trustguard_secure_jwt_secret_key_change_in_production_2026"
    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 60 * 8  # 8 hours

    # Database
    DATABASE_URL: str = "sqlite+aiosqlite:///./trustguard.db"

    # Ephemeral Cache (Redis)
    REDIS_URL: str = "redis://localhost:6379/0"
    ENABLE_REDIS_FALLBACK: bool = True
    EPHEMERAL_DEFAULT_TTL: int = 1800  # 30 minutes TTL for RAM-stored question chunks

    model_config = SettingsConfigDict(env_file=".env", extra="ignore")


settings = Settings()

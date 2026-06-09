from pydantic_settings import BaseSettings
from typing import Optional
from functools import lru_cache


class Settings(BaseSettings):
    APP_NAME: str = "Audit Trail Service"
    APP_VERSION: str = "1.0.0"
    DEBUG: bool = True

    DATABASE_URL: str = "sqlite:///./audit_trail.db"
    DATABASE_ECHO: bool = False

    SECRET_KEY: str = "your-secret-key-change-in-production"
    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 1440

    API_V1_PREFIX: str = "/api/v1"

    ADMIN_USERNAME: str = "admin"
    ADMIN_PASSWORD: str = "admin123"

    CORS_ORIGINS: list = ["*"]

    PAGE_SIZE_DEFAULT: int = 20
    PAGE_SIZE_MAX: int = 100

    RATE_LIMIT_ENABLED: bool = True
    RATE_LIMIT_EVENTS_PER_MINUTE_IP: int = 60
    RATE_LIMIT_EVENTS_PER_MINUTE_ACTOR: int = 60
    RATE_LIMIT_BULK_FACTOR: int = 10

    AUDIT_IMMUTABLE: bool = True

    class Config:
        env_file = ".env"
        case_sensitive = True


@lru_cache()
def get_settings() -> Settings:
    return Settings()


settings = get_settings()

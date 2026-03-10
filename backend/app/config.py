from pydantic_settings import BaseSettings
from typing import List


class Settings(BaseSettings):
    DATABASE_URL: str = "sqlite:///./guardian_shield.db"
    JWT_SECRET: str = "your-secret-key-change-in-production"
    JWT_ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 15
    REFRESH_TOKEN_EXPIRE_DAYS: int = 7
    CORS_ORIGINS: str = "http://localhost:3000"

    # Shared secret for ML engine → backend service-to-service calls.
    # Must match the ML_API_KEY env-var on the ML engine side.
    ML_API_KEY: str = "change-me-in-production"

    # ── Feature flags for new security modules ──────────────────────
    # Rate limiter
    RATE_LIMITER_ENABLED: bool = True
    RATE_LIMITER_MAX_PACKETS_PER_MINUTE: int = 100
    RATE_LIMITER_MAX_SYN_PER_SECOND: int = 20

    # Threat intelligence
    THREAT_INTEL_ENABLED: bool = False
    ABUSEIPDB_API_KEY: str = ""

    # Model drift monitoring
    DRIFT_MONITORING_ENABLED: bool = True

    # Explainable AI
    EXPLAINABILITY_ENABLED: bool = True

    @property
    def cors_origins_list(self) -> List[str]:
        return [origin.strip() for origin in self.CORS_ORIGINS.split(",")]

    class Config:
        env_file = ".env"
        env_file_encoding = "utf-8"


settings = Settings()

"""
OpsTrace Application and Database Configuration
Phase 2: PostgreSQL Database Design and Implementation
"""

from functools import lru_cache
from typing import Optional
from pydantic import Field, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict
from sqlalchemy.engine import URL


class Settings(BaseSettings):
    """
    Application runtime configuration loaded dynamically from environment variables.
    Zero hardcoded credentials.
    """
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
        case_sensitive=True,
    )

    # Application Environment
    ENVIRONMENT: str = Field(default="development", description="Runtime environment (development, production, testing)")
    LOG_LEVEL: str = Field(default="INFO", description="Global logging verbosity")

    # API Server Configuration
    BACKEND_HOST: str = Field(default="0.0.0.0", description="FastAPI bind address")
    BACKEND_PORT: int = Field(default=8000, description="FastAPI port")

    # PostgreSQL Database Credentials & Networking
    POSTGRES_USER: str = Field(default="opstrace_user", description="PostgreSQL database user")
    POSTGRES_PASSWORD: str = Field(default="", repr=False, exclude=True, description="PostgreSQL database password")
    POSTGRES_DB: str = Field(default="opstrace_db", description="PostgreSQL database name")
    POSTGRES_HOST: str = Field(default="localhost", description="PostgreSQL server hostname or IP")
    POSTGRES_PORT: int = Field(default=5432, description="PostgreSQL server port")

    # Connection Pool Settings
    POSTGRES_POOL_SIZE: int = Field(default=10, description="SQLAlchemy connection pool base size")
    POSTGRES_MAX_OVERFLOW: int = Field(default=20, description="SQLAlchemy connection pool max overflow")
    POSTGRES_POOL_TIMEOUT: int = Field(default=30, description="Connection pool checkout timeout in seconds")
    POSTGRES_POOL_RECYCLE: int = Field(default=1800, description="Connection recycle interval in seconds")

    # Explicit Database URL override (e.g. for testing with SQLite or cloud connection strings)
    DATABASE_URL: Optional[str] = Field(default=None, repr=False, exclude=True, description="Optional full database connection URL override")

    # Security Keys
    COLLECTOR_API_KEY: Optional[str] = Field(default=None, repr=False, exclude=True, description="Collector daemon bearer token")
    ADMIN_API_KEY: Optional[str] = Field(default=None, repr=False, exclude=True, description="Human operator admin token")

    # Comma-separated browser origins. The default supports local development
    # and the same-origin Nginx deployment without allowing arbitrary origins.
    CORS_ALLOWED_ORIGINS: str = Field(
        default="http://localhost:3000,http://localhost:8000",
        description="Comma-separated browser origins allowed by CORS.",
    )

    # Observability
    PROMETHEUS_METRICS_ENABLED: bool = Field(default=True, description="Enable Prometheus metrics endpoint")

    @model_validator(mode="after")
    def require_production_credentials(self) -> "Settings":
        """Prevent production startup with absent or template credentials."""
        if self.ENVIRONMENT.strip().lower() != "production":
            return self
        placeholders = {
            "change_this_in_production",
            "change_collector_token_secret",
            "change_admin_token_secret",
            "change_grafana_password",
        }
        required = {
            "COLLECTOR_API_KEY": self.COLLECTOR_API_KEY,
            "ADMIN_API_KEY": self.ADMIN_API_KEY,
        }
        if not self.DATABASE_URL:
            required["POSTGRES_PASSWORD"] = self.POSTGRES_PASSWORD
        invalid = [
            name for name, value in required.items()
            if not value or value.strip().lower() in placeholders or len(value) < 32
        ]
        if invalid:
            raise ValueError(
                "Production requires unique credentials of at least 32 characters for: "
                + ", ".join(invalid)
            )
        if "*" in {origin.strip() for origin in self.CORS_ALLOWED_ORIGINS.split(",")}:
            raise ValueError("Production CORS origins must be explicit; wildcard origins are not allowed.")
        return self

    @property
    def sqlalchemy_database_uri(self) -> str:
        """
        Dynamically constructs the SQLAlchemy database connection URL.
        Uses DATABASE_URL if explicitly specified; otherwise constructs standard PostgreSQL connection string.
        """
        if self.DATABASE_URL:
            if self.DATABASE_URL.startswith("postgres://"):
                return self.DATABASE_URL.replace("postgres://", "postgresql+psycopg2://", 1)
            if self.DATABASE_URL.startswith("postgresql://") and not self.DATABASE_URL.startswith("postgresql+"):
                return self.DATABASE_URL.replace("postgresql://", "postgresql+psycopg2://", 1)
            return self.DATABASE_URL

        return URL.create(
            "postgresql+psycopg2",
            username=self.POSTGRES_USER,
            password=self.POSTGRES_PASSWORD,
            host=self.POSTGRES_HOST,
            port=self.POSTGRES_PORT,
            database=self.POSTGRES_DB,
        ).render_as_string(hide_password=False)


@lru_cache()
def get_settings() -> Settings:
    """
    Returns a cached singleton of application settings.
    """
    return Settings()

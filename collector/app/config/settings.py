"""
OpsTrace Collector Configuration
Phase 5: Log Collection and Ingestion
(extends Phase 4: Linux Monitoring Collector)

Loads all configuration from environment variables.
Zero hard-coded credentials.
"""

from functools import lru_cache
from typing import List

from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class CollectorSettings(BaseSettings):
    """
    Runtime configuration for the OpsTrace Linux telemetry collector.

    All sensitive values (API keys, URLs) are sourced from the environment.
    Safe defaults are provided for local development only.
    """

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
        case_sensitive=True,
    )

    # ---------------------------------------------------------------------------
    # Backend connectivity
    # ---------------------------------------------------------------------------
    BACKEND_URL: str = Field(
        default="http://localhost:8000",
        description=(
            "Base URL of the OpsTrace FastAPI backend. "
            "Example: http://192.168.1.10:8000"
        ),
    )

    # API key sent in the Authorization: Bearer <token> header.
    # NEVER log or print this value.
    COLLECTOR_API_KEY: str = Field(
        default="",
        description="Bearer token used to authenticate with the OpsTrace backend.",
    )

    # ---------------------------------------------------------------------------
    # Collection behaviour
    # ---------------------------------------------------------------------------
    COLLECTION_INTERVAL: int = Field(
        default=30,
        ge=5,
        description=(
            "Interval in seconds between telemetry collection cycles. "
            "Minimum 5 seconds to avoid excessive system load."
        ),
    )

    # ---------------------------------------------------------------------------
    # Logging (collector daemon verbosity)
    # ---------------------------------------------------------------------------
    LOG_LEVEL: str = Field(
        default="INFO",
        description="Logging verbosity (DEBUG, INFO, WARNING, ERROR, CRITICAL).",
    )

    # ---------------------------------------------------------------------------
    # Collector identity
    # ---------------------------------------------------------------------------
    COLLECTOR_VERSION: str = Field(
        default="0.5.0",
        description="Collector daemon version string.",
    )

    # ---------------------------------------------------------------------------
    # Feature flags — Phase 4
    # ---------------------------------------------------------------------------
    COLLECT_SERVICES: bool = Field(
        default=True,
        description=(
            "Enable systemd service status collection. "
            "Automatically disabled if systemd/dbus is unavailable."
        ),
    )
    ENVIRONMENT: str = Field(
        default="development",
        description="Runtime environment (development, production, testing).",
    )

    # ---------------------------------------------------------------------------
    # Phase 5: Log collection settings
    # ---------------------------------------------------------------------------
    COLLECT_LOGS: bool = Field(
        default=True,
        description=(
            "Master switch for Phase 5 log collection. "
            "Set to false to disable all log collection without removing config."
        ),
    )

    LOG_FILE_PATHS: str = Field(
        default="",
        description=(
            "Comma-separated list of absolute log file paths to monitor. "
            "Example: /var/log/syslog,/var/log/myapp/app.log. "
            "Empty string disables file log collection."
        ),
    )

    LOG_BATCH_SIZE: int = Field(
        default=100,
        ge=1,
        description=(
            "Number of log events to accumulate before sending a batch "
            "to the backend.  Remaining events are flushed at cycle end."
        ),
    )

    COLLECT_JOURNAL: bool = Field(
        default=True,
        description=(
            "Enable systemd journal collection via journalctl. "
            "Automatically disabled if journalctl is unavailable (e.g. Windows)."
        ),
    )

    JOURNAL_LINES: int = Field(
        default=200,
        ge=1,
        description=(
            "Number of recent journal entries to fetch per cycle when "
            "no cursor is stored.  Only applies to the first collection cycle."
        ),
    )

    def get_log_file_paths(self) -> List[str]:
        """
        Parse the ``LOG_FILE_PATHS`` comma-separated string into a clean list.

        Empty strings and whitespace-only entries are filtered out.
        """
        if not self.LOG_FILE_PATHS:
            return []
        return [p.strip() for p in self.LOG_FILE_PATHS.split(",") if p.strip()]


@lru_cache()
def get_collector_settings() -> CollectorSettings:
    """
    Returns a cached singleton of collector settings.

    Using lru_cache ensures the environment is read once per process lifetime,
    not on every access.
    """
    return CollectorSettings()

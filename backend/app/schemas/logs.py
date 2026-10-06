"""
OpsTrace Log Ingestion Schemas
Phase 5: Log Collection and Ingestion

Pydantic request/response models for the log ingestion API endpoint.

These schemas define the wire format for log batches sent by the
Phase 5 collector.  They are distinct from the SQLAlchemy Log model
but map directly onto it.
"""

from __future__ import annotations

import hashlib
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, ConfigDict, Field, field_validator


class IngestLogLevel(str, Enum):
    """
    Accepted log level values in ingest requests.

    The Phase 2 ``logs`` table CHECK constraint allows:
      'DEBUG', 'INFO', 'WARN', 'WARNING', 'ERROR', 'CRITICAL', 'FATAL'

    The API accepts 'WARN' as an alias for 'WARNING' and normalises it.
    """

    DEBUG = "DEBUG"
    INFO = "INFO"
    WARNING = "WARNING"
    ERROR = "ERROR"
    CRITICAL = "CRITICAL"


# Level aliases that arrive from the collector but need normalisation.
_LEVEL_NORM: Dict[str, str] = {
    "WARN": "WARNING",
    "FATAL": "CRITICAL",
}


class LogEventPayload(BaseModel):
    """
    A single log event within an ingest batch.

    Maps to the Phase 2 ``Log`` SQLAlchemy model fields:
      timestamp   → timestamp
      level       → level
      message     → message
      source      → source      (max 100 chars, enforced here)
      hostname    → used to resolve host_id in the service layer
      service_name → used to resolve service_id in the service layer
      metadata    → attributes (JSONB column)
      fingerprint → fingerprint
    """

    model_config = ConfigDict(extra="forbid")

    timestamp: datetime = Field(
        default_factory=lambda: datetime.now(tz=timezone.utc),
        description="UTC timestamp of the log event.",
    )
    hostname: Optional[str] = Field(
        default=None,
        description=(
            "Hostname of the originating machine.  "
            "Used to look up or create the Host record."
        ),
    )
    service_name: Optional[str] = Field(
        default=None,
        description="Originating service name (resolved to service_id).",
    )
    level: str = Field(
        default="INFO",
        description="Log severity level.",
    )
    message: str = Field(
        description="Log message body.",
        max_length=16_384,
    )
    source: str = Field(
        default="unknown",
        description="Log source identifier (file path, journal unit, etc.).",
    )
    source_type: Optional[str] = Field(
        default=None,
        description="Type of log source: 'file' or 'journal'.",
    )
    metadata: Optional[Dict[str, Any]] = Field(
        default=None,
        description="Arbitrary key-value bag stored in the attributes column.",
    )
    fingerprint: Optional[str] = Field(
        default=None,
        description="Optional 64-char hex fingerprint for error clustering.",
    )

    @field_validator("level", mode="before")
    @classmethod
    def normalise_level(cls, v: str) -> str:
        """Normalise level aliases (WARN→WARNING, FATAL→CRITICAL)."""
        upper = str(v).upper().strip()
        return _LEVEL_NORM.get(upper, upper)

    @field_validator("source")
    @classmethod
    def truncate_source(cls, v: str) -> str:
        """Enforce the 100-char database column limit on source."""
        return (v or "unknown")[:100]

    def compute_fingerprint(self) -> str:
        """
        Compute a SHA-256 fingerprint (first 64 hex chars) based on
        level + source + the first 200 characters of the message.

        Used for error clustering in the backend.
        """
        key = f"{self.level}:{self.source}:{self.message[:200]}"
        return hashlib.sha256(key.encode("utf-8", errors="replace")).hexdigest()[:64]


class LogIngestRequest(BaseModel):
    """
    Batch ingest request body sent by the Phase 5 collector.

    One HTTP request carries N log events assembled by the LogBatcher.
    """

    model_config = ConfigDict(extra="forbid")

    collected_at: datetime = Field(
        default_factory=lambda: datetime.now(tz=timezone.utc),
        description="UTC timestamp when this batch was assembled by the collector.",
    )
    hostname: Optional[str] = Field(
        default=None,
        description="Primary hostname for all events in this batch.",
    )
    events: List[LogEventPayload] = Field(
        default_factory=list,
        description="List of log events in this batch.",
        max_length=1000,
    )
    collection_errors: List[str] = Field(
        default_factory=list,
        description="Non-fatal errors encountered during collection of this batch.",
        max_length=100,
    )

    @field_validator("events")
    @classmethod
    def events_must_not_be_empty(cls, v: List[LogEventPayload]) -> List[LogEventPayload]:
        """Allow empty batches through without error; they are simply ignored."""
        return v


class LogIngestResponse(BaseModel):
    """
    Response body returned by POST /api/v1/logs/ingest.
    """

    accepted: int = Field(
        description="Number of log events successfully persisted.",
    )
    rejected: int = Field(
        default=0,
        description="Number of events that could not be persisted (DB error, etc.).",
    )
    batch_id: Optional[str] = Field(
        default=None,
        description="Opaque identifier for this batch (for tracing).",
    )
    message: str = Field(
        default="ok",
        description="Human-readable status message.",
    )

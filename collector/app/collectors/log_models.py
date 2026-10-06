"""
OpsTrace Collector — Log Data Models
Phase 5: Log Collection and Ingestion

Typed Pydantic models representing a structured log event collected
from a Linux log source (file or systemd journal).

These models serve as the canonical internal contract between the
log collectors and the backend client.  They are designed to be
compatible with the Phase 2 ``Log`` database model.

Field mapping from Phase 2 Log:
  - timestamp  → timestamp
  - level      → level   (DEBUG/INFO/WARNING/ERROR/CRITICAL)
  - message    → message
  - source     → source  (up to 100 chars)
  - host       → hostname (resolved to host_id by the backend)
  - service    → service_name (resolved to service_id by the backend)
  - attributes → metadata  (arbitrary key-value bag)
  - fingerprint → fingerprint (optional; left to backend or caller)

Security:
  - Log contents are treated as untrusted input throughout.
  - No shell commands are ever derived from log message text.
"""

from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field, field_validator


# ---------------------------------------------------------------------------
# Log severity
# ---------------------------------------------------------------------------


class LogLevel(str, Enum):
    """
    Normalised log severity levels supported by OpsTrace.

    Maps to the CHECK constraint on ``logs.level`` in Phase 2:
      'DEBUG', 'INFO', 'WARN', 'WARNING', 'ERROR', 'CRITICAL', 'FATAL'

    The collector normalises to the subset used in Phase 5.
    """

    DEBUG = "DEBUG"
    INFO = "INFO"
    WARNING = "WARNING"
    ERROR = "ERROR"
    CRITICAL = "CRITICAL"


# Alias table for normalising raw level strings to LogLevel values.
# Matches are case-insensitive and cover common variants.
_LEVEL_ALIASES: Dict[str, LogLevel] = {
    "debug": LogLevel.DEBUG,
    "dbg": LogLevel.DEBUG,
    "info": LogLevel.INFO,
    "information": LogLevel.INFO,
    "notice": LogLevel.INFO,
    "warn": LogLevel.WARNING,
    "warning": LogLevel.WARNING,
    "err": LogLevel.ERROR,
    "error": LogLevel.ERROR,
    "crit": LogLevel.CRITICAL,
    "critical": LogLevel.CRITICAL,
    "fatal": LogLevel.CRITICAL,
    "emerg": LogLevel.CRITICAL,
    "alert": LogLevel.CRITICAL,
}


def normalise_level(raw: Optional[str]) -> LogLevel:
    """
    Convert a raw log-level string to a canonical ``LogLevel``.

    Returns ``LogLevel.INFO`` when the string is absent, empty, or
    unrecognised.  This function never raises.

    Args:
        raw: Raw level string from a log line, e.g. "WARN", "err", "FATAL".

    Returns:
        The matching ``LogLevel`` enum value, or ``LogLevel.INFO`` as the
        safe default.
    """
    if not raw:
        return LogLevel.INFO
    return _LEVEL_ALIASES.get(raw.strip().lower(), LogLevel.INFO)


# ---------------------------------------------------------------------------
# Log source types
# ---------------------------------------------------------------------------


class LogSourceType(str, Enum):
    """Enumeration of supported log source types."""

    FILE = "file"
    JOURNAL = "journal"


# ---------------------------------------------------------------------------
# Collected log event model (collector-side)
# ---------------------------------------------------------------------------


class CollectedLogEvent(BaseModel):
    """
    A single structured log event collected from a Linux log source.

    This is the canonical internal representation used by all Phase 5
    collectors before batching and transmission to the backend.

    Compatible with the Phase 2 ``Log`` database model fields.
    """

    # When the log entry was emitted (parsed from the log, or collection time).
    timestamp: datetime = Field(
        default_factory=lambda: datetime.now(tz=timezone.utc),
        description="UTC timestamp of the log event (parsed from source or collection time).",
    )

    # Hostname of the originating machine.
    hostname: Optional[str] = Field(
        default=None,
        description=(
            "Hostname where the log originated.  "
            "Used by the backend to look up or create the Host record."
        ),
    )

    # Service/unit name where available.
    service_name: Optional[str] = Field(
        default=None,
        description=(
            "Originating service or application name, e.g. 'nginx', 'myapp'. "
            "Used by the backend to look up the Service record."
        ),
    )

    # Normalised severity level.
    level: LogLevel = Field(
        default=LogLevel.INFO,
        description="Normalised log severity.",
    )

    # The log message text; always present.
    message: str = Field(
        description="The log message body.",
    )

    # Source identifier: file path, journal unit, etc.
    source: str = Field(
        default="unknown",
        max_length=100,
        description=(
            "Source identifier for this log event. "
            "For file collectors: the file path (truncated to 100 chars). "
            "For journal collectors: the systemd unit name."
        ),
    )

    # Which collector produced this event.
    source_type: LogSourceType = Field(
        default=LogSourceType.FILE,
        description="Type of log source (file or journal).",
    )

    # Arbitrary extra fields preserved from the raw log line.
    metadata: Optional[Dict[str, Any]] = Field(
        default=None,
        description=(
            "Arbitrary key-value metadata from the raw log entry. "
            "Stored in the ``attributes`` JSON column in the backend."
        ),
    )

    # Optional pre-computed fingerprint for deduplication.
    fingerprint: Optional[str] = Field(
        default=None,
        description="Optional 64-char hex fingerprint for error clustering.",
    )

    @field_validator("source", mode="before")
    @classmethod
    def truncate_source(cls, v: str) -> str:
        """Ensure source never exceeds the 100-char database column limit."""
        return v[:100] if v else "unknown"

    @field_validator("message")
    @classmethod
    def message_must_not_be_empty(cls, v: str) -> str:
        """Preserve the original message; strip only leading/trailing whitespace."""
        stripped = v.strip()
        return stripped if stripped else "(empty)"


# ---------------------------------------------------------------------------
# Log batch payload (sent to the backend in one HTTP request)
# ---------------------------------------------------------------------------


class LogBatch(BaseModel):
    """
    A batch of ``CollectedLogEvent`` objects sent to the backend in a
    single HTTP POST request.

    The backend ingestion endpoint expects this exact JSON shape.
    """

    collected_at: datetime = Field(
        default_factory=lambda: datetime.now(tz=timezone.utc),
        description="UTC timestamp when this batch was assembled.",
    )

    hostname: Optional[str] = Field(
        default=None,
        description=(
            "Primary hostname for all events in this batch.  "
            "Individual events may override this."
        ),
    )

    events: List[CollectedLogEvent] = Field(
        default_factory=list,
        description="List of collected log events.",
    )

    collection_errors: List[str] = Field(
        default_factory=list,
        description=(
            "Non-fatal errors encountered during log collection in this cycle. "
            "Allows the backend to know that some sources may be missing."
        ),
    )

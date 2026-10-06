"""
OpsTrace Collector — Phase 6 Analysis Result Models
Phase 6: Log Analysis & Intelligence

Strongly typed Pydantic models representing the structured output of the
Phase 6 log analysis engine.

Design:
  - Models are Pydantic v2 BaseModels compatible with the project's existing
    Pydantic usage in collector/app/collectors/log_models.py and
    backend/app/schemas/.
  - These models are *output* representations, not stored in the database.
    The existing Phase 2 ``logs`` table (with its ``fingerprint`` column) is
    sufficient for Phase 6 without any schema changes.
  - All fields have explicit types and descriptions for clarity and
    extensibility in future phases.

Relationship to Phase 5 models:
  - ``CollectedLogEvent`` (Phase 5) is the *input* to Phase 6.
  - ``AnalysisResult`` and ``ErrorGroupSummary`` are the *output* from Phase 6.
  - There is no circular dependency.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field


# ---------------------------------------------------------------------------
# Error group summary (one per fingerprint cluster)
# ---------------------------------------------------------------------------


class ErrorGroupSummary(BaseModel):
    """
    Summary of a group of log events sharing the same fingerprint.

    Produced by the grouping component and embedded in ``AnalysisResult``.
    """

    fingerprint: str = Field(
        description="64-char SHA-256 fingerprint identifying this error group.",
    )
    count: int = Field(
        default=0,
        description="Total number of events in this group.",
    )
    first_seen: Optional[datetime] = Field(
        default=None,
        description="UTC timestamp of the earliest event in this group.",
    )
    last_seen: Optional[datetime] = Field(
        default=None,
        description="UTC timestamp of the most recent event in this group.",
    )
    sample_message: str = Field(
        default="",
        description="Representative log message (from the first event seen).",
    )
    level: str = Field(
        default="UNKNOWN",
        description="Log severity level of events in this group.",
    )
    source: str = Field(
        default="unknown",
        description="Log source identifier of events in this group.",
    )

    model_config = {"frozen": False}


# ---------------------------------------------------------------------------
# Top-level analysis result
# ---------------------------------------------------------------------------


class AnalysisResult(BaseModel):
    """
    Structured result of one run of the Phase 6 ``LogAnalyzer``.

    Contains:
      - Counts by severity.
      - Grouped error information (one entry per unique fingerprint).
      - Error-rate statistics.
      - Any analysis-level warnings or errors encountered.
      - The timestamp when the analysis was performed.
    """

    # --- Timing ---
    analyzed_at: datetime = Field(
        default_factory=lambda: datetime.now(tz=timezone.utc),
        description="UTC timestamp when this analysis was performed.",
    )

    # --- Input summary ---
    total_logs_analyzed: int = Field(
        default=0,
        description="Total number of log events submitted for analysis.",
    )

    # --- Severity counts ---
    total_info: int = Field(
        default=0,
        description="Number of INFO-classified log events.",
    )
    total_warnings: int = Field(
        default=0,
        description="Number of WARNING-classified log events.",
    )
    total_errors: int = Field(
        default=0,
        description="Number of ERROR-classified log events.",
    )
    total_critical: int = Field(
        default=0,
        description="Number of CRITICAL-classified log events.",
    )
    total_unknown: int = Field(
        default=0,
        description="Number of log events that could not be classified.",
    )

    # --- Error grouping ---
    error_groups: List[ErrorGroupSummary] = Field(
        default_factory=list,
        description=(
            "List of error groups, one entry per unique fingerprint. "
            "Sorted by count descending (most frequent first)."
        ),
    )
    unique_error_fingerprints: int = Field(
        default=0,
        description="Number of distinct error fingerprints found.",
    )

    # --- Error rate ---
    error_rate_per_minute: float = Field(
        default=0.0,
        description="Errors per minute calculated over the analysis window.",
    )
    error_rate_per_hour: float = Field(
        default=0.0,
        description="Errors per hour calculated over the analysis window.",
    )
    analysis_window_seconds: float = Field(
        default=0.0,
        description="Duration of the analysis time window in seconds.",
    )
    window_start: Optional[datetime] = Field(
        default=None,
        description="Start of the analysis time window (UTC).",
    )
    window_end: Optional[datetime] = Field(
        default=None,
        description="End of the analysis time window (UTC).",
    )

    # --- Analysis metadata ---
    analysis_warnings: List[str] = Field(
        default_factory=list,
        description=(
            "Non-fatal warnings encountered during analysis "
            "(e.g. events skipped due to malformed data)."
        ),
    )
    analysis_errors: List[str] = Field(
        default_factory=list,
        description=(
            "Errors encountered during analysis that caused events to be skipped."
        ),
    )

    model_config = {"frozen": False}

    # --- Convenience properties ---

    @property
    def has_errors(self) -> bool:
        """True if any ERROR or CRITICAL events were found."""
        return self.total_errors > 0 or self.total_critical > 0

    @property
    def total_actionable(self) -> int:
        """Total errors + critical events."""
        return self.total_errors + self.total_critical

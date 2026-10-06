"""
OpsTrace Collector — Error-Rate Analyser
Phase 6: Log Analysis & Intelligence

Deterministic error-rate analysis using timestamps from log event records.

Purpose:
  Calculate actionable metrics such as:
  - Total error count in a time window.
  - Errors per minute / per hour.
  - Error counts grouped by fingerprint.

Design:
  - All calculations are pure Python; no database reads.
  - The analyser operates on in-memory sequences of ``CollectedLogEvent``.
  - Time windows are specified as ``timedelta`` objects (flexible).
  - An empty event list is handled safely (returns zeros).
  - All results are deterministic for the same input.

Security:
  - No external calls.
  - Log message content is counted/measured, never executed.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Dict, List, Optional, Sequence

from collector.app.collectors.log_models import CollectedLogEvent

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Window rate result
# ---------------------------------------------------------------------------


@dataclass
class WindowRate:
    """
    Error-rate statistics for a single time window.

    Attributes:
        window_seconds: Length of the analysis window in seconds.
        error_count:    Number of error-level events in the window.
        warning_count:  Number of warning-level events in the window.
        critical_count: Number of critical-level events in the window.
        total_count:    Total events (all levels) in the window.
        errors_per_minute: Calculated error rate (errors / window minutes).
        errors_per_hour:   Calculated error rate (errors / window hours).
        window_start:   Start of the analysis window (UTC), or None if empty.
        window_end:     End of the analysis window (UTC), or None if empty.
        fingerprint_counts: Error count broken down by fingerprint.
    """

    window_seconds: float
    error_count: int = 0
    warning_count: int = 0
    critical_count: int = 0
    total_count: int = 0
    errors_per_minute: float = 0.0
    errors_per_hour: float = 0.0
    window_start: Optional[datetime] = None
    window_end: Optional[datetime] = None
    fingerprint_counts: Dict[str, int] = field(default_factory=dict)


# ---------------------------------------------------------------------------
# Helper utilities
# ---------------------------------------------------------------------------

_ERROR_LEVELS = {"ERROR", "CRITICAL", "FATAL"}
_WARNING_LEVELS = {"WARN", "WARNING"}
_CRITICAL_LEVELS = {"CRITICAL", "FATAL"}


def _utc(ts: Optional[datetime]) -> Optional[datetime]:
    """Return a UTC-aware datetime or None."""
    if ts is None:
        return None
    if ts.tzinfo is None:
        return ts.replace(tzinfo=timezone.utc)
    return ts.astimezone(timezone.utc)


def _level_str(event: CollectedLogEvent) -> str:
    """Return the normalised upper-case level string for an event."""
    try:
        return event.level.value.upper()
    except Exception:
        return "UNKNOWN"


# ---------------------------------------------------------------------------
# Public analyser class
# ---------------------------------------------------------------------------


class ErrorRateAnalyzer:
    """
    Deterministic error-rate analyser for sequences of ``CollectedLogEvent``.

    Example::

        analyser = ErrorRateAnalyzer()

        # Analyse all events in a 10-minute window
        rate = analyser.calculate(events, window=timedelta(minutes=10))
        print(rate.errors_per_minute)

        # Count errors per fingerprint
        print(rate.fingerprint_counts)

    The analyser is stateless; a single instance can be reused.
    """

    def calculate(
        self,
        events: Sequence[CollectedLogEvent],
        window: Optional[timedelta] = None,
    ) -> WindowRate:
        """
        Calculate error-rate statistics for the given event sequence.

        The *window* parameter controls the denominator of the rate calculation:
          - If ``window`` is given, it is used directly.
          - If ``window`` is None, the window is inferred from the span between
            the earliest and latest event timestamps.
          - If only one event exists, a 1-minute window is assumed.
          - If the inferred window is zero (all events at the same instant),
            a 1-second window is assumed to avoid division by zero.

        Args:
            events: Sequence of ``CollectedLogEvent`` objects to analyse.
            window: Optional explicit time window for rate calculation.

        Returns:
            A ``WindowRate`` with all calculated fields populated.
        """
        if not events:
            window_secs = window.total_seconds() if window else 0.0
            return WindowRate(window_seconds=window_secs)

        timestamps: List[datetime] = []
        error_count = 0
        warning_count = 0
        critical_count = 0
        fp_counts: Dict[str, int] = {}

        for event in events:
            ts = _utc(event.timestamp)
            if ts is not None:
                timestamps.append(ts)

            lvl = _level_str(event)

            if lvl in _CRITICAL_LEVELS:
                critical_count += 1
                error_count += 1  # criticals are also errors
            elif lvl in _ERROR_LEVELS:
                error_count += 1
            elif lvl in _WARNING_LEVELS:
                warning_count += 1

            # Count per fingerprint for error-class events
            if lvl in _ERROR_LEVELS or lvl in _CRITICAL_LEVELS:
                fp = (event.fingerprint or "").strip() or "__unknown__"
                fp_counts[fp] = fp_counts.get(fp, 0) + 1

        # Determine window
        window_start: Optional[datetime] = None
        window_end: Optional[datetime] = None

        if timestamps:
            window_start = min(timestamps)
            window_end = max(timestamps)

        if window is not None:
            effective_window_secs = max(window.total_seconds(), 1.0)
        elif window_start is not None and window_end is not None:
            span = (window_end - window_start).total_seconds()
            effective_window_secs = max(span, 1.0)
        else:
            effective_window_secs = 60.0  # fallback: 1 minute

        errors_per_minute = (error_count / effective_window_secs) * 60.0
        errors_per_hour = (error_count / effective_window_secs) * 3600.0

        return WindowRate(
            window_seconds=effective_window_secs,
            error_count=error_count,
            warning_count=warning_count,
            critical_count=critical_count,
            total_count=len(events),
            errors_per_minute=round(errors_per_minute, 4),
            errors_per_hour=round(errors_per_hour, 4),
            window_start=window_start,
            window_end=window_end,
            fingerprint_counts=fp_counts,
        )

    def calculate_for_level(
        self,
        events: Sequence[CollectedLogEvent],
        level: str,
        window: Optional[timedelta] = None,
    ) -> WindowRate:
        """
        Calculate rate statistics for events matching a specific level.

        Args:
            events: Full event sequence.
            level:  Level string to filter on (case-insensitive), e.g. ``"ERROR"``.
            window: Optional explicit time window.

        Returns:
            A ``WindowRate`` computed on the filtered subset.
        """
        filtered = [e for e in events if _level_str(e) == level.upper()]
        return self.calculate(filtered, window=window)

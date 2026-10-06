"""
OpsTrace Collector — Log Grouping / Deduplication
Phase 6: Log Analysis & Intelligence

Groups repeated log events by their fingerprint to identify clusters of
the same underlying error without deleting original log records.

Purpose:
  When 100 identical "database connection refused" errors arrive, this
  component produces a single ``ErrorGroup`` with count=100, first_seen,
  last_seen, and the representative message — rather than treating them
  as 100 unrelated problems.

Design:
  - Groups are keyed by fingerprint string.
  - If a log event has no fingerprint, a new one is generated using the
    ``FingerprintGenerator`` so that grouping still works.
  - Original log events are not modified or deleted.
  - The grouper is stateless; each ``group()`` call starts fresh.
  - All edge cases (missing fingerprint, missing timestamp, empty input)
    are handled safely.

Security:
  - Log message content is stored as-is (not executed or interpreted).
"""

from __future__ import annotations

import logging
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Dict, List, Optional, Sequence

from collector.app.collectors.log_models import CollectedLogEvent
from collector.app.analyzers.fingerprint import FingerprintGenerator

logger = logging.getLogger(__name__)

_fp_gen = FingerprintGenerator()


# ---------------------------------------------------------------------------
# ErrorGroup dataclass
# ---------------------------------------------------------------------------


@dataclass
class ErrorGroup:
    """
    A deduplicated group of log events sharing the same fingerprint.

    Attributes:
        fingerprint:    The 64-char SHA-256 fingerprint that identifies this group.
        count:          Total number of events in this group.
        first_seen:     UTC timestamp of the earliest event in the group.
        last_seen:      UTC timestamp of the most recent event in the group.
        sample_message: Representative log message (from the first event seen).
        level:          Log level of the events in this group (from first event).
        source:         Log source identifier (from first event).
        event_indices:  Indices of matching events in the original input list.
    """

    fingerprint: str
    count: int = 0
    first_seen: Optional[datetime] = None
    last_seen: Optional[datetime] = None
    sample_message: str = ""
    level: str = "UNKNOWN"
    source: str = "unknown"
    event_indices: List[int] = field(default_factory=list)

    def update(self, event: CollectedLogEvent, index: int) -> None:
        """
        Incorporate one more event into this group.

        Args:
            event: The ``CollectedLogEvent`` being added.
            index: Its 0-based index in the original input list.
        """
        self.count += 1
        self.event_indices.append(index)

        ts = _safe_ts(event.timestamp)
        if self.first_seen is None or (ts is not None and ts < self.first_seen):
            self.first_seen = ts
        if self.last_seen is None or (ts is not None and ts > self.last_seen):
            self.last_seen = ts

        # Keep the sample message from the first event (already set at creation).


# ---------------------------------------------------------------------------
# Helper
# ---------------------------------------------------------------------------


def _safe_ts(ts: Optional[datetime]) -> Optional[datetime]:
    """
    Return a timezone-aware UTC datetime or None.

    Converts naive datetimes to UTC; returns None for genuinely absent timestamps.
    """
    if ts is None:
        return None
    if ts.tzinfo is None:
        return ts.replace(tzinfo=timezone.utc)
    return ts.astimezone(timezone.utc)


def _resolve_fingerprint(event: CollectedLogEvent) -> str:
    """
    Return the event's fingerprint, generating one if absent.

    Args:
        event: A ``CollectedLogEvent``.

    Returns:
        A 64-char hex fingerprint string (never empty).
    """
    if event.fingerprint and len(event.fingerprint) >= 8:
        return event.fingerprint[:64]
    return _fp_gen.generate(
        message=event.message,
        level=event.level.value if event.level else None,
        source=event.source,
    )


# ---------------------------------------------------------------------------
# Public grouper class
# ---------------------------------------------------------------------------


class LogGrouper:
    """
    Groups a sequence of ``CollectedLogEvent`` objects by fingerprint.

    Example::

        grouper = LogGrouper()
        groups = grouper.group(events)
        for fp, grp in groups.items():
            print(fp, grp.count, grp.first_seen)

    The grouper is stateless; a single instance can be reused across calls.
    """

    def group(
        self,
        events: Sequence[CollectedLogEvent],
    ) -> Dict[str, ErrorGroup]:
        """
        Group events by their fingerprint.

        Args:
            events: An ordered sequence of ``CollectedLogEvent`` objects.
                    Empty sequences return an empty dict.

        Returns:
            A dict mapping fingerprint → ``ErrorGroup``.  The dict is ordered
            by first appearance of each fingerprint in the input.
        """
        groups: Dict[str, ErrorGroup] = {}

        for idx, event in enumerate(events):
            try:
                fp = _resolve_fingerprint(event)
            except Exception as exc:
                logger.warning(
                    "LogGrouper: could not resolve fingerprint for event[%d]: %s",
                    idx,
                    exc,
                )
                fp = f"__ungrouped_{idx}__"

            if fp not in groups:
                groups[fp] = ErrorGroup(
                    fingerprint=fp,
                    sample_message=event.message or "(empty)",
                    level=event.level.value if event.level else "UNKNOWN",
                    source=event.source or "unknown",
                )

            try:
                groups[fp].update(event, idx)
            except Exception as exc:
                logger.warning(
                    "LogGrouper: error updating group %s for event[%d]: %s",
                    fp,
                    idx,
                    exc,
                )

        return groups

    def group_by_level(
        self,
        events: Sequence[CollectedLogEvent],
        level: str,
    ) -> Dict[str, ErrorGroup]:
        """
        Group only events matching the specified level string (case-insensitive).

        Convenience wrapper used by the error-rate analyser and the main engine.

        Args:
            events: Full sequence of log events.
            level:  Level string to filter on, e.g. ``"ERROR"``.

        Returns:
            Groups dict (fingerprint → ErrorGroup) for matching events only.
        """
        filtered = [e for e in events if (e.level.value if e.level else "").upper() == level.upper()]
        return self.group(filtered)

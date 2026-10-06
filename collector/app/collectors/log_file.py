"""
OpsTrace Collector — File Log Collector
Phase 5: Log Collection and Ingestion

Collects log entries from plain-text log files using incremental
(tail-style) reading.

Key behaviours:
  - Maintains a byte offset so only new log lines are read each cycle.
  - Detects file rotation/truncation (file is shorter than last offset)
    and resets to the beginning automatically.
  - Handles missing files, empty files, and permission errors gracefully.
  - Never crashes the daemon due to a single problematic log file.
  - Log file paths are fully configurable (no hard-coded paths).

Security:
  - Read-only file access; no writes to the monitored file system.
  - Log content is treated as untrusted text input and never executed.
  - Permission errors are logged and skipped, not propagated.
"""

from __future__ import annotations

import logging
import os
from pathlib import Path
from typing import Dict, List, Optional

from collector.app.collectors.log_models import CollectedLogEvent, LogSourceType
from collector.app.collectors.log_parser import parse_log_line

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Log source abstraction
# ---------------------------------------------------------------------------


class LogSource:
    """
    Abstract representation of a log source.

    Subclasses implement ``collect()`` to return a list of new
    ``CollectedLogEvent`` instances since the last call.

    This abstraction allows additional source types (file, journal,
    syslog socket, etc.) to be added without modifying the collector
    orchestration layer.
    """

    def collect(
        self, hostname: Optional[str] = None
    ) -> List[CollectedLogEvent]:  # pragma: no cover
        """
        Collect and return new log events from this source.

        Args:
            hostname: Optional hostname to embed in each collected event.

        Returns:
            List of new ``CollectedLogEvent`` objects.  Returns an empty
            list (never raises) when no new data is available or an error
            occurs.
        """
        raise NotImplementedError


# ---------------------------------------------------------------------------
# File log collector
# ---------------------------------------------------------------------------


class FileLogCollector(LogSource):
    """
    Collects log entries from a plain-text log file using incremental
    (positional/offset-based) reading.

    Offset management:
      - On first call: reads from the current end-of-file so that stale
        historical logs are not replayed on daemon restart.
        (Override ``start_from_beginning=True`` to read the whole file
        from byte 0 — useful for short-lived one-shot collection.)
      - Subsequent calls: reads only bytes appended since the last call.
      - Truncation/rotation detected when the current file size is less
        than the stored offset.  In that case the offset resets to 0 and
        the new file content is read from the start.

    Args:
        log_path:           Absolute or relative path to the log file.
        source_name:        Human-readable source name (defaults to the
                            file path, truncated to 100 chars).
        start_from_beginning: If True, start reading from byte 0 on first
                              collection.  Defaults to False (tail behaviour).
        encoding:           File encoding; defaults to 'utf-8'.
        errors:             How to handle decoding errors: 'replace' (default)
                            avoids crashes on binary content.
    """

    def __init__(
        self,
        log_path: str,
        source_name: Optional[str] = None,
        start_from_beginning: bool = False,
        encoding: str = "utf-8",
        errors: str = "replace",
    ) -> None:
        self._path = Path(log_path)
        self._source_name: str = (source_name or str(log_path))[:100]
        self._encoding = encoding
        self._errors = errors

        # Byte offset into the file; None means "not yet initialised".
        self._offset: Optional[int] = 0 if start_from_beginning else None

    # ------------------------------------------------------------------
    # Public interface
    # ------------------------------------------------------------------

    @property
    def path(self) -> Path:
        """The path to the monitored log file."""
        return self._path

    @property
    def offset(self) -> Optional[int]:
        """Current byte offset within the file (None = not yet read)."""
        return self._offset

    def collect(
        self, hostname: Optional[str] = None
    ) -> List[CollectedLogEvent]:
        """
        Read new lines from the log file and return structured events.

        Returns an empty list without raising when:
          - The file does not exist.
          - A permission error occurs.
          - The file is empty or has no new content.

        Errors are logged at WARNING level so the operator can investigate.

        Args:
            hostname: Hostname to embed in each log event.

        Returns:
            List of ``CollectedLogEvent`` objects for newly appended lines.
        """
        try:
            if not self._path.exists():
                logger.debug("Log file not found — skipping: %s", self._path)
                return []
            current_size = self._path.stat().st_size
        except PermissionError:
            logger.warning(
                "Permission denied reading stat of log file: %s", self._path
            )
            return []
        except OSError as exc:
            logger.warning("Cannot stat log file %s: %s", self._path, exc)
            return []

        # First-time initialisation: start tailing from the current end.
        if self._offset is None:
            self._offset = current_size
            logger.debug(
                "FileLogCollector initialised at offset=%d for %s",
                self._offset,
                self._path,
            )
            return []

        # Detect rotation or truncation.
        if current_size < self._offset:
            logger.info(
                "Log file %s appears to have been rotated or truncated "
                "(size=%d < offset=%d) — resetting to beginning.",
                self._path,
                current_size,
                self._offset,
            )
            self._offset = 0

        # Nothing new to read.
        if current_size == self._offset:
            return []

        return self._read_new_lines(hostname=hostname)

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _read_new_lines(
        self, hostname: Optional[str]
    ) -> List[CollectedLogEvent]:
        """
        Open the file, seek to ``_offset``, read new lines, and parse them.

        Updates ``_offset`` to the new file position after reading.
        """
        events: List[CollectedLogEvent] = []

        try:
            with self._path.open(
                mode="r", encoding=self._encoding, errors=self._errors
            ) as fh:
                fh.seek(self._offset)
                for raw_line in fh:
                    raw_line = raw_line.rstrip("\n\r")
                    if not raw_line.strip():
                        continue  # skip blank lines
                    try:
                        event = parse_log_line(
                            raw_line=raw_line,
                            source=self._source_name,
                            source_type=LogSourceType.FILE,
                            hostname=hostname,
                        )
                        events.append(event)
                    except Exception as exc:
                        logger.debug(
                            "Failed to parse log line from %s: %s — raw: %.80s",
                            self._path,
                            exc,
                            raw_line,
                        )
                # Record the new file position so subsequent calls skip
                # already-processed content.
                self._offset = fh.tell()

        except PermissionError:
            logger.warning(
                "Permission denied reading log file: %s — skipping this cycle",
                self._path,
            )
        except OSError as exc:
            logger.warning(
                "Cannot read log file %s: %s — skipping this cycle",
                self._path,
                exc,
            )

        logger.debug(
            "FileLogCollector: read %d new events from %s (offset now %d)",
            len(events),
            self._path,
            self._offset or 0,
        )
        return events


# ---------------------------------------------------------------------------
# Multi-file collector factory
# ---------------------------------------------------------------------------


def build_file_collectors(
    log_file_paths: List[str],
    start_from_beginning: bool = False,
) -> List[FileLogCollector]:
    """
    Build a ``FileLogCollector`` for each configured log file path.

    Paths that are empty strings or whitespace-only are silently skipped.

    Args:
        log_file_paths:       List of log file paths (strings).
        start_from_beginning: Passed to each ``FileLogCollector``.

    Returns:
        List of configured ``FileLogCollector`` instances.
    """
    collectors: List[FileLogCollector] = []
    seen: set = set()

    for raw_path in log_file_paths:
        path = raw_path.strip()
        if not path:
            continue
        if path in seen:
            logger.debug("Duplicate log file path ignored: %s", path)
            continue
        seen.add(path)
        collectors.append(
            FileLogCollector(
                log_path=path,
                start_from_beginning=start_from_beginning,
            )
        )
        logger.debug("Registered file log collector for: %s", path)

    return collectors


def collect_from_files(
    collectors: List[FileLogCollector],
    hostname: Optional[str] = None,
) -> tuple[List[CollectedLogEvent], List[str]]:
    """
    Run all file collectors and aggregate their results.

    Failures in individual collectors are captured as error strings rather
    than propagating exceptions.

    Args:
        collectors: List of ``FileLogCollector`` instances to run.
        hostname:   Hostname embedded in each event.

    Returns:
        Tuple of (events, errors) where ``events`` is the combined list of
        all collected log events and ``errors`` is a list of non-fatal error
        description strings.
    """
    all_events: List[CollectedLogEvent] = []
    errors: List[str] = []

    for collector in collectors:
        try:
            events = collector.collect(hostname=hostname)
            all_events.extend(events)
        except Exception as exc:
            msg = f"file log collector failed for {collector.path}: {exc}"
            logger.error("Log collection error — %s", msg)
            errors.append(msg)

    return all_events, errors

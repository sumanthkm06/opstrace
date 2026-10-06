"""
OpsTrace Collector — Systemd Journal Collector
Phase 5: Log Collection and Ingestion

Collects recent log entries from the Linux systemd journal using the
``journalctl`` command-line tool.

Key behaviours:
  - Uses ``journalctl --output=json --lines=<N>`` to fetch the N most
    recent journal entries, or ``--since=`` to fetch entries since a
    cursor timestamp.
  - Handles all failure modes gracefully: unavailable journalctl, 
    permission errors, command timeout, non-zero exit codes, empty output.
  - On non-Linux platforms (Windows development machines), the collector
    detects that journalctl is unavailable and returns an empty list.
  - Does NOT modify any system services or journal files.
  - Does NOT execute arbitrary commands derived from log contents.

Safety contract:
  - Only ``journalctl`` with fixed, safe, read-only flags is invoked.
  - No user-supplied or log-derived text is ever passed to subprocess.
  - The command list is constructed from configuration values only.
"""

from __future__ import annotations

import json
import logging
import shutil
import subprocess
from datetime import datetime, timezone
from typing import List, Optional

from collector.app.collectors.log_models import (
    CollectedLogEvent,
    LogLevel,
    LogSourceType,
    normalise_level,
)

logger = logging.getLogger(__name__)

# Conservative timeout for the journalctl subprocess (seconds).
_JOURNALCTL_TIMEOUT = 15

# Maximum number of journal entries fetched per cycle when no cursor is set.
_DEFAULT_LINES = 200


def _journalctl_available() -> bool:
    """
    Return True if the ``journalctl`` binary is on the system PATH.

    Returns False on Windows and in minimal Linux containers without systemd.
    """
    return shutil.which("journalctl") is not None


def _parse_journal_entry(
    entry: dict,
    hostname: Optional[str] = None,
) -> Optional[CollectedLogEvent]:
    """
    Convert a single JSON journal entry dict into a ``CollectedLogEvent``.

    journalctl --output=json fields of interest:
      __REALTIME_TIMESTAMP  — microseconds since epoch (string)
      PRIORITY              — syslog priority 0-7 (string)
      _SYSTEMD_UNIT         — originating systemd unit name
      _COMM                 — process name / command
      SYSLOG_IDENTIFIER     — syslog identifier
      _HOSTNAME             — originating hostname
      MESSAGE               — the actual log message

    Returns None if the entry lacks a MESSAGE field.
    """
    message = entry.get("MESSAGE", "")
    if not message:
        return None

    # Timestamp — journalctl provides microseconds since Unix epoch
    ts: Optional[datetime] = None
    raw_ts = entry.get("__REALTIME_TIMESTAMP")
    if raw_ts:
        try:
            ts = datetime.fromtimestamp(
                int(raw_ts) / 1_000_000, tz=timezone.utc
            )
        except (ValueError, TypeError, OSError):
            ts = None

    # Severity — PRIORITY is a syslog priority string (0=emerg … 7=debug)
    level = _priority_to_level(entry.get("PRIORITY"))

    # Service / unit name
    service_name: Optional[str] = (
        entry.get("_SYSTEMD_UNIT")
        or entry.get("SYSLOG_IDENTIFIER")
        or entry.get("_COMM")
    )
    if service_name:
        # Clean up '.service' suffix for brevity in source
        service_name = service_name.replace(".service", "")

    # Hostname from journal entry (overrides caller hostname if present)
    entry_hostname = entry.get("_HOSTNAME") or hostname

    # Source identifier: unit name or "journal"
    source = (
        entry.get("_SYSTEMD_UNIT", "")
        or entry.get("SYSLOG_IDENTIFIER", "")
        or "journal"
    )
    source = source[:100]

    # Preserve selected safe, non-sensitive journal fields in metadata
    meta = {}
    for field in ("PRIORITY", "_SYSTEMD_UNIT", "_COMM", "SYSLOG_IDENTIFIER",
                  "_PID", "_UID", "_GID", "_TRANSPORT", "__CURSOR"):
        val = entry.get(field)
        if val is not None:
            meta[field] = val

    return CollectedLogEvent(
        timestamp=ts or datetime.now(tz=timezone.utc),
        hostname=entry_hostname,
        service_name=service_name,
        level=level,
        message=str(message).strip() or "(empty)",
        source=source,
        source_type=LogSourceType.JOURNAL,
        metadata=meta if meta else None,
    )


def _priority_to_level(priority: Optional[str]) -> LogLevel:
    """
    Map a syslog PRIORITY string (0–7) to a ``LogLevel``.

    Syslog priorities:
      0 emerg, 1 alert, 2 crit, 3 err, 4 warning, 5 notice, 6 info, 7 debug

    Unknown values default to INFO.
    """
    _MAP = {
        "0": LogLevel.CRITICAL,
        "1": LogLevel.CRITICAL,
        "2": LogLevel.CRITICAL,
        "3": LogLevel.ERROR,
        "4": LogLevel.WARNING,
        "5": LogLevel.INFO,
        "6": LogLevel.INFO,
        "7": LogLevel.DEBUG,
    }
    return _MAP.get(str(priority or ""), LogLevel.INFO)


def collect_journal(
    lines: int = _DEFAULT_LINES,
    since_cursor: Optional[str] = None,
    unit_filter: Optional[str] = None,
    hostname: Optional[str] = None,
) -> tuple[List[CollectedLogEvent], Optional[str]]:
    """
    Collect recent entries from the systemd journal.

    Invokes ``journalctl`` in a subprocess with fixed, read-only flags.
    No text from log contents is ever passed to the subprocess command.

    Args:
        lines:          Number of most-recent entries to fetch when no
                        cursor is provided (default: 200).
        since_cursor:   Optional journal cursor string.  When provided,
                        entries after this cursor are fetched instead of
                        the last N lines.
        unit_filter:    Optional systemd unit name to filter on, e.g.
                        "nginx.service".  Only safe, fixed strings should
                        be passed here — never user-supplied input.
        hostname:       Hostname to embed in events when the journal entry
                        does not contain ``_HOSTNAME``.

    Returns:
        Tuple of:
          - List of ``CollectedLogEvent`` objects.
          - New cursor string from the last fetched entry (for use in the
            next call), or None if no entries were fetched.

    Raises:
        Nothing.  All errors are handled internally and return ([], None).
    """
    if not _journalctl_available():
        logger.info(
            "journalctl not found — skipping journal collection. "
            "This is expected on Windows and in non-systemd containers."
        )
        return [], None

    # Build a safe, fixed command.  No log-derived text is ever injected here.
    cmd = [
        "journalctl",
        "--output=json",
        "--no-pager",
    ]

    if since_cursor:
        cmd += ["--after-cursor", since_cursor]
    else:
        cmd += ["--lines", str(int(lines))]  # cast to int to prevent injection

    if unit_filter:
        # unit_filter must be a fixed configuration value, not user input.
        cmd += ["--unit", unit_filter]

    logger.debug("Invoking: %s", " ".join(cmd))

    try:
        result = subprocess.run(  # noqa: S603
            cmd,
            capture_output=True,
            text=True,
            timeout=_JOURNALCTL_TIMEOUT,
            check=False,
        )
    except FileNotFoundError:
        logger.info("journalctl binary not found — skipping journal collection.")
        return [], None
    except subprocess.TimeoutExpired:
        logger.warning(
            "journalctl timed out after %ds — skipping this cycle.",
            _JOURNALCTL_TIMEOUT,
        )
        return [], None
    except OSError as exc:
        logger.warning("OSError running journalctl: %s — skipping.", exc)
        return [], None

    if result.returncode not in (0, 1):
        # Exit code 1 from journalctl means "no entries matched" — acceptable.
        logger.warning(
            "journalctl exited with code %d: %.200s",
            result.returncode,
            result.stderr,
        )
        return [], None

    if not result.stdout.strip():
        logger.debug("journalctl returned no output.")
        return [], None

    events: List[CollectedLogEvent] = []
    last_cursor: Optional[str] = None

    for line in result.stdout.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            entry = json.loads(line)
        except json.JSONDecodeError as exc:
            logger.debug("Could not parse journal JSON line: %s — %.80s", exc, line)
            continue

        # Track the last cursor for stateful subsequent calls.
        cursor = entry.get("__CURSOR")
        if cursor:
            last_cursor = cursor

        event = _parse_journal_entry(entry, hostname=hostname)
        if event is not None:
            events.append(event)

    logger.debug(
        "JournalCollector: parsed %d events from journalctl output.",
        len(events),
    )
    return events, last_cursor

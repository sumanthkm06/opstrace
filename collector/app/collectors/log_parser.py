"""
OpsTrace Collector — Log Parser
Phase 5: Log Collection and Ingestion

Lightweight parsing for common Linux log formats.

The parser attempts to extract structured fields (timestamp, level,
service, message) from raw log lines.  If a field cannot be extracted,
a safe default is used rather than crashing.

Supported formats (attempted in order):

1. RFC 5424 / syslog-style:
   2024-01-15T12:34:56.789Z hostname service[pid]: LEVEL message
   2024-01-15 12:34:56,789 LEVEL message

2. ISO 8601 with level:
   2024-01-15T12:34:56+00:00 [WARNING] some message

3. Python/Java-style:
   2024-01-15 12:34:56,123 - service - WARNING - message

4. Apache/nginx combined log (partial):
   192.168.1.1 - - [15/Jan/2024:12:34:56 +0000] "GET / HTTP/1.1" 200 1234

5. Bare message with no recognisable structure:
   anything else → preserved as the full message, level=INFO

Security:
  - Log message content is never executed or interpreted as code.
  - Regex patterns have timeouts effectively bounded by the fixed
    line lengths of individual log entries.
"""

from __future__ import annotations

import logging
import re
from datetime import datetime, timezone
from typing import Optional, Tuple

from collector.app.collectors.log_models import CollectedLogEvent, LogLevel, LogSourceType, normalise_level

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Compiled regular expressions
# ---------------------------------------------------------------------------

# ISO 8601 / RFC 3339 timestamp at the start of a line.
# Matches:  2024-01-15T12:34:56Z
#           2024-01-15T12:34:56.789Z
#           2024-01-15T12:34:56+05:30
#           2024-01-15 12:34:56,789
_RE_ISO_TS = re.compile(
    r"^(?P<ts>\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:[.,]\d+)?(?:Z|[+-]\d{2}:?\d{2})?)"
)

# Syslog BSD-style timestamp: Jan 15 12:34:56
_RE_SYSLOG_BSD_TS = re.compile(
    r"^(?P<ts>(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})"
)

# Apache/nginx CLF timestamp: [15/Jan/2024:12:34:56 +0000]
_RE_APACHE_TS = re.compile(
    r"\[(?P<ts>\d{2}/\w{3}/\d{4}:\d{2}:\d{2}:\d{2}\s[+-]\d{4})\]"
)

# Log level keyword anywhere in the line (word boundary, case-insensitive).
_RE_LEVEL = re.compile(
    r"\b(?P<lvl>DEBUG|INFO|NOTICE|WARN(?:ING)?|ERR(?:OR)?|CRIT(?:ICAL)?|FATAL|EMERG|ALERT)\b",
    re.IGNORECASE,
)

# syslog service[pid]: pattern
_RE_SERVICE_PID = re.compile(r"(?P<svc>[A-Za-z0-9_.-]+)\[(?P<pid>\d+)\]:\s*")

# Python logging format: timestamp - svcname - LEVEL - message
_RE_PYTHON_FMT = re.compile(
    r"^(?P<ts>[\d\-T :,+Z]+?)\s+-\s+(?P<svc>[^-]+?)\s+-\s+(?P<lvl>[A-Z]+)\s+-\s+(?P<msg>.+)$"
)


# ---------------------------------------------------------------------------
# Timestamp parsers (tried in order)
# ---------------------------------------------------------------------------

_ISO_FORMATS = [
    "%Y-%m-%dT%H:%M:%S.%fZ",
    "%Y-%m-%dT%H:%M:%SZ",
    "%Y-%m-%dT%H:%M:%S.%f%z",
    "%Y-%m-%dT%H:%M:%S%z",
    "%Y-%m-%d %H:%M:%S.%f",
    "%Y-%m-%d %H:%M:%S,%f",
    "%Y-%m-%d %H:%M:%S",
]

_BSD_SYSLOG_FORMAT = "%b %d %H:%M:%S"
_APACHE_FORMAT = "%d/%b/%Y:%H:%M:%S %z"


def _parse_iso_timestamp(raw: str) -> Optional[datetime]:
    """
    Try to parse an ISO 8601 timestamp string.

    Returns a timezone-aware UTC datetime, or None on failure.
    """
    raw = raw.strip().replace(",", ".")
    for fmt in _ISO_FORMATS:
        try:
            dt = datetime.strptime(raw, fmt)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return dt.astimezone(timezone.utc)
        except ValueError:
            continue
    return None


def _parse_bsd_timestamp(raw: str) -> Optional[datetime]:
    """Parse a BSD syslog timestamp (no year, no TZ → assumed UTC / current year)."""
    try:
        dt = datetime.strptime(raw.strip(), _BSD_SYSLOG_FORMAT)
        dt = dt.replace(year=datetime.now(tz=timezone.utc).year, tzinfo=timezone.utc)
        return dt
    except ValueError:
        return None


def _parse_apache_timestamp(raw: str) -> Optional[datetime]:
    """Parse an Apache/nginx CLF timestamp."""
    try:
        dt = datetime.strptime(raw.strip(), _APACHE_FORMAT)
        return dt.astimezone(timezone.utc)
    except ValueError:
        return None


# ---------------------------------------------------------------------------
# Public parsing API
# ---------------------------------------------------------------------------


def parse_log_line(
    raw_line: str,
    source: str = "unknown",
    source_type: LogSourceType = LogSourceType.FILE,
    hostname: Optional[str] = None,
    default_service: Optional[str] = None,
) -> CollectedLogEvent:
    """
    Parse a single raw log line into a structured ``CollectedLogEvent``.

    Strategy:
      1. Try Python logging format (most structured).
      2. Extract ISO/BSD/Apache timestamp from the start.
      3. Extract log level keyword from the line.
      4. Extract service name from syslog ``service[pid]:`` pattern.
      5. Everything that could not be attributed to structure becomes
         the message.

    If no timestamp can be extracted, ``datetime.now(UTC)`` is used.
    If no level can be extracted, ``LogLevel.INFO`` is used.
    The raw line is always preserved in ``metadata["raw"]``.

    Args:
        raw_line:       Raw text of one log line.
        source:         Source identifier (file path or journal unit).
        source_type:    Whether this came from a file or the journal.
        hostname:       Host where the log was collected.
        default_service: Service name if determinable from context.

    Returns:
        A fully constructed ``CollectedLogEvent``.
    """
    line = raw_line.rstrip("\n\r")

    # Always preserve the raw line in metadata (treated as untrusted data only)
    meta: dict = {"raw": line}

    # Initialise defaults
    ts: Optional[datetime] = None
    level: LogLevel = LogLevel.INFO
    service_name: Optional[str] = default_service
    message: str = line

    # ---- 1. Try Python-style format first ----------------------------------
    m_py = _RE_PYTHON_FMT.match(line)
    if m_py:
        ts = _parse_iso_timestamp(m_py.group("ts"))
        level = normalise_level(m_py.group("lvl"))
        svc_raw = m_py.group("svc").strip()
        if svc_raw:
            service_name = svc_raw
        message = m_py.group("msg").strip()
        meta["format"] = "python"
        return CollectedLogEvent(
            timestamp=ts or datetime.now(tz=timezone.utc),
            hostname=hostname,
            service_name=service_name,
            level=level,
            message=message,
            source=source,
            source_type=source_type,
            metadata=meta,
        )

    # ---- 2. Extract timestamp ----------------------------------------------
    remainder = line  # portion of the line after timestamp is consumed

    m_iso = _RE_ISO_TS.match(line)
    if m_iso:
        ts_raw = m_iso.group("ts")
        ts = _parse_iso_timestamp(ts_raw)
        remainder = line[m_iso.end():].lstrip()
        meta["format"] = "iso"
    else:
        m_bsd = _RE_SYSLOG_BSD_TS.match(line)
        if m_bsd:
            ts_raw = m_bsd.group("ts")
            ts = _parse_bsd_timestamp(ts_raw)
            remainder = line[m_bsd.end():].lstrip()
            meta["format"] = "syslog_bsd"
        else:
            m_apache = _RE_APACHE_TS.search(line)
            if m_apache:
                ts_raw = m_apache.group("ts")
                ts = _parse_apache_timestamp(ts_raw)
                meta["format"] = "apache"
                # For Apache: remainder is the whole line; message stays as-is

    # ---- 3. Extract log level from the remainder ---------------------------
    m_lvl = _RE_LEVEL.search(remainder)
    if m_lvl:
        level = normalise_level(m_lvl.group("lvl"))
        meta["raw_level"] = m_lvl.group("lvl")

    # ---- 4. Extract service[pid] from the remainder ------------------------
    m_svc = _RE_SERVICE_PID.search(remainder)
    if m_svc and not service_name:
        service_name = m_svc.group("svc")
        meta["pid"] = m_svc.group("pid")

    # ---- 5. Determine message ----------------------------------------------
    # For syslog lines: strip hostname, service[pid]:, then take the rest.
    # For ISO lines: remainder is already post-timestamp.
    # Fallback: use the full original line.
    if remainder:
        # Remove service[pid]: prefix from the syslog body if present.
        body = _RE_SERVICE_PID.sub("", remainder, count=1).strip()
        # Remove the level keyword from the very beginning of the body.
        body = re.sub(r"^\[?" + re.escape(m_lvl.group("lvl")) + r"\]?\s*:?\s*", "", body,
                      flags=re.IGNORECASE) if m_lvl else body
        message = body if body else line
    else:
        message = line

    if not message.strip():
        message = line  # last-resort: keep the original

    return CollectedLogEvent(
        timestamp=ts or datetime.now(tz=timezone.utc),
        hostname=hostname,
        service_name=service_name,
        level=level,
        message=message.strip() or line.strip() or "(empty)",
        source=source,
        source_type=source_type,
        metadata=meta,
    )

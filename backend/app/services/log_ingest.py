"""
OpsTrace Log Ingestion Service
Phase 5: Log Collection and Ingestion

Business logic for persisting a batch of ingest log events to the
Phase 2 ``logs`` database table via the existing SQLAlchemy ``Log`` model.

Responsibilities:
  - Resolve or create the ``Host`` record for each unique hostname.
  - Optionally look up an existing ``Service`` record by name.
  - Compute a fingerprint if the event does not include one.
  - Persist each ``Log`` row; capture and count individual row failures.
  - Never raise from the service layer — return counts instead.

Host resolution strategy:
  - If the ``hostname`` field of the event is None or empty, the event is
    stored against a synthetic ``__unknown__`` host record.
  - Hosts are created with minimal data (hostname only) if they do not
    already exist.  This is intentionally lightweight; a proper host
    registration flow belongs to a later phase.

Security:
  - Log message content is stored as-is in the database (TEXT column).
  - No shell commands or SQL is derived from log content.
"""

from __future__ import annotations

import logging
import uuid
from datetime import datetime, timezone
from typing import Dict, List, Optional, Tuple

from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session

from backend.app.models.host import Host
from backend.app.models.log import Log
from backend.app.models.service import Service
from backend.app.schemas.logs import LogEventPayload, LogIngestRequest, LogIngestResponse

logger = logging.getLogger(__name__)

# Placeholder hostname used when the collector does not supply one.
_UNKNOWN_HOST = "__unknown__"


def _get_or_create_host(db: Session, hostname: Optional[str]) -> Host:
    """
    Look up an existing Host by hostname or create a minimal one.

    This is intentionally lightweight: only ``hostname`` is set.
    A proper host-registration endpoint is out of scope for Phase 5.

    Args:
        db:       SQLAlchemy session.
        hostname: The hostname string from the log event.

    Returns:
        The matching or newly created ``Host`` ORM object.
    """
    effective_hostname = (hostname or _UNKNOWN_HOST).strip() or _UNKNOWN_HOST

    host = db.query(Host).filter(Host.hostname == effective_hostname).first()
    if host is not None:
        return host

    logger.debug("Creating new host record for hostname='%s'", effective_hostname)
    host = Host(
        hostname=effective_hostname,
        status="healthy",
    )
    db.add(host)
    db.flush()  # populate host.id without committing the outer transaction
    return host


def _lookup_service(
    db: Session, service_name: Optional[str], host_id: uuid.UUID
) -> Optional[Service]:
    """
    Look up an existing Service by name scoped to the given host.

    Returns None if service_name is absent or no match is found.
    Service creation is out of scope for Phase 5.
    """
    if not service_name:
        return None
    return (
        db.query(Service)
        .filter(Service.name == service_name, Service.host_id == host_id)
        .first()
    )


def _accepted_level(level: str) -> str:
    """
    Map the ingest level string to a value accepted by the Phase 2
    CHECK constraint on ``logs.level``.

    Accepted values: DEBUG, INFO, WARN, WARNING, ERROR, CRITICAL, FATAL.
    Falls back to 'INFO' for unrecognised values.
    """
    _VALID = {"DEBUG", "INFO", "WARN", "WARNING", "ERROR", "CRITICAL", "FATAL"}
    upper = level.upper()
    return upper if upper in _VALID else "INFO"


def ingest_log_batch(
    db: Session,
    request: LogIngestRequest,
) -> LogIngestResponse:
    """
    Persist a batch of log events from the Phase 5 collector.

    Processing steps for each event:
      1. Resolve or create the ``Host`` row.
      2. Optionally look up the ``Service`` row.
      3. Compute ``fingerprint`` if not supplied.
      4. Create and add the ``Log`` row within the outer transaction.

    All events in the batch share a single DB transaction.  If the
    transaction fails mid-batch, partial results may be rolled back.
    Individual ``SQLAlchemyError`` rows are caught to prevent one bad
    event from rejecting the entire batch.

    Args:
        db:      SQLAlchemy session (injected by FastAPI dependency).
        request: Parsed ``LogIngestRequest`` from the HTTP body.

    Returns:
        ``LogIngestResponse`` with accepted/rejected counts.
    """
    if not request.events:
        logger.debug("Log ingest called with empty events list — nothing to do.")
        return LogIngestResponse(accepted=0, rejected=0, message="no events")

    accepted = 0
    rejected = 0

    # Cache host lookups within the batch to avoid repeated DB round-trips.
    host_cache: Dict[str, Host] = {}

    batch_id = str(uuid.uuid4())[:8]  # Short ID for logging correlation

    logger.debug(
        "Processing log ingest batch=%s events=%d", batch_id, len(request.events)
    )

    for event in request.events:
        try:
            hostname_key = (event.hostname or request.hostname or _UNKNOWN_HOST).strip()

            # Resolve host (cached within this batch)
            if hostname_key not in host_cache:
                host_cache[hostname_key] = _get_or_create_host(db, hostname_key)
            host = host_cache[hostname_key]

            # Resolve service (not cached — less frequent)
            service = _lookup_service(db, event.service_name, host.id)

            # Compute fingerprint if not provided
            fingerprint = event.fingerprint or event.compute_fingerprint()

            log_row = Log(
                host_id=host.id,
                service_id=service.id if service else None,
                timestamp=event.timestamp.replace(tzinfo=timezone.utc)
                if event.timestamp.tzinfo is None
                else event.timestamp,
                level=_accepted_level(event.level),
                message=event.message,
                source=event.source[:100],
                fingerprint=fingerprint[:64] if fingerprint else None,
                attributes=event.metadata,
            )
            db.add(log_row)
            accepted += 1

        except SQLAlchemyError as exc:
            logger.warning(
                "Failed to persist log event in batch=%s: %s", batch_id, exc
            )
            db.rollback()
            rejected += 1
        except Exception as exc:
            logger.error(
                "Unexpected error processing log event in batch=%s: %s", batch_id, exc
            )
            rejected += 1

    try:
        db.commit()
        logger.debug(
            "Log batch=%s committed: accepted=%d rejected=%d",
            batch_id, accepted, rejected,
        )
    except SQLAlchemyError as exc:
        logger.error("Failed to commit log batch=%s: %s", batch_id, exc)
        db.rollback()
        # If commit fails, count all as rejected.
        rejected += accepted
        accepted = 0

    return LogIngestResponse(
        accepted=accepted,
        rejected=rejected,
        batch_id=batch_id,
        message="ok" if rejected == 0 else f"{rejected} events rejected",
    )

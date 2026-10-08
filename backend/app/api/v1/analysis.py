"""
OpsTrace API v1 — Log Analysis Router
Phase 6: Log Analysis & Intelligence

Exposes GET /api/v1/logs/analyze

Reads stored log records from the Phase 2 ``logs`` table and runs them
through the Phase 6 analysis engine, returning a structured
``AnalysisResult`` as JSON.

Design:
  - Provides a read-only dashboard query over stored logs.
  - Database access uses the existing ``get_db`` dependency.
  - The analysis engine (``LogAnalyzer``) is instantiated per-request to
    remain stateless.
  - This endpoint performs READ-ONLY database queries; it does not modify
    any existing records.

Query parameters:
  limit:  Maximum number of recent log records to analyse (default: 1000).
          Capped at 10 000 to prevent accidental DoS.
  level:  Optional filter — only analyse logs at or above this level.
          Accepted: DEBUG, INFO, WARNING, ERROR, CRITICAL.

Security:
  - Log message content is treated as untrusted data throughout.
"""

from __future__ import annotations

import logging
from datetime import timedelta
from typing import Optional

from fastapi import APIRouter, Depends, Query, status
from sqlalchemy.orm import Session

from backend.app.core.database import get_db
from backend.app.models.log import Log

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/logs", tags=["logs"])


# ---------------------------------------------------------------------------
# Analysis endpoint
# ---------------------------------------------------------------------------


@router.get(
    "/analyze",
    status_code=status.HTTP_200_OK,
    summary="Analyse stored log events",
    description=(
        "Reads recent log records from the database and runs them through the "
        "Phase 6 analysis engine.  Returns classification counts, error groups "
        "(deduplicated by fingerprint), and error-rate statistics."
    ),
)
def analyze_logs(
    db: Session = Depends(get_db),
    limit: int = Query(
        default=1000,
        ge=1,
        le=10000,
        description="Maximum number of recent log records to analyse.",
    ),
    level: Optional[str] = Query(
        default=None,
        description="Filter to only analyse logs at this level (e.g. ERROR).",
    ),
) -> dict:
    """
    GET /api/v1/logs/analyze

    Fetch up to ``limit`` recent log records, convert them to
    ``CollectedLogEvent`` objects, and run the Phase 6 analysis pipeline.

    Returns the ``AnalysisResult`` serialised as JSON.
    """
    # Lazy import to keep Phase 6 decoupled from Phase 3 at module load time.
    from collector.app.analyzers.log_analyzer import LogAnalyzer
    from collector.app.collectors.log_models import CollectedLogEvent, LogLevel

    query = db.query(Log).order_by(Log.timestamp.desc())

    if level:
        normalised_level = level.strip().upper()
        query = query.filter(Log.level == normalised_level)

    db_logs = query.limit(limit).all()

    logger.debug("Log analysis: fetched %d records from DB.", len(db_logs))

    # Convert ORM Log rows → CollectedLogEvent for the analysis engine.
    events: list[CollectedLogEvent] = []
    conversion_errors = 0

    for db_log in db_logs:
        try:
            # Map the DB level string to the LogLevel enum safely.
            try:
                log_level = LogLevel(db_log.level)
            except ValueError:
                log_level = LogLevel.INFO

            event = CollectedLogEvent(
                timestamp=db_log.timestamp,
                hostname=db_log.host.hostname if db_log.host else None,
                service_name=(
                    db_log.service.name if db_log.service else None
                ),
                level=log_level,
                message=db_log.message or "(empty)",
                source=db_log.source or "unknown",
                fingerprint=db_log.fingerprint,
                metadata=db_log.attributes,
            )
            events.append(event)
        except Exception as exc:
            logger.warning("Failed to convert log row id=%s: %s", db_log.id, exc)
            conversion_errors += 1

    analyzer = LogAnalyzer()
    result = analyzer.analyze(events)

    if conversion_errors:
        result.analysis_warnings.append(
            f"{conversion_errors} database records could not be converted."
        )

    return result.model_dump(mode="json")

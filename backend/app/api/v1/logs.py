"""
OpsTrace API v1 — Log Ingestion Router
Phase 5: Log Collection and Ingestion

Handles POST /api/v1/logs/ingest

Receives a batch of structured log events from the Phase 5 collector,
validates them via Pydantic, and persists them through the Phase 2 Log model.

Authentication:
  Reuses the existing ``COLLECTOR_API_KEY`` bearer-token scheme established
  in Phase 3/4.  Requests without a valid key return 403.

Design:
  - One endpoint for the full Phase 5 scope: batch log ingestion.
  - No advanced log analytics, no incident detection, no dashboards.
  - Business logic is delegated to the service layer (log_ingest.py).

Security:
  - Authorization header value is NEVER logged.
  - Log message content is treated as untrusted input (stored as TEXT).
  - No shell commands are derived from log content.
"""

from __future__ import annotations

import logging

from fastapi import APIRouter, Depends, Header, HTTPException, status
from sqlalchemy.orm import Session

from backend.app.core.config import get_settings
from backend.app.api.auth import require_bearer_token
from backend.app.core.database import get_db
from backend.app.schemas.logs import LogIngestRequest, LogIngestResponse
from backend.app.services.log_ingest import ingest_log_batch

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/logs", tags=["logs"])


# ---------------------------------------------------------------------------
# Authentication dependency
# ---------------------------------------------------------------------------


def _require_collector_auth(
    authorization: str = Header(
        default="",
        description="Bearer token for collector authentication.",
    )
) -> None:
    """
    Validate the ``Authorization: Bearer <token>`` header.

    Raises HTTP 403 if:
      - The header is absent or malformed.
      - The token does not match the configured ``COLLECTOR_API_KEY``.

    The actual key value is NEVER logged or included in error messages.
    """
    settings = get_settings()
    require_bearer_token(authorization, settings.COLLECTOR_API_KEY, settings.ENVIRONMENT)


# ---------------------------------------------------------------------------
# Ingest endpoint
# ---------------------------------------------------------------------------


@router.post(
    "/ingest",
    response_model=LogIngestResponse,
    status_code=status.HTTP_200_OK,
    summary="Ingest a batch of log events",
    description=(
        "Accepts a batch of structured log events collected by the "
        "Phase 5 OpsTrace log collector.  Events are persisted to the "
        "Phase 2 ``logs`` database table via the existing ``Log`` model. "
        "Requires a valid ``Authorization: Bearer <token>`` header matching "
        "the configured ``COLLECTOR_API_KEY``."
    ),
    dependencies=[Depends(_require_collector_auth)],
)
def ingest_logs(
    request: LogIngestRequest,
    db: Session = Depends(get_db),
) -> LogIngestResponse:
    """
    POST /api/v1/logs/ingest

    Persist a batch of collected log events.

    - An empty ``events`` list is accepted (returns ``accepted=0``).
    - Individual event failures are counted in ``rejected`` without
      aborting the rest of the batch.
    - Collection errors reported by the collector are logged for
      operator visibility but do not affect the HTTP response status.
    """
    if request.collection_errors:
        logger.warning(
            "Collector reported %d collection error(s) in this log batch: %s",
            len(request.collection_errors),
            "Collection error details omitted.",
        )

    result = ingest_log_batch(db=db, request=request)

    logger.debug(
        "Log ingest complete: accepted=%d rejected=%d",
        result.accepted,
        result.rejected,
    )

    return result

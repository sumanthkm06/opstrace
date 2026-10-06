"""
OpsTrace API v1 — Change-Aware Correlation Router
Phase 9: Change-Aware Correlation

Exposes REST API endpoints for change correlation:
  - POST /api/v1/incidents/{incident_id}/correlate-changes
  - GET /api/v1/incidents/{incident_id}/correlated-changes
"""

from __future__ import annotations

import logging
import uuid
from typing import Any, Dict

from fastapi import APIRouter, Depends, Header, HTTPException, status
from sqlalchemy.orm import Session

from backend.app.core.config import get_settings
from backend.app.api.auth import require_bearer_token
from backend.app.core.database import get_db
from backend.app.engines.correlation_engine import ChangeCorrelationEngine
from backend.app.schemas.correlation import (
    CorrelateIncidentRequest,
    IncidentCorrelationSummaryResponse,
)

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/incidents", tags=["correlation"])


def _require_collector_auth(
    authorization: str = Header(
        default="",
        description="Bearer token for API authorization.",
    )
) -> None:
    """Validate bearer token if configured."""
    settings = get_settings()
    require_bearer_token(authorization, settings.COLLECTOR_API_KEY, settings.ENVIRONMENT)


def _require_admin_auth(
    authorization: str = Header(default="", description="Bearer token for operator actions."),
) -> None:
    settings = get_settings()
    require_bearer_token(authorization, settings.ADMIN_API_KEY, settings.ENVIRONMENT)


@router.post(
    "/{incident_id}/correlate-changes",
    status_code=status.HTTP_200_OK,
    summary="Trigger change correlation for an incident",
    description=(
        "Evaluates PostgreSQL deployments and configuration changes within a lookback window "
        "against the specified incident, linking suspect changes and updating correlation metadata. "
        "Requires the configured operator/admin bearer key."
    ),
    dependencies=[Depends(_require_admin_auth)],
)
def correlate_incident_changes(
    incident_id: uuid.UUID,
    payload: CorrelateIncidentRequest = CorrelateIncidentRequest(),
    db: Session = Depends(get_db),
) -> Dict[str, Any]:
    """
    POST /api/v1/incidents/{incident_id}/correlate-changes
    """
    engine = ChangeCorrelationEngine(
        lookback_minutes=payload.lookback_minutes,
        min_score_threshold=payload.min_score_threshold,
    )

    try:
        result = engine.correlate_and_persist_incident(
            db=db,
            incident_id=incident_id,
            lookback_minutes=payload.lookback_minutes,
        )
    except Exception as exc:
        logger.error(
            "Change correlation failed for incident %s (%s).",
            incident_id,
            type(exc).__name__,
        )
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Change correlation failed.",
        )

    if not result:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Incident with ID '{incident_id}' not found.",
        )

    return result.model_dump(mode="json")


@router.get(
    "/{incident_id}/correlated-changes",
    status_code=status.HTTP_200_OK,
    summary="Get change correlation summary for an incident",
    description="Retrieves the correlated suspect deployment, config change, and attribution details.",
    dependencies=[Depends(_require_collector_auth)],
)
def get_incident_correlated_changes(
    incident_id: uuid.UUID,
    db: Session = Depends(get_db),
) -> Dict[str, Any]:
    """
    GET /api/v1/incidents/{incident_id}/correlated-changes
    """
    engine = ChangeCorrelationEngine()
    summary = engine.get_incident_correlation_summary(db=db, incident_id=incident_id)

    if not summary:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Incident with ID '{incident_id}' not found.",
        )

    return summary

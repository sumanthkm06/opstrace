"""
OpsTrace API v1 — Incident Timeline & Replay Router
Phase 10: Incident Timeline & Replay

Exposes REST API endpoints for incident timeline reconstruction and replay:
  - GET /api/v1/incidents/{incident_id}/timeline
  - GET /api/v1/incidents/{incident_id}/replay
  - GET /api/v1/incidents/{incident_id}/timeline/summary
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
from backend.app.engines.timeline_engine import TimelineEngine

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/incidents", tags=["timeline"])


def _require_collector_auth(
    authorization: str = Header(
        default="",
        description="Bearer token for API authorization.",
    )
) -> None:
    """Validate bearer token if configured."""
    settings = get_settings()
    require_bearer_token(authorization, settings.COLLECTOR_API_KEY, settings.ENVIRONMENT)


@router.get(
    "/{incident_id}/timeline",
    status_code=status.HTTP_200_OK,
    summary="Get complete incident chronological timeline",
    description="Reconstructs the full chronological event lifecycle of an incident.",
    dependencies=[Depends(_require_collector_auth)],
)
def get_incident_timeline(
    incident_id: uuid.UUID,
    db: Session = Depends(get_db),
) -> Dict[str, Any]:
    """
    GET /api/v1/incidents/{incident_id}/timeline
    """
    engine = TimelineEngine()
    timeline = engine.build_timeline(db=db, incident_id=incident_id)

    if not timeline:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Incident with ID '{incident_id}' not found.",
        )

    return timeline.model_dump(mode="json")


@router.get(
    "/{incident_id}/replay",
    status_code=status.HTTP_200_OK,
    summary="Replay incident observed lifecycle deterministically",
    description="Returns step-by-step reconstructed snapshots of an incident's observed state. Strictly read-only.",
    dependencies=[Depends(_require_collector_auth)],
)
def replay_incident(
    incident_id: uuid.UUID,
    db: Session = Depends(get_db),
) -> Dict[str, Any]:
    """
    GET /api/v1/incidents/{incident_id}/replay
    """
    engine = TimelineEngine()
    replay = engine.replay_incident(db=db, incident_id=incident_id)

    if not replay:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Incident with ID '{incident_id}' not found.",
        )

    return replay.model_dump(mode="json")


@router.get(
    "/{incident_id}/timeline/summary",
    status_code=status.HTTP_200_OK,
    summary="Get compact timeline summary for an incident",
    description="Returns duration, severity transitions, total events, and candidate change correlation summary.",
    dependencies=[Depends(_require_collector_auth)],
)
def get_incident_timeline_summary(
    incident_id: uuid.UUID,
    db: Session = Depends(get_db),
) -> Dict[str, Any]:
    """
    GET /api/v1/incidents/{incident_id}/timeline/summary
    """
    engine = TimelineEngine()
    summary = engine.get_timeline_summary(db=db, incident_id=incident_id)

    if not summary:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Incident with ID '{incident_id}' not found.",
        )

    return summary.model_dump(mode="json")

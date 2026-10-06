"""Collector telemetry ingestion and Prometheus scrape endpoint."""

import logging

from fastapi import APIRouter, Depends, Header, HTTPException, Response, status
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session

from backend.app.core.config import get_settings
from backend.app.api.auth import require_bearer_token
from backend.app.core.database import get_db
from backend.app.observability.prometheus import (
    prometheus_payload,
    record_telemetry,
    refresh_incident_counts,
)
from backend.app.schemas.telemetry import TelemetryIngestResponse
from backend.app.services.telemetry_ingest import ingest_telemetry
from collector.app.collectors.models import TelemetryPayload

router = APIRouter(prefix="/telemetry", tags=["telemetry"])
metrics_router = APIRouter(tags=["metrics"])
logger = logging.getLogger(__name__)


def _require_collector_auth(authorization: str = Header(default="")) -> None:
    settings = get_settings()
    require_bearer_token(authorization, settings.COLLECTOR_API_KEY, settings.ENVIRONMENT)


@router.post("", response_model=TelemetryIngestResponse,
             dependencies=[Depends(_require_collector_auth)],
             summary="Ingest a collector telemetry snapshot")
def receive_telemetry(payload: TelemetryPayload, db: Session = Depends(get_db)) -> TelemetryIngestResponse:
    if payload.host is None:
        raise HTTPException(status_code=422, detail="Telemetry must include host identification.")
    try:
        host, metric_count, service_count = ingest_telemetry(db, payload)
    except Exception:
        db.rollback()
        raise
    record_telemetry(payload)
    return TelemetryIngestResponse(
        accepted=True, host_id=str(host.id), metrics_recorded=metric_count,
        services_updated=service_count, collected_at=payload.collected_at,
    )


@metrics_router.get("/metrics", include_in_schema=False)
def scrape_metrics(db: Session = Depends(get_db)) -> Response:
    if not get_settings().PROMETHEUS_METRICS_ENABLED:
        raise HTTPException(status_code=404, detail="Prometheus metrics are disabled.")
    try:
        refresh_incident_counts(db)
    except SQLAlchemyError:
        logger.warning("Could not refresh incident metrics from the database.", exc_info=True)
    return Response(content=prometheus_payload(), media_type="text/plain; version=0.0.4; charset=utf-8")

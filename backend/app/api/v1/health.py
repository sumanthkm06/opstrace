"""
OpsTrace API v1 Health Check Router
Phase 3: FastAPI Backend Foundation

Handles GET /api/v1/health — a readiness probe that includes a
lightweight, read-only database connectivity check.
"""

from datetime import datetime, timezone

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from backend.app.core.config import get_settings
from backend.app.core.database import check_database_connection, get_db
from backend.app.schemas.health import APIHealthResponse, DatabaseHealthStatus

router = APIRouter(tags=["health"])

# Keep in sync with the root health router
APP_VERSION = "0.3.0"


@router.get(
    "/health",
    response_model=APIHealthResponse,
    summary="API v1 readiness probe",
    description=(
        "Returns extended health status including a lightweight, read-only "
        "database connectivity check. A degraded status is returned when the "
        "database is unreachable; the HTTP status code remains 200 so upstream "
        "monitors can distinguish process failures (no response) from DB issues."
    ),
)
def api_health_check(db: Session = Depends(get_db)) -> APIHealthResponse:
    """
    GET /api/v1/health

    Readiness endpoint. Performs a 'SELECT 1' ping against the configured
    database to confirm connectivity. Returns 200 in all cases; the 'status'
    field communicates the degraded state so callers can alert appropriately
    without treating a DB hiccup as a full service outage.
    """
    settings = get_settings()

    db_ok = check_database_connection()
    db_status = DatabaseHealthStatus(
        connected=db_ok,
        message="Database connection successful" if db_ok else "Database unreachable",
    )

    overall_status = "ok" if db_ok else "degraded"

    return APIHealthResponse(
        status=overall_status,
        service="opstrace-backend",
        version=APP_VERSION,
        environment=settings.ENVIRONMENT,
        api_version="v1",
        database=db_status,
        timestamp=datetime.now(tz=timezone.utc),
    )

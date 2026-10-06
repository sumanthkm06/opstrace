"""
OpsTrace Health Check Router — Root Level
Phase 3: FastAPI Backend Foundation

Handles GET /health — a simple liveness probe that does NOT require
a database connection. Suitable for load balancer health checks.
"""

from datetime import datetime, timezone

from fastapi import APIRouter

from backend.app.core.config import get_settings
from backend.app.schemas.health import HealthResponse

router = APIRouter(tags=["health"])

# Application version — sourced from config/env in future phases
APP_VERSION = "0.3.0"


@router.get(
    "/health",
    response_model=HealthResponse,
    summary="Application liveness probe",
    description=(
        "Returns a simple JSON health status confirming the application process "
        "is running. Does not check database connectivity. Suitable for load "
        "balancer liveness probes."
    ),
)
def health_check() -> HealthResponse:
    """
    GET /health

    Lightweight liveness endpoint. Always returns 200 if the process is up.
    No database I/O is performed.
    """
    settings = get_settings()
    return HealthResponse(
        status="ok",
        service="opstrace-backend",
        version=APP_VERSION,
        environment=settings.ENVIRONMENT,
        timestamp=datetime.now(tz=timezone.utc),
    )

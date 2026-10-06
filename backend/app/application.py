"""
OpsTrace FastAPI Application Factory
Phase 3: FastAPI Backend Foundation

Creates and configures the FastAPI application instance.
All middleware, exception handlers, and router registrations happen here.
The database layer and configuration are reused from Phase 2 — nothing
in this module duplicates or replaces core/ or models/.
"""

import logging
from contextlib import asynccontextmanager
from typing import AsyncGenerator

from fastapi import FastAPI, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from backend.app.api.health import router as root_health_router
from backend.app.api.v1.router import api_v1_router
from backend.app.api.v1.telemetry import metrics_router
from backend.app.core.config import get_settings

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Application metadata
# ---------------------------------------------------------------------------
APP_TITLE = "OpsTrace"
APP_DESCRIPTION = (
    "OpsTrace — Infrastructure Monitoring & Automated Remediation Platform.\n\n"
    "Phase 3 API foundation: health probes and versioned /api/v1/ structure.\n"
    "Full host, metric, log, incident, and remediation endpoints arrive in "
    "subsequent phases."
)
APP_VERSION = "0.3.0"
APP_CONTACT = {
    "name": "OpsTrace Engineering",
    "url": "https://github.com/opstrace/opstrace",
}
APP_LICENSE = {"name": "MIT"}


# ---------------------------------------------------------------------------
# Application lifespan (startup / shutdown hooks)
# ---------------------------------------------------------------------------

@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
    """
    Async context manager for application startup and shutdown lifecycle.

    Startup:
      - Validates application settings are loadable.
      - Logs the environment and version.

    Shutdown:
      - Currently a no-op; connection pool cleanup is handled by SQLAlchemy.
    """
    settings = get_settings()
    logger.info(
        "OpsTrace backend starting — env=%s version=%s",
        settings.ENVIRONMENT,
        APP_VERSION,
    )
    yield
    logger.info("OpsTrace backend shutting down")


# ---------------------------------------------------------------------------
# Application factory
# ---------------------------------------------------------------------------

def create_app() -> FastAPI:
    """
    Factory function that builds and returns the configured FastAPI application.

    Using a factory instead of a module-level instance makes the application
    easily testable (each test can call create_app() for a fresh instance)
    and avoids circular import issues.
    """
    settings = get_settings()

    app = FastAPI(
        title=APP_TITLE,
        description=APP_DESCRIPTION,
        version=APP_VERSION,
        contact=APP_CONTACT,
        license_info=APP_LICENSE,
        # OpenAPI endpoints — FastAPI enables these by default
        docs_url="/docs",
        redoc_url="/redoc",
        openapi_url="/openapi.json",
        lifespan=lifespan,
    )

    # ------------------------------------------------------------------
    # Middleware
    # ------------------------------------------------------------------

    # Same-origin Nginx does not need CORS. Explicit local origins support the
    # Vite development server; set CORS_ALLOWED_ORIGINS for other deployments.
    allowed_origins = [
        origin.strip()
        for origin in settings.CORS_ALLOWED_ORIGINS.split(",")
        if origin.strip()
    ]

    app.add_middleware(
        CORSMiddleware,
        allow_origins=allowed_origins,
        allow_credentials=False,   # credentials=True requires explicit origins
        allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
        allow_headers=["Content-Type", "Authorization", "Accept"],
    )

    # ------------------------------------------------------------------
    # Exception handlers
    # ------------------------------------------------------------------

    @app.exception_handler(Exception)
    async def unhandled_exception_handler(
        request: Request, exc: Exception
    ) -> JSONResponse:
        """
        Catch-all handler for unhandled exceptions.
        Returns a clean JSON 500 response instead of a raw stack trace.
        """
        logger.error(
            "Unhandled exception on %s %s (%s).",
            request.method,
            request.url.path,
            type(exc).__name__,
        )
        return JSONResponse(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            content={
                "detail": "An unexpected internal error occurred.",
                "type": "internal_server_error",
            },
        )

    # ------------------------------------------------------------------
    # Router registration
    # ------------------------------------------------------------------

    # Root-level health probe (no /api/v1 prefix)
    app.include_router(root_health_router)

    # Versioned API router — all Phase 3+ domain routes live under /api/v1
    app.include_router(api_v1_router)

    if settings.PROMETHEUS_METRICS_ENABLED:
        app.include_router(metrics_router)

    return app

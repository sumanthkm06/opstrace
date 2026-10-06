"""
OpsTrace API v1 Router Registry
Phase 6: Log Analysis & Intelligence
(extends Phase 5: Log Collection and Ingestion)
(extends Phase 3: FastAPI Backend Foundation)

Central registration point for all /api/v1/* routers.
Future phases add their routers here without touching main.py.
"""

from fastapi import APIRouter

from backend.app.api.v1 import health
from backend.app.api.v1 import logs         # Phase 5: log ingestion
from backend.app.api.v1 import analysis     # Phase 6: log analysis
from backend.app.api.v1 import correlation  # Phase 9: change-aware correlation
from backend.app.api.v1 import timeline     # Phase 10: incident timeline & replay
from backend.app.api.v1 import dependency   # Phase 11: dependency & impact analysis
from backend.app.api.v1 import resources    # Phase 12: dashboard resource endpoints
from backend.app.api.v1 import telemetry   # Phase 13: collector metrics
from backend.app.api.v1 import simulations  # Phase 19: controlled failure fixtures

# Main v1 router — all sub-routers are included here
api_v1_router = APIRouter(prefix="/api/v1")

# Phase 3: health check
api_v1_router.include_router(health.router)

# Phase 5: log ingestion
api_v1_router.include_router(logs.router)

# Phase 6: log analysis (GET /api/v1/logs/analyze)
api_v1_router.include_router(analysis.router)

# Phase 9: change correlation
api_v1_router.include_router(correlation.router)

# Phase 10: timeline & replay
api_v1_router.include_router(timeline.router)

# Phase 11: dependency impact analysis
api_v1_router.include_router(dependency.router)

# Phase 12: dashboard resources (hosts, services, incidents, remediations)
api_v1_router.include_router(resources.router)

# Phase 13: collector telemetry ingestion
api_v1_router.include_router(telemetry.router)

# Phase 19: fixture-only controlled failure simulation
api_v1_router.include_router(simulations.router)




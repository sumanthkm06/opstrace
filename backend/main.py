"""
OpsTrace Backend Application Entrypoint
Phase 3: FastAPI Backend Foundation

This module is the canonical entry point for the OpsTrace backend server.

Running the server:
    # From the repository root:
    uvicorn backend.main:app --host 0.0.0.0 --port 8000 --reload

    # Or via Python:
    python -m backend.main

The FastAPI application instance ('app') is created by the application
factory in backend.app.application so it can be independently tested
without starting the server.
"""

import logging
import sys
from pathlib import Path

# Ensure the repository root is on sys.path when this file is run directly,
# e.g. via 'python backend/main.py'.  When launched through uvicorn from the
# repo root, Python already resolves 'backend.*' imports correctly.
_REPO_ROOT = Path(__file__).resolve().parent.parent
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from backend.app.application import create_app  # noqa: E402
from backend.app.core.config import get_settings  # noqa: E402

# ---------------------------------------------------------------------------
# Build the application instance that ASGI servers (uvicorn / gunicorn) bind.
# ---------------------------------------------------------------------------
app = create_app()

# ---------------------------------------------------------------------------
# Developer convenience: run via 'python backend/main.py'
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    import uvicorn

    settings = get_settings()
    logging.basicConfig(
        level=getattr(logging, settings.LOG_LEVEL.upper(), logging.INFO),
        format="%(asctime)s %(levelname)-8s %(name)s — %(message)s",
    )
    uvicorn.run(
        "backend.main:app",
        host=settings.BACKEND_HOST,
        port=settings.BACKEND_PORT,
        reload=settings.ENVIRONMENT == "development",
        log_level=settings.LOG_LEVEL.lower(),
    )

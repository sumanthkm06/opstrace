"""Controlled, dry-run failure simulation API."""
from fastapi import APIRouter, Depends, Header

from backend.app.api.auth import require_bearer_token
from backend.app.core.config import get_settings
from backend.app.services.failure_simulation import FailureSimulator, SimulationRequest, SimulationResult

router = APIRouter(prefix="/simulations", tags=["simulations"])


def _require_admin_auth(authorization: str = Header(default="")) -> None:
    settings = get_settings()
    require_bearer_token(authorization, settings.ADMIN_API_KEY, settings.ENVIRONMENT)


@router.post("/failures", response_model=SimulationResult, summary="Run a safe failure simulation",
             dependencies=[Depends(_require_admin_auth)])
def simulate_failure(payload: SimulationRequest) -> SimulationResult:
    """Run one predefined synthetic scenario; no live resources are accessed."""
    return FailureSimulator().run(payload)

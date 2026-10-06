"""
OpsTrace API v1 — Dependency and Impact Analysis
Phase 11
"""

import uuid
from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session

from backend.app.core.database import get_db
from backend.app.engines.dependency_engine import DependencyEngine
from backend.app.schemas.dependency import DependencyImpactAnalysis

router = APIRouter(prefix="/dependencies", tags=["Dependencies"])
engine = DependencyEngine()


@router.get("/service/{service_id}/impact", response_model=DependencyImpactAnalysis)
def analyze_service_impact(
    service_id: uuid.UUID,
    max_depth: int = Query(default=5, ge=1, le=10),
    db: Session = Depends(get_db)
) -> DependencyImpactAnalysis:
    """
    Perform a dependency and impact analysis for a specific service.
    Finds upstream root cause candidates and downstream blast radius.
    """
    try:
        return engine.analyze_impact(db=db, service_id=service_id, max_depth=max_depth)
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail="Internal server error during analysis")

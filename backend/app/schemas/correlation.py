"""
OpsTrace API Schemas — Change Correlation
Phase 9: Change-Aware Correlation

Pydantic schemas for request/response validation on change correlation API endpoints.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, ConfigDict, Field


class CorrelateIncidentRequest(BaseModel):
    """Request payload for triggering change correlation on an incident."""

    model_config = ConfigDict(extra="forbid")

    lookback_minutes: int = Field(
        default=60,
        ge=1,
        le=1440,
        description="Time window in minutes prior to incident detection to evaluate changes.",
    )
    min_score_threshold: float = Field(
        default=0.20,
        ge=0.0,
        le=1.0,
        description="Minimum score threshold for suspect attribution.",
    )


class SuspectDeploymentSummary(BaseModel):
    """Summary representation of a correlated deployment."""

    id: uuid.UUID
    version: str
    status: str
    deployed_by: str
    deployed_at: Optional[str] = None


class SuspectConfigChangeSummary(BaseModel):
    """Summary representation of a correlated configuration change."""

    id: uuid.UUID
    config_file_path: str
    change_type: str
    changed_by: str
    diff: Optional[str] = None
    changed_at: Optional[str] = None


class IncidentCorrelationSummaryResponse(BaseModel):
    """API response model for GET /api/v1/incidents/{incident_id}/correlated-changes."""

    incident_id: uuid.UUID
    incident_title: str
    detected_at: Optional[str] = None
    correlated_deployment: Optional[SuspectDeploymentSummary] = None
    correlated_config_change: Optional[SuspectConfigChangeSummary] = None
    correlation_details: Optional[Dict[str, Any]] = None
    causation_disclaimer: str = Field(
        default="Correlation indicates temporal/spatial proximity. Correlation does not prove causation."
    )
    correlation_does_not_prove_causation: bool = Field(default=True)

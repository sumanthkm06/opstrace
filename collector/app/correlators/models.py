"""
OpsTrace Collector — Phase 9 Change-Aware Correlation Models
Phase 9: Change-Aware Correlation

Pydantic models representing candidate software deployments and configuration alterations,
correlation scoring confidence levels, change correlation outputs, and batch results.

Key Design Principle:
  - Explainable & Deterministic: All scoring rules are transparent and rule-based.
  - Causation Disclaimer: Explicitly reinforces that correlation does not prove causation.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field


# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------


class ChangeCategory(str, Enum):
    """Categories of candidate system changes."""

    DEPLOYMENT = "deployment"
    CONFIG_CHANGE = "config_change"
    ENV_VAR_UPDATE = "env_var_update"
    PACKAGE_UPDATE = "package_update"
    SERVICE_RESTART = "service_restart"


class CorrelationConfidence(str, Enum):
    """Qualitative confidence level for change attribution."""

    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    UNLIKELY = "unlikely"

    @classmethod
    def from_score(cls, score: float) -> "CorrelationConfidence":
        """Map numerical score (0.0 to 1.0) to confidence level."""
        if score >= 0.75:
            return cls.HIGH
        elif score >= 0.45:
            return cls.MEDIUM
        elif score >= 0.20:
            return cls.LOW
        else:
            return cls.UNLIKELY


# ---------------------------------------------------------------------------
# Candidate Change Input Model
# ---------------------------------------------------------------------------


class CandidateChange(BaseModel):
    """
    Representation of a candidate software deployment or config change event
    being evaluated against an operational incident.
    """

    change_id: uuid.UUID = Field(default_factory=uuid.uuid4)
    change_type: ChangeCategory = Field(description="Category of the system change.")
    timestamp: datetime = Field(description="Time when the change occurred/was deployed.")
    service_id: Optional[uuid.UUID] = Field(
        default=None, description="Service UUID associated with change."
    )
    host_id: Optional[uuid.UUID] = Field(
        default=None, description="Host UUID where change occurred."
    )
    service_name: Optional[str] = Field(
        default=None, description="Human-readable service name."
    )
    summary: str = Field(description="Summary description of the change.")
    details: Dict[str, Any] = Field(
        default_factory=dict, description="Structured attributes (version, config path, etc.)."
    )
    diff: Optional[str] = Field(default=None, description="Textual diff or previous/new values.")
    changed_by: Optional[str] = Field(
        default=None, description="User or system actor who initiated the change."
    )

    model_config = {"frozen": False}


# ---------------------------------------------------------------------------
# Single Change Correlation Evaluation Model
# ---------------------------------------------------------------------------


class ChangeCorrelation(BaseModel):
    """Scored evaluation of a single candidate change against an incident."""

    candidate: CandidateChange = Field(description="The evaluated candidate change.")
    score: float = Field(
        ge=0.0,
        le=1.0,
        description="Deterministic correlation score between 0.0 and 1.0.",
    )
    confidence: CorrelationConfidence = Field(
        description="Qualitative confidence rating based on score."
    )
    reasons: List[str] = Field(
        default_factory=list,
        description="Deterministic, rule-based explanation list for why score was assigned.",
    )
    is_primary_suspect: bool = Field(
        default=False, description="True if candidate is top ranked suspect for incident."
    )

    model_config = {"frozen": False}


# ---------------------------------------------------------------------------
# Incident Change Correlation Output Model
# ---------------------------------------------------------------------------


class IncidentChangeCorrelation(BaseModel):
    """
    Complete change-aware correlation analysis for an operational incident.

    Disclaims causation explicitly to maintain statistical and diagnostic clarity:
    "Correlation does not prove causation."
    """

    incident_id: Optional[uuid.UUID] = Field(default=None)
    incident_title: str = Field(description="Title of evaluated incident.")
    detected_at: datetime = Field(description="Incident detection timestamp.")
    host_id: Optional[uuid.UUID] = Field(default=None)
    service_id: Optional[uuid.UUID] = Field(default=None)
    correlated_deployment_id: Optional[uuid.UUID] = Field(
        default=None, description="Top suspect deployment UUID (if any)."
    )
    correlated_config_change_id: Optional[uuid.UUID] = Field(
        default=None, description="Top suspect config change UUID (if any)."
    )
    primary_suspect: Optional[ChangeCorrelation] = Field(
        default=None, description="Highest-scoring candidate change."
    )
    secondary_suspects: List[ChangeCorrelation] = Field(
        default_factory=list, description="Other candidate changes within correlation window."
    )
    total_candidates_evaluated: int = Field(
        default=0, description="Total number of changes evaluated in time window."
    )
    correlation_window_minutes: int = Field(
        default=60, description="Lookback window used for evaluation in minutes."
    )
    causation_disclaimer: str = Field(
        default=(
            "Correlation indicates temporal and scope proximity of changes to an incident. "
            "Correlation does not prove causation."
        ),
        description="Explicit architecture guarantee for explainable diagnosis.",
    )
    correlation_does_not_prove_causation: bool = Field(
        default=True,
        description="Explicit flag affirming correlation != causation principle.",
    )
    correlated_at: datetime = Field(
        default_factory=lambda: datetime.now(tz=timezone.utc),
        description="Timestamp when correlation was computed.",
    )

    model_config = {"frozen": False}


# ---------------------------------------------------------------------------
# Batch Change Correlation Result Model
# ---------------------------------------------------------------------------


class ChangeCorrelationBatchResult(BaseModel):
    """Batch correlation results across multiple incidents."""

    processed_at: datetime = Field(
        default_factory=lambda: datetime.now(tz=timezone.utc)
    )
    correlations: List[IncidentChangeCorrelation] = Field(default_factory=list)
    total_incidents_processed: int = Field(default=0)
    total_correlated: int = Field(
        default=0, description="Count of incidents with at least one correlated suspect change."
    )
    warnings: List[str] = Field(default_factory=list)

    model_config = {"frozen": False}

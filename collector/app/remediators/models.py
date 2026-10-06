"""
OpsTrace Collector — Phase 8 Remediation Models
Phase 8: Remediation

Pydantic models representing remediation action types, statuses,
remediation plans, and remediation results.

Security:
  - Remediation actions are drawn exclusively from a closed allowlist.
  - No action string is ever derived from log messages, incident titles,
    or any user-controlled input.
  - Execution boundaries require explicit caller opt-in (dry_run=False).
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field


# ---------------------------------------------------------------------------
# Action Types (CLOSED ALLOWLIST — only add here, never from external input)
# ---------------------------------------------------------------------------


class RemediationActionType(str, Enum):
    """
    Explicit allowlist of safe remediation actions.

    IMPORTANT: New action types must be reviewed and added to this enum
    manually. Action strings from log messages, incident titles, or any
    external input must NEVER be used as action types.
    """

    RESTART_SERVICE = "restart_service"
    CLEAR_RETRY_OPERATION = "clear_retry_operation"
    SCALE_RECOVERY_RECOMMENDATION = "scale_recovery_recommendation"
    CONFIG_ROLLBACK_RECOMMENDATION = "config_rollback_recommendation"
    MANUAL_INVESTIGATION_REQUIRED = "manual_investigation_required"
    NO_ACTION = "no_action"


# ---------------------------------------------------------------------------
# Remediation Status
# ---------------------------------------------------------------------------


class RemediationStatus(str, Enum):
    """Lifecycle statuses for a remediation attempt."""

    PENDING = "pending"
    RUNNING = "running"
    SUCCESS = "success"
    FAILED = "failed"
    SKIPPED = "skipped"

    def to_db_status(self) -> str:
        """
        Map to a valid Phase 2 remediations.status constraint value.
        DB allowed values: pending_approval, approved, rejected, executed, failed.
        """
        _map: Dict["RemediationStatus", str] = {
            RemediationStatus.PENDING: "pending_approval",
            RemediationStatus.RUNNING: "approved",
            RemediationStatus.SUCCESS: "executed",
            RemediationStatus.FAILED: "failed",
            RemediationStatus.SKIPPED: "rejected",
        }
        return _map.get(self, "pending_approval")


# ---------------------------------------------------------------------------
# Remediation Plan
# ---------------------------------------------------------------------------


class RemediationPlan(BaseModel):
    """
    A proposed remediation action for a detected incident.
    Produced by RemediationEngine.plan() before any execution occurs.
    """

    plan_id: uuid.UUID = Field(default_factory=uuid.uuid4)
    incident_id: Optional[uuid.UUID] = Field(default=None)
    incident_title: str = Field(description="Human-readable title of the incident.")
    incident_type: str = Field(description="Machine incident type identifier.")
    action_type: RemediationActionType = Field(
        description="Selected remediation action from the allowlist."
    )
    description: str = Field(description="What this remediation will do.")
    rationale: str = Field(default="", description="Why this action was selected.")
    parameters: Dict[str, Any] = Field(
        default_factory=dict,
        description="Static pre-validated parameters — never from user input.",
    )
    dry_run: bool = Field(
        default=True,
        description="True=simulate only. False requires explicit caller opt-in.",
    )
    requested_at: datetime = Field(
        default_factory=lambda: datetime.now(tz=timezone.utc)
    )

    model_config = {"frozen": False}


# ---------------------------------------------------------------------------
# Remediation Result
# ---------------------------------------------------------------------------


class RemediationResult(BaseModel):
    """Outcome of a remediation execution or dry-run attempt."""

    plan_id: uuid.UUID = Field(description="Back-reference to the RemediationPlan.")
    incident_id: Optional[uuid.UUID] = Field(default=None)
    action_type: RemediationActionType = Field(
        description="The action that was (or would have been) taken."
    )
    status: RemediationStatus = Field(description="Final status of the remediation.")
    message: str = Field(default="")
    error: Optional[str] = Field(default=None)
    dry_run: bool = Field(default=True)
    executed_at: datetime = Field(
        default_factory=lambda: datetime.now(tz=timezone.utc)
    )
    output: Dict[str, Any] = Field(default_factory=dict)

    model_config = {"frozen": False}


# ---------------------------------------------------------------------------
# Audit Record
# ---------------------------------------------------------------------------


class RemediationAuditRecord(BaseModel):
    """
    Lightweight in-process audit record for a remediation decision.
    Maps to the Phase 2 AuditEvent ORM when a DB session is available.
    """

    audit_id: uuid.UUID = Field(default_factory=uuid.uuid4)
    action: str = Field(description="Audit action label.")
    actor: str = Field(default="system")
    resource_type: str = Field(default="remediation")
    resource_id: str = Field(description="String form of plan_id.")
    incident_id: Optional[uuid.UUID] = Field(default=None)
    details: Dict[str, Any] = Field(default_factory=dict)
    created_at: datetime = Field(
        default_factory=lambda: datetime.now(tz=timezone.utc)
    )

    model_config = {"frozen": False}


# ---------------------------------------------------------------------------
# Batch Result
# ---------------------------------------------------------------------------


class RemediationBatchResult(BaseModel):
    """Result of processing a full IncidentDetectionResult through the engine."""

    processed_at: datetime = Field(
        default_factory=lambda: datetime.now(tz=timezone.utc)
    )
    plans: List[RemediationPlan] = Field(default_factory=list)
    results: List[RemediationResult] = Field(default_factory=list)
    audit_records: List[RemediationAuditRecord] = Field(default_factory=list)
    total_incidents: int = Field(default=0)
    total_actioned: int = Field(default=0)
    total_skipped: int = Field(default=0)
    total_failed: int = Field(default=0)
    warnings: List[str] = Field(default_factory=list)

    model_config = {"frozen": False}

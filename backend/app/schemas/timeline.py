"""
OpsTrace API Schemas — Incident Timeline & Replay
Phase 10: Incident Timeline & Replay

Pydantic models representing chronological timeline events, timeline summaries,
and deterministic incident replay snapshots.

Key Rules:
  - Observation/Reconstruction: Timeline & replay reconstruct state from historical records.
  - Non-causal attribution: Correlation is never presented as proven causation.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


# ---------------------------------------------------------------------------
# Individual Timeline Event Model
# ---------------------------------------------------------------------------


class IncidentTimelineEvent(BaseModel):
    """A single chronological event in an incident lifecycle."""

    event_id: Optional[uuid.UUID] = Field(default=None, description="Event UUID if stored.")
    incident_id: uuid.UUID = Field(description="Associated incident UUID.")
    sequence: int = Field(default=1, ge=0, description="1-indexed chronological order info.")
    event_type: str = Field(description="Machine identifier for event type.")
    timestamp: datetime = Field(description="Timestamp when event occurred.")
    severity: Optional[str] = Field(default=None, description="Severity at time of event if applicable.")
    message: str = Field(description="Human-readable event description.")
    source: str = Field(
        default="incident_event",
        description="Origin source: incident_event, deployment, config_change, remediation, audit_event.",
    )
    metadata: Dict[str, Any] = Field(default_factory=dict, description="Structured attributes & payload.")

    model_config = {"frozen": False}


# ---------------------------------------------------------------------------
# Complete Incident Timeline Model
# ---------------------------------------------------------------------------


class IncidentTimeline(BaseModel):
    """Complete chronological timeline of an incident lifecycle."""

    incident_id: uuid.UUID = Field(description="Target incident UUID.")
    incident_title: str = Field(description="Incident title.")
    status: str = Field(description="Current incident status.")
    severity: str = Field(description="Current incident severity.")
    host_id: Optional[uuid.UUID] = Field(default=None)
    service_id: Optional[uuid.UUID] = Field(default=None)
    started_at: datetime = Field(description="Timestamp of earliest observed event or detection.")
    resolved_at: Optional[datetime] = Field(default=None, description="Timestamp of resolution if resolved.")
    duration_seconds: Optional[float] = Field(
        default=None, description="Total incident duration in seconds."
    )
    total_events: int = Field(default=0, description="Total number of events in timeline.")
    events: List[IncidentTimelineEvent] = Field(
        default_factory=list, description="Chronologically sorted timeline events."
    )
    summary: str = Field(description="Human-readable timeline overview.")
    causation_disclaimer: str = Field(
        default="Candidate contributing changes indicate temporal/scope proximity. Correlation does not prove causation.",
        description="Non-causal attribution guarantee.",
    )

    model_config = {"frozen": False}


# ---------------------------------------------------------------------------
# Incident Replay Snapshot Model
# ---------------------------------------------------------------------------


class IncidentReplaySnapshot(BaseModel):
    """State of an incident reconstructed at a specific step in its lifecycle."""

    step: int = Field(ge=1, description="Step number in replay execution sequence.")
    incident_id: uuid.UUID = Field(description="Target incident UUID.")
    replay_timestamp: datetime = Field(description="Timestamp of current replay event.")
    event_type: str = Field(description="Type of event at this step.")
    event_description: str = Field(description="Summary description of event at this step.")
    observed_severity: str = Field(description="Reconstructed severity level after this event.")
    observed_status: str = Field(description="Reconstructed incident status after this event.")
    correlated_changes_known: List[Dict[str, Any]] = Field(
        default_factory=list, description="Candidate changes identified up to this point."
    )
    remediations_known: List[Dict[str, Any]] = Field(
        default_factory=list, description="Remediation plans/results known up to this point."
    )
    state_summary: str = Field(description="Summary of reconstructed state at this step.")
    is_reconstructed_state: bool = Field(
        default=True,
        description="Explicit indication that this is reconstructed state, not a historical DB snapshot.",
    )

    model_config = {"frozen": False}


# ---------------------------------------------------------------------------
# Incident Replay Result Model
# ---------------------------------------------------------------------------


class IncidentReplayResult(BaseModel):
    """Complete deterministic replay of an incident lifecycle."""

    incident_id: uuid.UUID = Field(description="Target incident UUID.")
    total_steps: int = Field(default=0, description="Total number of replay steps.")
    snapshots: List[IncidentReplaySnapshot] = Field(
        default_factory=list, description="Chronological sequence of reconstructed state snapshots."
    )
    final_status: str = Field(description="Final reconstructed status.")
    final_severity: str = Field(description="Final reconstructed severity.")
    reconstructed_at: datetime = Field(
        default_factory=lambda: datetime.now(tz=timezone.utc),
        description="Timestamp when replay was generated.",
    )
    causation_disclaimer: str = Field(
        default="Replay reconstructs observed timeline events. Correlation does not prove causation.",
    )

    model_config = {"frozen": False}


# ---------------------------------------------------------------------------
# Incident Timeline Summary Model
# ---------------------------------------------------------------------------


class IncidentTimelineSummary(BaseModel):
    """Compact structured summary of an incident timeline."""

    incident_id: uuid.UUID
    incident_type: str
    current_status: str
    current_severity: str
    first_observed_at: datetime
    last_observed_at: datetime
    duration_seconds: float
    total_events: int
    severity_transitions: List[Dict[str, Any]] = Field(
        default_factory=list, description="Sequence of severity escalation/de-escalation transitions."
    )
    candidate_contributing_changes: List[Dict[str, Any]] = Field(
        default_factory=list,
        description="Correlated candidate changes from Phase 9 (never presented as proven cause).",
    )
    remediation_summary: List[Dict[str, Any]] = Field(
        default_factory=list, description="Phase 8 remediation actions and outcomes."
    )
    final_state: str = Field(description="Final state summary.")
    causation_disclaimer: str = Field(
        default="Candidate contributing changes indicate temporal/scope proximity. Correlation does not prove causation.",
    )

    model_config = {"frozen": False}

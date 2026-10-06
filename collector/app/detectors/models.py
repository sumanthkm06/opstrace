"""
OpsTrace Collector — Phase 7 Incident Detection Models
Phase 7: Incident Detection & Incident Correlation

Pydantic models representing detected incidents, evidence, detection rules configuration,
and detection outputs.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field


class IncidentSeverity(str, Enum):
    """
    Incident severity classification level.

    Values:
        INFO: Informational severity level.
        WARNING: Warning severity level.
        ERROR: Error severity level.
        CRITICAL: Critical severity level.
    """

    INFO = "INFO"
    WARNING = "WARNING"
    ERROR = "ERROR"
    CRITICAL = "CRITICAL"

    def to_db_severity(self) -> str:
        """
        Map to the Phase 2 PostgreSQL check constraint value on ``incidents.severity``.
        Allowed values in DB: 'critical', 'high', 'medium', 'low'.
        """
        mapping = {
            IncidentSeverity.CRITICAL: "critical",
            IncidentSeverity.ERROR: "high",
            IncidentSeverity.WARNING: "medium",
            IncidentSeverity.INFO: "low",
        }
        return mapping.get(self, "medium")

    @classmethod
    def from_db_severity(cls, db_severity: str) -> IncidentSeverity:
        """Map DB severity string ('critical', 'high', 'medium', 'low') back to Enum."""
        sev_lower = (db_severity or "").strip().lower()
        mapping = {
            "critical": cls.CRITICAL,
            "high": cls.ERROR,
            "medium": cls.WARNING,
            "low": cls.INFO,
        }
        return mapping.get(sev_lower, cls.WARNING)

    @property
    def rank(self) -> int:
        """Numeric rank for severity comparison (higher = more severe)."""
        ranks = {
            IncidentSeverity.INFO: 1,
            IncidentSeverity.WARNING: 2,
            IncidentSeverity.ERROR: 3,
            IncidentSeverity.CRITICAL: 4,
        }
        return ranks.get(self, 2)


class IncidentType(str, Enum):
    """Types of incidents detected by OpsTrace detection rules."""

    HIGH_ERROR_RATE = "HIGH_ERROR_RATE"
    REPEATED_CRITICAL_ERRORS = "REPEATED_CRITICAL_ERRORS"
    REPEATED_FINGERPRINT = "REPEATED_FINGERPRINT"
    SERVICE_FAILURE = "SERVICE_FAILURE"
    MULTIPLE_RELATED_ERRORS = "MULTIPLE_RELATED_ERRORS"
    CUSTOM_RULE = "CUSTOM_RULE"


class IncidentEvidence(BaseModel):
    """Evidence or supporting event details attached to an incident."""

    event_type: str = Field(
        default="log_event",
        description="Category of evidence (e.g. log_group, error_rate_exceeded, service_failure_match).",
    )
    timestamp: Optional[datetime] = Field(
        default=None,
        description="Timestamp when the evidence event occurred.",
    )
    message: str = Field(
        default="",
        description="Evidence message snippet or descriptive text.",
    )
    fingerprint: Optional[str] = Field(
        default=None,
        description="Log fingerprint string if applicable.",
    )
    source: Optional[str] = Field(
        default=None,
        description="Log source or component identifier.",
    )
    details: Dict[str, Any] = Field(
        default_factory=dict,
        description="Arbitrary structured metadata context.",
    )

    model_config = {"frozen": False}


class DetectedIncident(BaseModel):
    """
    Representation of a detected operational incident produced by Phase 7.
    """

    incident_id: Optional[uuid.UUID] = Field(
        default=None,
        description="Optional unique identifier assigned to this incident.",
    )
    incident_type: str = Field(
        default=IncidentType.SERVICE_FAILURE.value,
        description="Identifier of the rule or condition that triggered this incident.",
    )
    title: str = Field(
        description="Human-readable title describing the incident.",
    )
    description: str = Field(
        default="",
        description="Detailed description or summary of contributing factors.",
    )
    severity: IncidentSeverity = Field(
        default=IncidentSeverity.WARNING,
        description="Severity level (INFO, WARNING, ERROR, CRITICAL).",
    )
    status: str = Field(
        default="open",
        description="Incident lifecycle status (open, investigating, mitigated, resolved, closed).",
    )
    first_seen: Optional[datetime] = Field(
        default=None,
        description="Earliest timestamp associated with contributing events.",
    )
    last_seen: Optional[datetime] = Field(
        default=None,
        description="Most recent timestamp associated with contributing events.",
    )
    host_name: Optional[str] = Field(
        default=None,
        description="Hostname of the affected infrastructure node.",
    )
    host_id: Optional[uuid.UUID] = Field(
        default=None,
        description="Database UUID of the affected Host entity.",
    )
    service_name: Optional[str] = Field(
        default=None,
        description="Name of the affected service if identifiable.",
    )
    service_id: Optional[uuid.UUID] = Field(
        default=None,
        description="Database UUID of the affected Service entity.",
    )
    related_fingerprints: List[str] = Field(
        default_factory=list,
        description="List of log fingerprints correlated with this incident.",
    )
    evidence: List[IncidentEvidence] = Field(
        default_factory=list,
        description="List of evidence items supporting this incident.",
    )
    metadata: Dict[str, Any] = Field(
        default_factory=dict,
        description="Additional structured context (counts, rules triggered, etc.).",
    )

    model_config = {"frozen": False}

    @property
    def db_severity(self) -> str:
        """Map to DB check constraint string ('critical', 'high', 'medium', 'low')."""
        return self.severity.to_db_severity()

    def merge(self, other: DetectedIncident) -> DetectedIncident:
        """
        Merge another detected incident into this one (correlation).
        Updates timestamps, escalates severity, merges fingerprints and evidence.
        """
        # Escalate severity to highest of both
        if other.severity.rank > self.severity.rank:
            self.severity = other.severity

        # Earliest first_seen
        if other.first_seen and (not self.first_seen or other.first_seen < self.first_seen):
            self.first_seen = other.first_seen

        # Latest last_seen
        if other.last_seen and (not self.last_seen or other.last_seen > self.last_seen):
            self.last_seen = other.last_seen

        # Merge fingerprints preserving order and uniqueness
        fp_set = set(self.related_fingerprints)
        for fp in other.related_fingerprints:
            if fp and fp not in fp_set:
                self.related_fingerprints.append(fp)
                fp_set.add(fp)

        # Merge evidence
        self.evidence.extend(other.evidence)

        # Merge metadata
        for k, v in other.metadata.items():
            if k not in self.metadata:
                self.metadata[k] = v

        return self


class DetectionRuleConfig(BaseModel):
    """
    Configurable parameters and thresholds for Phase 7 incident detection rules.
    """

    error_rate_warning_threshold: float = Field(
        default=10.0,
        description="Errors per minute threshold for WARNING severity high error rate incident.",
    )
    error_rate_error_threshold: float = Field(
        default=30.0,
        description="Errors per minute threshold for ERROR severity high error rate incident.",
    )
    error_rate_critical_threshold: float = Field(
        default=60.0,
        description="Errors per minute threshold for CRITICAL severity high error rate incident.",
    )
    repeated_fingerprint_threshold: int = Field(
        default=3,
        description="Minimum occurrences of identical fingerprint to trigger repeated fingerprint incident.",
    )
    critical_error_threshold: int = Field(
        default=1,
        description="Minimum critical log count to trigger a critical error incident.",
    )
    multiple_errors_threshold: int = Field(
        default=3,
        description="Minimum number of unique error fingerprints occurring together to trigger correlation incident.",
    )
    service_failure_keywords: List[str] = Field(
        default_factory=lambda: [
            "service unavailable",
            "connection refused",
            "failed to connect",
            "service down",
            "fatal crash",
            "out of memory",
            "oom-killer",
            "database connection failed",
            "connection failed",
            "critical failure",
            "unhandled exception",
        ],
        description="Case-insensitive keyword substrings indicating service failure or component unavailability.",
    )
    correlation_window_seconds: float = Field(
        default=300.0,
        description="Time window in seconds for correlating related events into a single active incident.",
    )

    model_config = {"frozen": False}


class IncidentDetectionResult(BaseModel):
    """Structured output of a Phase 7 incident detection run."""

    detected_at: datetime = Field(
        default_factory=lambda: datetime.now(tz=timezone.utc),
        description="UTC timestamp when incident detection was executed.",
    )
    incidents: List[DetectedIncident] = Field(
        default_factory=list,
        description="List of detected incidents.",
    )
    total_incidents_detected: int = Field(
        default=0,
        description="Number of incidents detected in this run.",
    )
    total_rules_evaluated: int = Field(
        default=0,
        description="Number of detection rules evaluated.",
    )
    detection_warnings: List[str] = Field(
        default_factory=list,
        description="Non-fatal warning messages encountered during detection.",
    )
    detection_errors: List[str] = Field(
        default_factory=list,
        description="Non-fatal error messages encountered during detection.",
    )

    model_config = {"frozen": False}

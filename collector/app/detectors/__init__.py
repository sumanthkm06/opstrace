"""
OpsTrace Incident Detection & Correlation Package
Phase 7: Incident Detection & Incident Correlation
"""

from collector.app.detectors.models import (
    DetectionRuleConfig,
    DetectedIncident,
    IncidentDetectionResult,
    IncidentEvidence,
    IncidentSeverity,
    IncidentType,
)
from collector.app.detectors.incident_detector import IncidentDetector
from collector.app.detectors.rules import (
    BaseDetectionRule,
    CriticalErrorRule,
    HighErrorRateRule,
    MultipleRelatedErrorsRule,
    RepeatedFingerprintRule,
    ServiceFailureRule,
)

__all__ = [
    "IncidentSeverity",
    "IncidentType",
    "IncidentEvidence",
    "DetectedIncident",
    "DetectionRuleConfig",
    "IncidentDetectionResult",
    "BaseDetectionRule",
    "ServiceFailureRule",
    "HighErrorRateRule",
    "RepeatedFingerprintRule",
    "CriticalErrorRule",
    "MultipleRelatedErrorsRule",
    "IncidentDetector",
]

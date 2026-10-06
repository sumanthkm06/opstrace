"""
OpsTrace Change-Aware Correlation Package
Phase 9: Change-Aware Correlation

Exports models and correlation engines for evaluating software deployments
and configuration alterations against operational incidents.
"""

from collector.app.correlators.change_correlator import ChangeCorrelator
from collector.app.correlators.models import (
    CandidateChange,
    ChangeCategory,
    ChangeCorrelation,
    ChangeCorrelationBatchResult,
    CorrelationConfidence,
    IncidentChangeCorrelation,
)

__all__ = [
    "ChangeCategory",
    "CorrelationConfidence",
    "CandidateChange",
    "ChangeCorrelation",
    "IncidentChangeCorrelation",
    "ChangeCorrelationBatchResult",
    "ChangeCorrelator",
]

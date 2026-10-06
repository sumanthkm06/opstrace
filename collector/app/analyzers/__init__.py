"""
OpsTrace Collector — Log Analysis & Intelligence
Phase 6: Log Analysis & Intelligence

Public API for the Phase 6 analysis engine.

Typical usage::

    from collector.app.analyzers import LogAnalyzer
    from collector.app.collectors.log_models import CollectedLogEvent

    events: list[CollectedLogEvent] = [...]
    result = LogAnalyzer().analyze(events)
    print(result.total_errors, result.error_rate_per_minute)

All sub-components are available individually for unit testing:

    from collector.app.analyzers import (
        LogClassifier,
        FingerprintGenerator,
        LogGrouper,
        ErrorRateAnalyzer,
        LogAnalyzer,
        AnalysisResult,
        ErrorGroup,
        AnalysisClassification,
    )
"""

from collector.app.analyzers.classifier import LogClassifier, AnalysisClassification
from collector.app.analyzers.fingerprint import FingerprintGenerator
from collector.app.analyzers.grouping import LogGrouper, ErrorGroup
from collector.app.analyzers.error_rate import ErrorRateAnalyzer
from collector.app.analyzers.log_analyzer import LogAnalyzer
from collector.app.analyzers.models import AnalysisResult

__all__ = [
    "LogClassifier",
    "AnalysisClassification",
    "FingerprintGenerator",
    "LogGrouper",
    "ErrorGroup",
    "ErrorRateAnalyzer",
    "LogAnalyzer",
    "AnalysisResult",
]

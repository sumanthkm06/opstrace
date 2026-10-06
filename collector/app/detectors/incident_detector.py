"""
OpsTrace Collector — Incident Detection Engine
Phase 7: Incident Detection & Incident Correlation

The ``IncidentDetector`` orchestrates detection rules and correlates rule outputs
into consolidated operational incidents.
"""

from __future__ import annotations

import logging
from typing import List, Optional, Sequence

from collector.app.analyzers.models import AnalysisResult
from collector.app.collectors.log_models import CollectedLogEvent
from collector.app.detectors.models import (
    DetectedIncident,
    DetectionRuleConfig,
    IncidentDetectionResult,
)
from collector.app.detectors.rules import (
    BaseDetectionRule,
    CriticalErrorRule,
    HighErrorRateRule,
    MultipleRelatedErrorsRule,
    RepeatedFingerprintRule,
    ServiceFailureRule,
)

logger = logging.getLogger(__name__)


class IncidentDetector:
    """
    Phase 7 incident detection engine.

    Orchestrates detection rules, evaluates Phase 6 ``AnalysisResult`` and raw log events,
    and correlates related rule outputs into single consolidated incidents.
    """

    def __init__(
        self,
        config: Optional[DetectionRuleConfig] = None,
        rules: Optional[Sequence[BaseDetectionRule]] = None,
    ) -> None:
        self.config = config or DetectionRuleConfig()
        if rules is not None:
            self.rules = list(rules)
        else:
            self.rules = [
                ServiceFailureRule(),
                HighErrorRateRule(),
                CriticalErrorRule(),
                RepeatedFingerprintRule(),
                MultipleRelatedErrorsRule(),
            ]

    def detect(
        self,
        analysis_result: Optional[AnalysisResult] = None,
        events: Optional[Sequence[CollectedLogEvent]] = None,
        host_name: Optional[str] = None,
        service_name: Optional[str] = None,
    ) -> IncidentDetectionResult:
        """
        Execute all registered detection rules and correlate the results.

        Args:
            analysis_result: Phase 6 AnalysisResult (may be None).
            events: Sequence of CollectedLogEvent objects (may be None or empty).
            host_name: Optional hostname string.
            service_name: Optional service name string.

        Returns:
            IncidentDetectionResult containing correlated DetectedIncident list.
            Never raises; malformed inputs produce warnings/errors in the result.
        """
        result = IncidentDetectionResult()

        safe_events = events or ()
        safe_analysis = analysis_result or AnalysisResult()

        raw_incidents: List[DetectedIncident] = []

        # 1. Run each detection rule safely
        for idx, rule in enumerate(self.rules):
            result.total_rules_evaluated += 1
            try:
                detected = rule.evaluate(
                    analysis_result=safe_analysis,
                    events=safe_events,
                    config=self.config,
                    host_name=host_name,
                    service_name=service_name,
                )
                if detected:
                    raw_incidents.extend(detected)
            except Exception as exc:
                rule_id = getattr(rule, "rule_id", f"rule_{idx}")
                logger.warning("IncidentDetector: rule '%s' failed: %s", rule_id, exc)
                result.detection_errors.append(
                    f"Rule '{rule_id}' failed: {type(exc).__name__}"
                )

        # 2. Correlate raw incidents
        correlated = self.correlate_incidents(raw_incidents)

        result.incidents = correlated
        result.total_incidents_detected = len(correlated)

        return result

    def correlate_incidents(
        self, incidents: List[DetectedIncident]
    ) -> List[DetectedIncident]:
        """
        Correlate and deduplicate raw incidents triggered by multiple rules.

        Incidents sharing related fingerprints or targeting the same service/host
        with service failure conditions are merged into a single consolidated incident.
        """
        if not incidents:
            return []

        if len(incidents) == 1:
            return incidents

        merged_clusters: List[DetectedIncident] = []

        for inc in incidents:
            matched = False
            for target in merged_clusters:
                if self._should_merge(target, inc):
                    target.merge(inc)
                    matched = True
                    break
            if not matched:
                # Copy to avoid side effects
                merged_clusters.append(inc.model_copy(deep=True))

        return merged_clusters

    def _should_merge(self, inc1: DetectedIncident, inc2: DetectedIncident) -> bool:
        """Check if two detected incidents should be merged/correlated."""
        # 0. Do NOT merge if both incidents specify different explicit service names
        if (
            inc1.service_name is not None
            and inc2.service_name is not None
            and inc1.service_name.lower() != inc2.service_name.lower()
        ):
            return False

        # 1. Check if they share any fingerprint
        fps1 = set(inc1.related_fingerprints)
        fps2 = set(inc2.related_fingerprints)
        if fps1 and fps2 and bool(fps1.intersection(fps2)):
            return True

        # 2. If both are ServiceFailure incidents for the same non-None service/host
        if (
            inc1.incident_type == inc2.incident_type
            and inc1.service_name is not None
            and inc1.service_name == inc2.service_name
            and inc1.host_name == inc2.host_name
        ):
            return True

        # 3. If one is ServiceFailure and the other is RepeatedFingerprint on the same non-None service
        if (
            {inc1.incident_type, inc2.incident_type}.intersection(
                {"SERVICE_FAILURE", "REPEATED_FINGERPRINT", "REPEATED_CRITICAL_ERRORS"}
            )
            and inc1.service_name is not None
            and inc1.service_name == inc2.service_name
        ):
            return True

        return False

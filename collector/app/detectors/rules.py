"""
OpsTrace Collector — Phase 7 Detection Rules
Phase 7: Incident Detection & Incident Correlation

Defines detection rules that evaluate Phase 6 ``AnalysisResult`` data and raw
collected log events to identify operational incidents.
"""

from __future__ import annotations

import logging
from abc import ABC, abstractmethod
from datetime import datetime, timezone
from typing import List, Optional, Sequence

from collector.app.analyzers.models import AnalysisResult, ErrorGroupSummary
from collector.app.collectors.log_models import CollectedLogEvent
from collector.app.detectors.models import (
    DetectedIncident,
    DetectionRuleConfig,
    IncidentEvidence,
    IncidentSeverity,
    IncidentType,
)

logger = logging.getLogger(__name__)


class BaseDetectionRule(ABC):
    """Abstract base class for all incident detection rules."""

    rule_id: str = "base_rule"
    description: str = "Base detection rule"

    @abstractmethod
    def evaluate(
        self,
        analysis_result: AnalysisResult,
        events: Sequence[CollectedLogEvent] = (),
        config: Optional[DetectionRuleConfig] = None,
        host_name: Optional[str] = None,
        service_name: Optional[str] = None,
    ) -> List[DetectedIncident]:
        """
        Evaluate log analysis output and return any detected incidents.

        Args:
            analysis_result: Structured result from Phase 6 LogAnalyzer.
            events: Sequence of raw or enriched CollectedLogEvent objects.
            config: Configurable detection thresholds and options.
            host_name: Identifier of affected host.
            service_name: Identifier of affected service.

        Returns:
            List of DetectedIncident instances (may be empty).
        """
        pass


class ServiceFailureRule(BaseDetectionRule):
    """
    Detects service or component failures indicated by critical error messages
    or specific unavailability keywords (e.g. 'connection failed', 'service unavailable').

    Correlates related log events across error groups into a single incident.
    """

    rule_id = IncidentType.SERVICE_FAILURE.value
    description = "Detects service availability and component connectivity failures"

    def evaluate(
        self,
        analysis_result: AnalysisResult,
        events: Sequence[CollectedLogEvent] = (),
        config: Optional[DetectionRuleConfig] = None,
        host_name: Optional[str] = None,
        service_name: Optional[str] = None,
    ) -> List[DetectedIncident]:
        if not analysis_result and not events:
            return []

        cfg = config or DetectionRuleConfig()
        keywords = [kw.lower() for kw in cfg.service_failure_keywords]

        matching_groups: List[ErrorGroupSummary] = []
        matching_events: List[CollectedLogEvent] = []

        # 1. Check error groups from analysis_result
        if analysis_result and analysis_result.error_groups:
            for grp in analysis_result.error_groups:
                msg_lower = (grp.sample_message or "").lower()
                if any(kw in msg_lower for kw in keywords):
                    matching_groups.append(grp)

        # 2. Check raw/collected events for any service failure keywords not captured in error_groups
        if events:
            for evt in events:
                msg_lower = (evt.message or "").lower()
                lvl = (evt.level.value if hasattr(evt.level, "value") else str(evt.level or "")).upper()
                if lvl in ("ERROR", "CRITICAL", "FATAL") and any(kw in msg_lower for kw in keywords):
                    matching_events.append(evt)

        if not matching_groups and not matching_events:
            return []

        # Determine severity and construct correlated title
        has_critical = any(grp.level == "CRITICAL" for grp in matching_groups) or any(
            (evt.level.value if hasattr(evt.level, "value") else str(evt.level or "")).upper() in ("CRITICAL", "FATAL")
            for evt in matching_events
        )
        severity = IncidentSeverity.CRITICAL if has_critical else IncidentSeverity.ERROR

        # Derive service name if not explicitly provided
        inferred_service = service_name
        if not inferred_service and matching_groups:
            # Check source of matching group
            src = matching_groups[0].source
            if src and src != "unknown" and src != "syslog":
                inferred_service = src
        if not inferred_service:
            inferred_service = "Service"

        title = f"{inferred_service.capitalize()} Failure / Unavailability"
        if host_name:
            title += f" on {host_name}"

        # Collect evidence & timestamps
        evidence_list: List[IncidentEvidence] = []
        related_fingerprints: List[str] = []
        first_seen: Optional[datetime] = None
        last_seen: Optional[datetime] = None

        total_matching_log_count = 0

        for grp in matching_groups:
            total_matching_log_count += grp.count
            if grp.fingerprint and grp.fingerprint not in related_fingerprints:
                related_fingerprints.append(grp.fingerprint)

            if grp.first_seen and (not first_seen or grp.first_seen < first_seen):
                first_seen = grp.first_seen
            if grp.last_seen and (not last_seen or grp.last_seen > last_seen):
                last_seen = grp.last_seen

            evidence_list.append(
                IncidentEvidence(
                    event_type="service_failure_group",
                    timestamp=grp.last_seen or grp.first_seen,
                    message=grp.sample_message,
                    fingerprint=grp.fingerprint,
                    source=grp.source,
                    details={"count": grp.count, "level": grp.level},
                )
            )

        for evt in matching_events:
            total_matching_log_count += 1
            if evt.fingerprint and evt.fingerprint not in related_fingerprints:
                related_fingerprints.append(evt.fingerprint)

            evt_ts = evt.timestamp
            if evt_ts:
                if not first_seen or evt_ts < first_seen:
                    first_seen = evt_ts
                if not last_seen or evt_ts > last_seen:
                    last_seen = evt_ts

            evidence_list.append(
                IncidentEvidence(
                    event_type="service_failure_log",
                    timestamp=evt.timestamp,
                    message=evt.message,
                    fingerprint=evt.fingerprint,
                    source=evt.source,
                    details={"service_name": evt.service_name},
                )
            )

        desc = (
            f"Detected service failure condition matching availability keywords. "
            f"Correlated {total_matching_log_count} log event(s) across "
            f"{len(related_fingerprints)} unique fingerprint(s)."
        )

        incident = DetectedIncident(
            incident_type=IncidentType.SERVICE_FAILURE.value,
            title=title,
            description=desc,
            severity=severity,
            status="open",
            first_seen=first_seen,
            last_seen=last_seen,
            host_name=host_name,
            service_name=inferred_service,
            related_fingerprints=related_fingerprints,
            evidence=evidence_list,
            metadata={
                "rule_id": self.rule_id,
                "correlated_event_count": total_matching_log_count,
                "matching_group_count": len(matching_groups),
            },
        )

        return [incident]


class HighErrorRateRule(BaseDetectionRule):
    """
    Detects abnormally high error rates over the analysis window.
    """

    rule_id = IncidentType.HIGH_ERROR_RATE.value
    description = "Detects elevated error rate per minute exceeding threshold"

    def evaluate(
        self,
        analysis_result: AnalysisResult,
        events: Sequence[CollectedLogEvent] = (),
        config: Optional[DetectionRuleConfig] = None,
        host_name: Optional[str] = None,
        service_name: Optional[str] = None,
    ) -> List[DetectedIncident]:
        if not analysis_result:
            return []

        cfg = config or DetectionRuleConfig()
        rate = getattr(analysis_result, "error_rate_per_minute", 0.0)

        # Check thresholds
        if rate >= cfg.error_rate_critical_threshold:
            severity = IncidentSeverity.CRITICAL
        elif rate >= cfg.error_rate_error_threshold:
            severity = IncidentSeverity.ERROR
        elif rate >= cfg.error_rate_warning_threshold:
            severity = IncidentSeverity.WARNING
        else:
            return []

        title = f"High Error Rate Detected ({rate:.1f} errors/min)"
        if service_name:
            title = f"High Error Rate in {service_name} ({rate:.1f} errors/min)"
        if host_name:
            title += f" on {host_name}"

        desc = (
            f"Error rate reached {rate:.2f} errors/minute over an analysis window of "
            f"{analysis_result.analysis_window_seconds:.1f} seconds. "
            f"Total errors: {analysis_result.total_errors}, Critical: {analysis_result.total_critical}."
        )

        fingerprints = [
            grp.fingerprint
            for grp in getattr(analysis_result, "error_groups", [])
            if getattr(grp, "fingerprint", None)
        ]

        evidence = [
            IncidentEvidence(
                event_type="error_rate_threshold_exceeded",
                timestamp=analysis_result.window_end or analysis_result.analyzed_at,
                message=f"Error rate is {rate:.2f}/min (threshold: {cfg.error_rate_warning_threshold}/min)",
                details={
                    "error_rate_per_minute": rate,
                    "total_errors": analysis_result.total_errors,
                    "total_critical": analysis_result.total_critical,
                    "window_seconds": analysis_result.analysis_window_seconds,
                },
            )
        ]

        incident = DetectedIncident(
            incident_type=IncidentType.HIGH_ERROR_RATE.value,
            title=title,
            description=desc,
            severity=severity,
            status="open",
            first_seen=analysis_result.window_start,
            last_seen=analysis_result.window_end,
            host_name=host_name,
            service_name=service_name,
            related_fingerprints=fingerprints,
            evidence=evidence,
            metadata={
                "rule_id": self.rule_id,
                "error_rate_per_minute": rate,
                "total_errors": analysis_result.total_errors,
            },
        )

        return [incident]


class RepeatedFingerprintRule(BaseDetectionRule):
    """
    Detects repeated occurrences of identical error fingerprints.
    """

    rule_id = IncidentType.REPEATED_FINGERPRINT.value
    description = "Detects recurring errors sharing identical fingerprints"

    def evaluate(
        self,
        analysis_result: AnalysisResult,
        events: Sequence[CollectedLogEvent] = (),
        config: Optional[DetectionRuleConfig] = None,
        host_name: Optional[str] = None,
        service_name: Optional[str] = None,
    ) -> List[DetectedIncident]:
        if not analysis_result or not getattr(analysis_result, "error_groups", None):
            return []

        cfg = config or DetectionRuleConfig()
        threshold = cfg.repeated_fingerprint_threshold
        incidents: List[DetectedIncident] = []

        for grp in analysis_result.error_groups:
            if grp.count >= threshold:
                # Map group level to IncidentSeverity
                lvl_str = (grp.level or "ERROR").upper()
                if lvl_str == "CRITICAL" or lvl_str == "FATAL":
                    severity = IncidentSeverity.CRITICAL
                elif lvl_str == "ERROR":
                    severity = IncidentSeverity.ERROR
                elif lvl_str == "WARNING" or lvl_str == "WARN":
                    severity = IncidentSeverity.WARNING
                else:
                    severity = IncidentSeverity.INFO

                title = f"Repeated Error Pattern ({grp.count} occurrences): {grp.sample_message[:60]}"
                if len(grp.sample_message) > 60:
                    title += "..."

                desc = (
                    f"Error fingerprint '{grp.fingerprint[:12]}' occurred {grp.count} times. "
                    f"Sample: '{grp.sample_message}'"
                )

                evidence = [
                    IncidentEvidence(
                        event_type="repeated_fingerprint",
                        timestamp=grp.last_seen or grp.first_seen,
                        message=grp.sample_message,
                        fingerprint=grp.fingerprint,
                        source=grp.source,
                        details={"count": grp.count, "level": grp.level},
                    )
                ]

                inc = DetectedIncident(
                    incident_type=IncidentType.REPEATED_FINGERPRINT.value,
                    title=title,
                    description=desc,
                    severity=severity,
                    status="open",
                    first_seen=grp.first_seen,
                    last_seen=grp.last_seen,
                    host_name=host_name,
                    service_name=service_name or (grp.source if grp.source != "unknown" else None),
                    related_fingerprints=[grp.fingerprint] if grp.fingerprint else [],
                    evidence=evidence,
                    metadata={
                        "rule_id": self.rule_id,
                        "fingerprint": grp.fingerprint,
                        "occurrence_count": grp.count,
                    },
                )
                incidents.append(inc)

        return incidents


class CriticalErrorRule(BaseDetectionRule):
    """
    Detects critical/fatal log events and creates a CRITICAL severity incident.
    """

    rule_id = IncidentType.REPEATED_CRITICAL_ERRORS.value
    description = "Detects critical or fatal severity error events"

    def evaluate(
        self,
        analysis_result: AnalysisResult,
        events: Sequence[CollectedLogEvent] = (),
        config: Optional[DetectionRuleConfig] = None,
        host_name: Optional[str] = None,
        service_name: Optional[str] = None,
    ) -> List[DetectedIncident]:
        cfg = config or DetectionRuleConfig()
        crit_count = getattr(analysis_result, "total_critical", 0) if analysis_result else 0

        # Also check raw events
        raw_crit = [
            e for e in events
            if hasattr(e, "level") and (
                (hasattr(e.level, "value") and e.level.value in ("CRITICAL", "FATAL")) or
                (isinstance(e.level, str) and e.level.upper() in ("CRITICAL", "FATAL"))
            )
        ]

        total_crit = max(crit_count, len(raw_crit))
        if total_crit < cfg.critical_error_threshold:
            return []

        title = f"Critical System Error ({total_crit} critical events)"
        if service_name:
            title = f"Critical Error in {service_name} ({total_crit} events)"
        if host_name:
            title += f" on {host_name}"

        evidence_list: List[IncidentEvidence] = []
        fingerprints: List[str] = []

        if analysis_result and getattr(analysis_result, "error_groups", None):
            for grp in analysis_result.error_groups:
                if grp.level == "CRITICAL":
                    if grp.fingerprint and grp.fingerprint not in fingerprints:
                        fingerprints.append(grp.fingerprint)
                    evidence_list.append(
                        IncidentEvidence(
                            event_type="critical_error_group",
                            timestamp=grp.last_seen or grp.first_seen,
                            message=grp.sample_message,
                            fingerprint=grp.fingerprint,
                            source=grp.source,
                            details={"count": grp.count},
                        )
                    )

        for e in raw_crit:
            if getattr(e, "fingerprint", None) and e.fingerprint not in fingerprints:
                fingerprints.append(e.fingerprint)
            evidence_list.append(
                IncidentEvidence(
                    event_type="critical_error_log",
                    timestamp=e.timestamp,
                    message=e.message,
                    fingerprint=getattr(e, "fingerprint", None),
                    source=e.source,
                    details={},
                )
            )

        inc = DetectedIncident(
            incident_type=IncidentType.REPEATED_CRITICAL_ERRORS.value,
            title=title,
            description=f"Recorded {total_crit} critical or fatal log events requiring immediate triage.",
            severity=IncidentSeverity.CRITICAL,
            status="open",
            first_seen=analysis_result.window_start if analysis_result else None,
            last_seen=analysis_result.window_end if analysis_result else None,
            host_name=host_name,
            service_name=service_name,
            related_fingerprints=fingerprints,
            evidence=evidence_list,
            metadata={
                "rule_id": self.rule_id,
                "critical_count": total_crit,
            },
        )

        return [inc]


class MultipleRelatedErrorsRule(BaseDetectionRule):
    """
    Detects multiple distinct error fingerprints occurring together.
    """

    rule_id = IncidentType.MULTIPLE_RELATED_ERRORS.value
    description = "Detects multiple distinct error categories occurring concurrently"

    def evaluate(
        self,
        analysis_result: AnalysisResult,
        events: Sequence[CollectedLogEvent] = (),
        config: Optional[DetectionRuleConfig] = None,
        host_name: Optional[str] = None,
        service_name: Optional[str] = None,
    ) -> List[DetectedIncident]:
        if not analysis_result:
            return []

        cfg = config or DetectionRuleConfig()
        unique_fps = getattr(analysis_result, "unique_error_fingerprints", 0)

        if unique_fps < cfg.multiple_errors_threshold:
            return []

        title = f"Multiple Correlated Error Patterns ({unique_fps} distinct fingerprints)"
        if host_name:
            title += f" on {host_name}"

        evidence_list: List[IncidentEvidence] = []
        fingerprints: List[str] = []

        for grp in getattr(analysis_result, "error_groups", []):
            if grp.fingerprint:
                fingerprints.append(grp.fingerprint)
            evidence_list.append(
                IncidentEvidence(
                    event_type="correlated_error_group",
                    timestamp=grp.last_seen or grp.first_seen,
                    message=grp.sample_message,
                    fingerprint=grp.fingerprint,
                    source=grp.source,
                    details={"count": grp.count, "level": grp.level},
                )
            )

        inc = DetectedIncident(
            incident_type=IncidentType.MULTIPLE_RELATED_ERRORS.value,
            title=title,
            description=f"Detected {unique_fps} unique error fingerprints in a single analysis window.",
            severity=IncidentSeverity.ERROR if unique_fps < 5 else IncidentSeverity.CRITICAL,
            status="open",
            first_seen=analysis_result.window_start,
            last_seen=analysis_result.window_end,
            host_name=host_name,
            service_name=service_name,
            related_fingerprints=fingerprints,
            evidence=evidence_list,
            metadata={
                "rule_id": self.rule_id,
                "unique_fingerprints_count": unique_fps,
            },
        )

        return [inc]

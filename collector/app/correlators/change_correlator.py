"""
OpsTrace Collector — Phase 9 Change-Aware Correlator Engine
Phase 9: Change-Aware Correlation

Correlates operational incidents against recent candidate software deployments and
configuration alterations using transparent, rule-based algorithms.

Key Principles:
  1. Explainable & Deterministic: Scoring uses rule weights for temporal proximity,
     scope matching, and change impact.
  2. Non-causal Attribution: Explicitly highlights that correlation does NOT prove causation.
  3. Structured Attribution: Identifies suspect deployment UUIDs and suspect config change UUIDs.
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import List, Optional, Tuple

from collector.app.correlators.models import (
    CandidateChange,
    ChangeCategory,
    ChangeCorrelation,
    ChangeCorrelationBatchResult,
    CorrelationConfidence,
    IncidentChangeCorrelation,
)
from collector.app.detectors.models import DetectedIncident, IncidentDetectionResult

logger = logging.getLogger(__name__)


class ChangeCorrelator:
    """
    Rule-based Change-Aware Correlation Engine.

    Evaluates candidate system changes against incidents to determine candidate
    contributing changes, candidate suspect IDs, and explainable rationale.
    """

    def __init__(
        self,
        lookback_minutes: int = 60,
        min_score_threshold: float = 0.20,
    ) -> None:
        """
        Initialize the ChangeCorrelator.

        Args:
            lookback_minutes: Time window (in minutes) prior to incident detection to evaluate changes.
            min_score_threshold: Minimum correlation score required to include candidate in suspect list.
        """
        self.lookback_minutes = max(1, lookback_minutes)
        self.min_score_threshold = max(0.0, min(1.0, min_score_threshold))

    def correlate_incident(
        self,
        incident: DetectedIncident,
        candidate_changes: List[CandidateChange],
        host_id: Optional[str] = None,
        service_id: Optional[str] = None,
    ) -> IncidentChangeCorrelation:
        """
        Correlate a single ``DetectedIncident`` against a list of candidate changes.

        Args:
            incident: DetectedIncident instance.
            candidate_changes: List of candidate deployments or config changes.
            host_id: Optional target Host UUID string override.
            service_id: Optional target Service UUID string override.

        Returns:
            IncidentChangeCorrelation result containing primary and secondary suspects.
        """
        if not incident:
            raise ValueError("Incident cannot be None.")

        now_utc = datetime.now(timezone.utc)
        det_time = incident.first_seen or now_utc
        if det_time.tzinfo is None:
            det_time = det_time.replace(tzinfo=timezone.utc)

        eff_host_id = host_id or (str(incident.host_id) if incident.host_id else None)
        eff_service_id = service_id or (str(incident.service_id) if incident.service_id else None)

        if not candidate_changes:
            return IncidentChangeCorrelation(
                incident_id=incident.incident_id,
                incident_title=incident.title,
                detected_at=det_time,
                host_id=incident.host_id,
                service_id=incident.service_id,
                correlated_deployment_id=None,
                correlated_config_change_id=None,
                primary_suspect=None,
                secondary_suspects=[],
                total_candidates_evaluated=0,
                correlation_window_minutes=self.lookback_minutes,
            )

        evaluations: List[ChangeCorrelation] = []

        for candidate in candidate_changes:
            eval_res = self.evaluate_candidate(
                incident_title=incident.title,
                incident_det_time=det_time,
                host_id=eff_host_id,
                service_id=eff_service_id,
                candidate=candidate,
            )
            if eval_res and eval_res.score >= self.min_score_threshold:
                evaluations.append(eval_res)

        # Sort evaluations by score descending, then by change timestamp descending
        evaluations.sort(
            key=lambda x: (x.score, x.candidate.timestamp),
            reverse=True,
        )

        primary_suspect: Optional[ChangeCorrelation] = None
        secondary_suspects: List[ChangeCorrelation] = []

        if evaluations:
            evaluations[0].is_primary_suspect = True
            primary_suspect = evaluations[0]
            secondary_suspects = evaluations[1:]

        # Extract correlated deployment / config_change IDs from candidates
        corr_dep_id, corr_cc_id = self._extract_suspect_ids(evaluations)

        return IncidentChangeCorrelation(
            incident_id=incident.incident_id,
            incident_title=incident.title,
            detected_at=det_time,
            host_id=incident.host_id,
            service_id=incident.service_id,
            correlated_deployment_id=corr_dep_id,
            correlated_config_change_id=corr_cc_id,
            primary_suspect=primary_suspect,
            secondary_suspects=secondary_suspects,
            total_candidates_evaluated=len(candidate_changes),
            correlation_window_minutes=self.lookback_minutes,
        )

    def correlate_batch(
        self,
        detection_result: IncidentDetectionResult,
        candidate_changes: List[CandidateChange],
        host_id: Optional[str] = None,
        service_id: Optional[str] = None,
    ) -> ChangeCorrelationBatchResult:
        """
        Correlate a batch of incidents in ``IncidentDetectionResult`` against candidate changes.

        Args:
            detection_result: IncidentDetectionResult from IncidentDetector.
            candidate_changes: List of candidate system changes.
            host_id: Optional host UUID override.
            service_id: Optional service UUID override.

        Returns:
            ChangeCorrelationBatchResult containing correlation for each incident.
        """
        now_utc = datetime.now(timezone.utc)

        if not detection_result or not detection_result.incidents:
            return ChangeCorrelationBatchResult(
                processed_at=now_utc,
                correlations=[],
                total_incidents_processed=0,
                total_correlated=0,
                warnings=["Empty or None detection result provided."],
            )

        correlations: List[IncidentChangeCorrelation] = []
        correlated_count = 0

        for inc in detection_result.incidents:
            corr = self.correlate_incident(
                incident=inc,
                candidate_changes=candidate_changes,
                host_id=host_id,
                service_id=service_id,
            )
            correlations.append(corr)
            if corr.primary_suspect:
                correlated_count += 1

        return ChangeCorrelationBatchResult(
            processed_at=now_utc,
            correlations=correlations,
            total_incidents_processed=len(detection_result.incidents),
            total_correlated=correlated_count,
        )

    def evaluate_candidate(
        self,
        incident_title: str,
        incident_det_time: datetime,
        host_id: Optional[str],
        service_id: Optional[str],
        candidate: CandidateChange,
    ) -> Optional[ChangeCorrelation]:
        """
        Evaluate a single candidate change against incident parameters using rule weights.

        Weight Breakdown:
          - Temporal Proximity: 40%
          - Scope Matching: 40%
          - Impact & Change Nature: 20%
        """
        if not candidate:
            return None

        c_time = candidate.timestamp
        if c_time.tzinfo is None:
            c_time = c_time.replace(tzinfo=timezone.utc)

        # -------------------------------------------------------------------
        # 1. Temporal Proximity Evaluation (40%)
        # -------------------------------------------------------------------
        time_diff_seconds = (incident_det_time - c_time).total_seconds()
        lookback_seconds = self.lookback_minutes * 60

        # Ignore changes occurring significantly after incident (>120s buffer for clock drift)
        if time_diff_seconds < -120:
            return ChangeCorrelation(
                candidate=candidate,
                score=0.0,
                confidence=CorrelationConfidence.UNLIKELY,
                reasons=["Change occurred after incident detection."],
            )

        # Ignore changes outside the lookback window
        if time_diff_seconds > lookback_seconds:
            return ChangeCorrelation(
                candidate=candidate,
                score=0.0,
                confidence=CorrelationConfidence.UNLIKELY,
                reasons=[
                    f"Change occurred {int(time_diff_seconds / 60)} minutes before incident "
                    f"(outside {self.lookback_minutes}-minute lookback window)."
                ],
            )

        reasons: List[str] = []

        # Calculate temporal score (0.0 to 1.0)
        abs_diff = max(0.0, time_diff_seconds)
        if abs_diff <= 300:  # <= 5 min
            temp_score = 1.0
            reasons.append("Change occurred within 5 minutes of incident detection.")
        elif abs_diff <= 900:  # <= 15 min
            temp_score = 0.85
            reasons.append("Change occurred within 15 minutes of incident detection.")
        elif abs_diff <= 1800:  # <= 30 min
            temp_score = 0.65
            reasons.append("Change occurred within 30 minutes of incident detection.")
        else:
            temp_score = 0.40
            reasons.append(
                f"Change occurred within correlation lookback window ({int(abs_diff / 60)} minutes prior)."
            )

        # -------------------------------------------------------------------
        # 2. Scope Matching Evaluation (40%)
        # -------------------------------------------------------------------
        cand_host_id = str(candidate.host_id) if candidate.host_id else None
        cand_service_id = str(candidate.service_id) if candidate.service_id else None

        scope_score = 0.0
        if service_id and cand_service_id and service_id == cand_service_id:
            scope_score = 1.0
            reasons.append(f"Direct service match: target service {service_id}.")
        elif host_id and cand_host_id and host_id == cand_host_id:
            if cand_service_id:
                scope_score = 0.70
                reasons.append("Same host match (co-located service change).")
            else:
                scope_score = 0.85
                reasons.append("Direct host match for infrastructure configuration change.")
        elif not cand_host_id and not cand_service_id:
            # Global/environment-wide change
            scope_score = 0.50
            reasons.append("Global or environment-level configuration change.")
        else:
            # Different host and different service -> zero scope score
            scope_score = 0.0
            reasons.append("Disjoint scope: change occurred on a different host and service.")

        # If scope score is 0.0, overall correlation is zero
        if scope_score == 0.0:
            return ChangeCorrelation(
                candidate=candidate,
                score=0.0,
                confidence=CorrelationConfidence.UNLIKELY,
                reasons=reasons,
            )

        # -------------------------------------------------------------------
        # 3. Impact & Change Nature Evaluation (20%)
        # -------------------------------------------------------------------
        impact_score = 0.50
        if candidate.change_type == ChangeCategory.CONFIG_CHANGE:
            if candidate.diff or candidate.details.get("previous_value"):
                impact_score = 1.0
                reasons.append("Configuration change contains active diff or parameter modification.")
            else:
                impact_score = 0.80
                reasons.append("Configuration file modification event.")
        elif candidate.change_type == ChangeCategory.DEPLOYMENT:
            status = str(candidate.details.get("status", "completed")).lower()
            if status in ("failed", "rolled_back"):
                impact_score = 1.0
                reasons.append(f"Deployment status is '{status}', increasing correlation suspicion.")
            else:
                impact_score = 0.90
                reasons.append("Software deployment release event.")
        elif candidate.change_type == ChangeCategory.ENV_VAR_UPDATE:
            impact_score = 0.85
            reasons.append("Environment variable alteration.")
        elif candidate.change_type == ChangeCategory.PACKAGE_UPDATE:
            impact_score = 0.75
            reasons.append("System package update.")

        # -------------------------------------------------------------------
        # Composite Score Calculation
        # -------------------------------------------------------------------
        final_score = round(
            (temp_score * 0.40) + (scope_score * 0.40) + (impact_score * 0.20),
            4,
        )
        final_score = max(0.0, min(1.0, final_score))
        confidence = CorrelationConfidence.from_score(final_score)

        return ChangeCorrelation(
            candidate=candidate,
            score=final_score,
            confidence=confidence,
            reasons=reasons,
        )

    def _extract_suspect_ids(
        self, evaluations: List[ChangeCorrelation]
    ) -> Tuple[Optional[any], Optional[any]]:
        """Extract top correlated deployment and config_change IDs from evaluations."""
        dep_id = None
        cc_id = None

        for item in evaluations:
            cand = item.candidate
            if item.score < self.min_score_threshold:
                continue

            if cand.change_type == ChangeCategory.DEPLOYMENT and dep_id is None:
                dep_id = cand.change_id
            elif cand.change_type == ChangeCategory.CONFIG_CHANGE and cc_id is None:
                cc_id = cand.change_id
                # Check if this config change was part of a deployment
                if not dep_id and cand.details.get("deployment_id"):
                    try:
                        import uuid
                        dep_id = uuid.UUID(str(cand.details["deployment_id"]))
                    except (ValueError, TypeError):
                        pass

            if dep_id and cc_id:
                break

        return dep_id, cc_id

"""
OpsTrace Collector — Phase 8 Remediation Engine
Phase 8: Remediation

The RemediationEngine receives detected incidents, determines whether
a safe remediation action is appropriate, plans the action from a
closed allowlist, and executes it (or simulates it in dry-run mode).

Security:
  - Actions are ONLY selected from RemediationActionType enum values.
  - No shell commands are derived from log messages or incident text.
  - Dry-run is the default; actual execution requires explicit opt-in.
  - Duplicate remediation is prevented per incident within a run.
"""

from __future__ import annotations

import logging
import uuid
from datetime import datetime, timezone
from typing import Dict, List, Optional, Set

from collector.app.detectors.models import (
    DetectedIncident,
    IncidentDetectionResult,
    IncidentType,
)
from collector.app.remediators.models import (
    RemediationActionType,
    RemediationAuditRecord,
    RemediationBatchResult,
    RemediationPlan,
    RemediationResult,
    RemediationStatus,
)

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Allowlist: IncidentType → RemediationActionType
#
# SECURITY: This is the ONLY place where incident type maps to action.
# Never derive action type from string input.
# ---------------------------------------------------------------------------

_INCIDENT_TYPE_TO_ACTION: Dict[str, RemediationActionType] = {
    IncidentType.SERVICE_FAILURE.value: RemediationActionType.RESTART_SERVICE,
    IncidentType.HIGH_ERROR_RATE.value: RemediationActionType.CLEAR_RETRY_OPERATION,
    IncidentType.REPEATED_CRITICAL_ERRORS.value: RemediationActionType.MANUAL_INVESTIGATION_REQUIRED,
    IncidentType.REPEATED_FINGERPRINT.value: RemediationActionType.CLEAR_RETRY_OPERATION,
    IncidentType.MULTIPLE_RELATED_ERRORS.value: RemediationActionType.SCALE_RECOVERY_RECOMMENDATION,
    IncidentType.CUSTOM_RULE.value: RemediationActionType.MANUAL_INVESTIGATION_REQUIRED,
}

_ACTION_DESCRIPTIONS: Dict[RemediationActionType, str] = {
    RemediationActionType.RESTART_SERVICE: (
        "Gracefully restart the affected service to recover from failure state."
    ),
    RemediationActionType.CLEAR_RETRY_OPERATION: (
        "Clear stuck operation queues and retry pending work items."
    ),
    RemediationActionType.SCALE_RECOVERY_RECOMMENDATION: (
        "Recommendation: Scale up affected service tier to absorb elevated load."
    ),
    RemediationActionType.CONFIG_ROLLBACK_RECOMMENDATION: (
        "Recommendation: Roll back the most recent configuration change."
    ),
    RemediationActionType.MANUAL_INVESTIGATION_REQUIRED: (
        "Manual investigation is required. No automated action will be taken."
    ),
    RemediationActionType.NO_ACTION: (
        "No remediation action is applicable for this incident type."
    ),
}

_ACTION_RATIONALES: Dict[RemediationActionType, str] = {
    RemediationActionType.RESTART_SERVICE: (
        "Service failure detected; restart is the standard first recovery step."
    ),
    RemediationActionType.CLEAR_RETRY_OPERATION: (
        "High error rate or repeated fingerprint suggests transient operation failure."
    ),
    RemediationActionType.SCALE_RECOVERY_RECOMMENDATION: (
        "Multiple correlated errors suggest resource saturation."
    ),
    RemediationActionType.CONFIG_ROLLBACK_RECOMMENDATION: (
        "Recent configuration change is a likely contributing factor."
    ),
    RemediationActionType.MANUAL_INVESTIGATION_REQUIRED: (
        "Incident complexity or criticality requires human analysis."
    ),
    RemediationActionType.NO_ACTION: (
        "No automated action is available for this incident class."
    ),
}

# Actions that are recommendations only — never touch live systems
_RECOMMENDATION_ONLY_ACTIONS: Set[RemediationActionType] = {
    RemediationActionType.SCALE_RECOVERY_RECOMMENDATION,
    RemediationActionType.CONFIG_ROLLBACK_RECOMMENDATION,
    RemediationActionType.MANUAL_INVESTIGATION_REQUIRED,
    RemediationActionType.NO_ACTION,
}


class RemediationEngine:
    """
    Phase 8 Remediation Engine.

    Determines and executes (or simulates) safe remediation actions for
    detected incidents produced by the Phase 7 IncidentDetector.

    Usage::

        engine = RemediationEngine(dry_run=True)  # default: dry_run
        batch = engine.process(detection_result)

        for result in batch.results:
            print(result.status, result.message)

    Safety guarantees:
      - Only allowlisted action types are selected.
      - dry_run=True (default): nothing touches live systems.
      - Duplicate remediations for the same incident are skipped.
      - All decisions produce an audit record.
      - Exceptions are caught and reported as FAILED status; never re-raised.
    """

    def __init__(self, dry_run: bool = True) -> None:
        self.dry_run = dry_run

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def process(
        self,
        detection_result: IncidentDetectionResult,
        actor: str = "system",
    ) -> RemediationBatchResult:
        """
        Process all detected incidents from a Phase 7 detection result.

        Args:
            detection_result: IncidentDetectionResult from IncidentDetector.
            actor: Identifier of the actor requesting remediation (default: system).

        Returns:
            RemediationBatchResult with plans, results, and audit records.
            Never raises; errors are captured in results.
        """
        batch = RemediationBatchResult()

        if not detection_result or not detection_result.incidents:
            return batch

        batch.total_incidents = len(detection_result.incidents)
        seen_incident_ids: Set[uuid.UUID] = set()

        for incident in detection_result.incidents:
            try:
                plan, result, audits = self._process_one(
                    incident=incident,
                    actor=actor,
                    seen_incident_ids=seen_incident_ids,
                )
                batch.plans.append(plan)
                batch.results.append(result)
                batch.audit_records.extend(audits)

                if result.status == RemediationStatus.SUCCESS:
                    batch.total_actioned += 1
                elif result.status == RemediationStatus.SKIPPED:
                    batch.total_skipped += 1
                elif result.status == RemediationStatus.FAILED:
                    batch.total_failed += 1

                # Track seen incident UUIDs for duplicate detection
                if incident.incident_id:
                    seen_incident_ids.add(incident.incident_id)

            except Exception as exc:
                logger.error(
                    "RemediationEngine: unexpected error for incident '%s': %s",
                    getattr(incident, "title", "unknown"),
                    exc,
                )
                batch.warnings.append(
                    f"Unexpected error for incident "
                    f"'{getattr(incident, 'title', 'unknown')}': {type(exc).__name__}"
                )
                batch.total_failed += 1

        return batch

    def plan(
        self,
        incident: DetectedIncident,
    ) -> RemediationPlan:
        """
        Produce a RemediationPlan for a single incident without executing it.

        Args:
            incident: DetectedIncident from Phase 7.

        Returns:
            RemediationPlan with action_type from the allowlist.
        """
        if incident is None:
            raise ValueError("incident must not be None")

        action_type = self._select_action(incident.incident_type)
        return RemediationPlan(
            incident_id=incident.incident_id,
            incident_title=incident.title,
            incident_type=incident.incident_type,
            action_type=action_type,
            description=_ACTION_DESCRIPTIONS[action_type],
            rationale=_ACTION_RATIONALES[action_type],
            dry_run=self.dry_run,
        )

    def execute(
        self,
        plan: RemediationPlan,
    ) -> RemediationResult:
        """
        Execute (or dry-run simulate) a remediation plan.

        Args:
            plan: RemediationPlan produced by plan().

        Returns:
            RemediationResult describing the outcome.
        """
        if plan is None:
            raise ValueError("plan must not be None")

        # SECURITY: Validate the action_type is in the allowlist
        if not isinstance(plan.action_type, RemediationActionType):
            return RemediationResult(
                plan_id=plan.plan_id,
                incident_id=plan.incident_id,
                action_type=RemediationActionType.NO_ACTION,
                status=RemediationStatus.FAILED,
                message="Rejected: action_type is not in the allowlist.",
                error=f"Unknown action_type: {plan.action_type!r}",
                dry_run=plan.dry_run,
            )

        # Recommendation-only actions: always SKIPPED (no system changes)
        if plan.action_type in _RECOMMENDATION_ONLY_ACTIONS:
            return RemediationResult(
                plan_id=plan.plan_id,
                incident_id=plan.incident_id,
                action_type=plan.action_type,
                status=RemediationStatus.SKIPPED,
                message=(
                    f"[Recommendation] {plan.description} "
                    f"(No automated execution — human review required.)"
                ),
                dry_run=plan.dry_run,
                output={"recommendation": plan.description},
            )

        # Dry-run: simulate only
        if plan.dry_run:
            return RemediationResult(
                plan_id=plan.plan_id,
                incident_id=plan.incident_id,
                action_type=plan.action_type,
                status=RemediationStatus.SKIPPED,
                message=(
                    f"[Dry-run] Would execute: {plan.action_type.value} "
                    f"for incident '{plan.incident_title}'."
                ),
                dry_run=True,
                output={
                    "would_execute": plan.action_type.value,
                    "incident_title": plan.incident_title,
                    "parameters": plan.parameters,
                },
            )

        # Live execution path — dispatch to safe handler
        return self._execute_live(plan)

    def validate_action_type(self, action_type_str: str) -> Optional[RemediationActionType]:
        """
        Validate that a string is a known allowlisted action type.

        Args:
            action_type_str: Candidate action type string.

        Returns:
            RemediationActionType enum member if valid, else None.
        """
        try:
            return RemediationActionType(action_type_str)
        except ValueError:
            return None

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _process_one(
        self,
        incident: DetectedIncident,
        actor: str,
        seen_incident_ids: Set[uuid.UUID],
    ):
        """Process a single incident: plan + execute + audit."""
        # Duplicate prevention
        if incident.incident_id and incident.incident_id in seen_incident_ids:
            plan = self.plan(incident)
            plan.dry_run = self.dry_run
            result = RemediationResult(
                plan_id=plan.plan_id,
                incident_id=incident.incident_id,
                action_type=plan.action_type,
                status=RemediationStatus.SKIPPED,
                message=f"Duplicate: remediation already processed for incident {incident.incident_id}.",
                dry_run=self.dry_run,
            )
            audits = [self._make_audit(
                action="remediation_skipped_duplicate",
                plan=plan,
                result=result,
                actor=actor,
            )]
            return plan, result, audits

        plan = self.plan(incident)
        plan.dry_run = self.dry_run

        audit_planned = self._make_audit(
            action="remediation_planned",
            plan=plan,
            result=None,
            actor=actor,
        )

        result = self.execute(plan)

        audit_result = self._make_audit(
            action="remediation_executed",
            plan=plan,
            result=result,
            actor=actor,
        )

        return plan, result, [audit_planned, audit_result]

    def _execute_live(self, plan: RemediationPlan) -> RemediationResult:
        """
        Safe live execution dispatcher.

        SECURITY: Only calls pre-defined, hardcoded handler methods.
        The action_type has already been validated against the allowlist.
        No shell commands are constructed from plan fields.
        """
        handler_map = {
            RemediationActionType.RESTART_SERVICE: self._action_restart_service,
            RemediationActionType.CLEAR_RETRY_OPERATION: self._action_clear_retry,
        }
        handler = handler_map.get(plan.action_type)
        if handler is None:
            return RemediationResult(
                plan_id=plan.plan_id,
                incident_id=plan.incident_id,
                action_type=plan.action_type,
                status=RemediationStatus.FAILED,
                message=f"No live handler registered for action: {plan.action_type.value}",
                error="handler_not_found",
                dry_run=False,
            )
        try:
            return handler(plan)
        except Exception as exc:
            logger.error(
                "RemediationEngine: live execution failed for action '%s': %s",
                plan.action_type.value,
                exc,
            )
            return RemediationResult(
                plan_id=plan.plan_id,
                incident_id=plan.incident_id,
                action_type=plan.action_type,
                status=RemediationStatus.FAILED,
                message=f"Execution failed: {type(exc).__name__}",
                error=str(exc),
                dry_run=False,
            )

    # ------------------------------------------------------------------
    # Live Action Handlers
    # SECURITY: These methods NEVER construct shell commands from plan
    # fields. They call internal APIs or predefined operations only.
    # ------------------------------------------------------------------

    def _action_restart_service(self, plan: RemediationPlan) -> RemediationResult:
        """
        Predefined safe handler for restart_service.

        In a real deployment this would call an internal service manager
        API (not shell). For this implementation it is stubbed as SUCCESS
        to allow full integration without requiring a live service manager.

        SECURITY: Does NOT execute any shell command. Does NOT use any
        string from plan.incident_title or plan.parameters as a command.
        """
        logger.info(
            "RemediationEngine: restart_service action — stub executed "
            "(no live service manager configured)"
        )
        return RemediationResult(
            plan_id=plan.plan_id,
            incident_id=plan.incident_id,
            action_type=plan.action_type,
            status=RemediationStatus.SUCCESS,
            message=(
                f"Service restart initiated for incident '{plan.incident_title}'. "
                f"(Stub: live service manager not configured.)"
            ),
            dry_run=False,
            output={
                "action": "restart_service",
                "stub": True,
                "note": "Live execution requires service manager integration.",
            },
        )

    def _action_clear_retry(self, plan: RemediationPlan) -> RemediationResult:
        """
        Predefined safe handler for clear_retry_operation.

        Stub implementation. Real deployment would call an internal queue
        management API. No shell commands are used.
        """
        logger.info(
            "RemediationEngine: clear_retry_operation action — stub executed"
        )
        return RemediationResult(
            plan_id=plan.plan_id,
            incident_id=plan.incident_id,
            action_type=plan.action_type,
            status=RemediationStatus.SUCCESS,
            message=(
                f"Operation queue cleared and retry scheduled for incident "
                f"'{plan.incident_title}'. (Stub: queue manager not configured.)"
            ),
            dry_run=False,
            output={
                "action": "clear_retry_operation",
                "stub": True,
                "note": "Live execution requires queue manager integration.",
            },
        )

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _select_action(incident_type: str) -> RemediationActionType:
        """
        Map incident_type to an allowlisted RemediationActionType.

        Falls back to MANUAL_INVESTIGATION_REQUIRED for unknown types.

        SECURITY: Only returns enum values, never constructs action strings
        from input.
        """
        if not incident_type:
            return RemediationActionType.MANUAL_INVESTIGATION_REQUIRED
        return _INCIDENT_TYPE_TO_ACTION.get(
            incident_type, RemediationActionType.MANUAL_INVESTIGATION_REQUIRED
        )

    @staticmethod
    def _make_audit(
        action: str,
        plan: RemediationPlan,
        result: Optional[RemediationResult],
        actor: str,
    ) -> RemediationAuditRecord:
        """Build a RemediationAuditRecord for a plan/result event."""
        details: dict = {
            "action_type": plan.action_type.value,
            "incident_type": plan.incident_type,
            "incident_title": plan.incident_title,
            "dry_run": plan.dry_run,
        }
        if result is not None:
            details["status"] = result.status.value
            details["message"] = result.message
            if result.error:
                details["error"] = result.error

        return RemediationAuditRecord(
            action=action,
            actor=actor,
            resource_type="remediation",
            resource_id=str(plan.plan_id),
            incident_id=plan.incident_id,
            details=details,
        )

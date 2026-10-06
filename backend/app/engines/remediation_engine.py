"""
OpsTrace Backend — Remediation DB Persistence Engine
Phase 8: Remediation

Persists Phase 8 remediation plans, results, and audit events to the
Phase 2 PostgreSQL database models (Remediation, AuditEvent).

Security:
  - Uses RemediationEngine (collector) for action selection.
  - Action types are ONLY taken from RemediationActionType enum.
  - No shell commands are executed from DB-persisted data.
"""

from __future__ import annotations

import logging
import uuid
from datetime import datetime, timezone
from typing import List, Optional

from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session

from backend.app.models.audit_event import AuditEvent
from backend.app.models.incident import Incident
from backend.app.models.remediation import Remediation

from collector.app.detectors.models import IncidentDetectionResult
from collector.app.remediators.remediation_engine import RemediationEngine as _CoreEngine
from collector.app.remediators.models import (
    RemediationBatchResult,
    RemediationPlan,
    RemediationResult,
    RemediationStatus,
)

logger = logging.getLogger(__name__)


class RemediationPersistenceEngine:
    """
    Phase 8 backend service: orchestrates remediation and persists to DB.

    Delegates action selection and execution to the collector-side
    RemediationEngine, then maps results to Phase 2 ORM objects.
    """

    def __init__(self, dry_run: bool = True) -> None:
        self.dry_run = dry_run
        self._core = _CoreEngine(dry_run=dry_run)

    def process_and_persist(
        self,
        db: Session,
        detection_result: IncidentDetectionResult,
        actor: str = "system",
    ) -> RemediationBatchResult:
        """
        Run remediation for a detection result and persist to DB.

        Args:
            db: SQLAlchemy Session.
            detection_result: IncidentDetectionResult from Phase 7.
            actor: Audit actor label.

        Returns:
            RemediationBatchResult — never raises.
        """
        batch = self._core.process(detection_result, actor=actor)

        for plan, result in zip(batch.plans, batch.results):
            try:
                self._persist_one(db, plan, result, actor)
            except Exception as exc:
                logger.error(
                    "RemediationPersistenceEngine: DB persist failed for plan %s: %s",
                    plan.plan_id,
                    exc,
                )
                db.rollback()
                batch.warnings.append(
                    f"DB persist failed for plan {plan.plan_id}: {type(exc).__name__}"
                )

        try:
            db.commit()
        except SQLAlchemyError as exc:
            logger.error("RemediationPersistenceEngine: commit failed: %s", exc)
            db.rollback()
            batch.warnings.append(f"DB commit failed: {type(exc).__name__}")

        return batch

    def _persist_one(
        self,
        db: Session,
        plan: RemediationPlan,
        result: RemediationResult,
        actor: str,
    ) -> None:
        """Persist a single remediation plan + result + audit to the DB.

        The Phase 2 Remediation ORM requires a non-NULL incident_id (FK to
        incidents.id). If the incident does not exist in the DB, we skip the
        Remediation row write and emit only an AuditEvent without a
        remediation_id link. This keeps the engine safe while honoring the
        existing DB schema constraint.
        """
        db_status = result.status.to_db_status()

        # Look up the Incident DB record — required for the NOT NULL FK
        incident_db_id: Optional[uuid.UUID] = None
        if plan.incident_id:
            inc = db.query(Incident).filter(Incident.id == plan.incident_id).first()
            if inc:
                incident_db_id = inc.id

        if incident_db_id is None:
            # Cannot create Remediation row without a valid incident FK.
            # Write an orphan AuditEvent so the decision is still recorded.
            logger.warning(
                "RemediationPersistenceEngine: incident_id %s not found in DB; "
                "skipping Remediation row, writing orphan AuditEvent only.",
                plan.incident_id,
            )
            audit = AuditEvent(
                remediation_id=None,
                action="remediation_skipped_no_db_incident",
                actor=actor,
                resource_type="remediation",
                resource_id=str(plan.plan_id),
                details={
                    "action_type": plan.action_type.value,
                    "incident_type": plan.incident_type,
                    "incident_title": plan.incident_title,
                    "dry_run": plan.dry_run,
                    "status": result.status.value,
                    "message": result.message,
                    "reason": "incident_not_found_in_db",
                },
            )
            db.add(audit)
            db.flush()
            return

        # Create Remediation ORM record
        rem = Remediation(
            id=plan.plan_id,
            incident_id=incident_db_id,
            action_type=plan.action_type.value,
            description=plan.description,
            status=db_status,
            parameters=plan.parameters,
            rationale=plan.rationale,
            requested_by=actor,
            executed_at=(
                result.executed_at
                if result.status in (RemediationStatus.SUCCESS, RemediationStatus.FAILED)
                else None
            ),
            execution_output=result.message if result.message else None,
        )
        db.add(rem)
        db.flush()

        # Create AuditEvent record linked to the Remediation row
        audit = AuditEvent(
            remediation_id=rem.id,
            action="remediation_executed",
            actor=actor,
            resource_type="remediation",
            resource_id=str(rem.id),
            details={
                "action_type": plan.action_type.value,
                "incident_type": plan.incident_type,
                "incident_title": plan.incident_title,
                "dry_run": plan.dry_run,
                "status": result.status.value,
                "message": result.message,
                "error": result.error,
            },
        )
        db.add(audit)
        db.flush()

        # Create AuditEvent record
        audit = AuditEvent(
            remediation_id=rem.id,
            action="remediation_executed",
            actor=actor,
            resource_type="remediation",
            resource_id=str(rem.id),
            details={
                "action_type": plan.action_type.value,
                "incident_type": plan.incident_type,
                "incident_title": plan.incident_title,
                "dry_run": plan.dry_run,
                "status": result.status.value,
                "message": result.message,
                "error": result.error,
            },
        )
        db.add(audit)
        db.flush()

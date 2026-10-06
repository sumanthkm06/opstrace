"""
OpsTrace Backend — Change-Aware Correlation Engine & DB Service
Phase 9: Change-Aware Correlation

Provides database persistence and change correlation analysis by evaluating
PostgreSQL ``Deployment`` and ``ConfigChange`` models against ``Incident`` records.

Design:
  - Explainable & Rule-Based: Uses deterministic scoring rules from ChangeCorrelator.
  - Causation Disclaimer: Explicitly records that correlation does not prove causation.
  - Non-destructive & Audited: Updates correlation foreign keys on Incident and creates
    timeline ``IncidentEvent`` records.
"""

from __future__ import annotations

import logging
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional

from sqlalchemy import or_
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session

from backend.app.models.config_change import ConfigChange as DBConfigChange
from backend.app.models.deployment import Deployment as DBDeployment
from backend.app.models.incident import Incident as DBIncident
from backend.app.models.incident_event import IncidentEvent as DBIncidentEvent
from collector.app.correlators.change_correlator import ChangeCorrelator
from collector.app.correlators.models import (
    CandidateChange,
    ChangeCategory,
    IncidentChangeCorrelation,
)

logger = logging.getLogger(__name__)


class ChangeCorrelationEngine:
    """
    Phase 9 Backend Engine for Change-Aware Correlation.

    Links PostgreSQL ``Deployment`` and ``ConfigChange`` records to ``Incident``
    entities and records correlation timeline events.
    """

    def __init__(
        self,
        lookback_minutes: int = 60,
        min_score_threshold: float = 0.20,
    ) -> None:
        self.lookback_minutes = max(1, lookback_minutes)
        self.min_score_threshold = min_score_threshold
        self.correlator = ChangeCorrelator(
            lookback_minutes=self.lookback_minutes,
            min_score_threshold=self.min_score_threshold,
        )

    def correlate_and_persist_incident(
        self,
        db: Session,
        incident_id: uuid.UUID,
        lookback_minutes: Optional[int] = None,
    ) -> Optional[IncidentChangeCorrelation]:
        """
        Run change correlation for a specific database ``Incident`` and persist results.

        Updates:
          - ``Incident.correlated_deployment_id``
          - ``Incident.correlated_config_change_id``
          - ``Incident.metadata_json["change_correlation"]``
          - Creates ``IncidentEvent`` record of type ``change_correlated``.

        Args:
            db: SQLAlchemy Session.
            incident_id: Target Incident UUID.
            lookback_minutes: Optional override for lookback window.

        Returns:
            IncidentChangeCorrelation or None if incident is not found.
        """
        inc = db.query(DBIncident).filter(DBIncident.id == incident_id).first()
        if not inc:
            logger.warning("Change correlation requested for non-existent Incident ID %s", incident_id)
            return None

        effective_lookback = lookback_minutes or self.lookback_minutes
        det_time = inc.detected_at
        if det_time.tzinfo is None:
            det_time = det_time.replace(tzinfo=timezone.utc)

        start_window = det_time - timedelta(minutes=effective_lookback)
        # Small grace window (2 mins) after incident detection to handle clock drift
        end_window = det_time + timedelta(minutes=2)

        # -------------------------------------------------------------------
        # 1. Fetch candidate deployments from DB
        # -------------------------------------------------------------------
        dep_query = db.query(DBDeployment).filter(
            DBDeployment.deployed_at >= start_window,
            DBDeployment.deployed_at <= end_window,
        )
        if inc.service_id and inc.host_id:
            dep_query = dep_query.filter(
                or_(
                    DBDeployment.service_id == inc.service_id,
                    DBDeployment.host_id == inc.host_id,
                )
            )
        elif inc.host_id:
            dep_query = dep_query.filter(DBDeployment.host_id == inc.host_id)
        elif inc.service_id:
            dep_query = dep_query.filter(DBDeployment.service_id == inc.service_id)

        db_deployments = dep_query.all()

        # -------------------------------------------------------------------
        # 2. Fetch candidate config changes from DB
        # -------------------------------------------------------------------
        cc_query = db.query(DBConfigChange).filter(
            DBConfigChange.changed_at >= start_window,
            DBConfigChange.changed_at <= end_window,
        )
        if inc.service_id and inc.host_id:
            cc_query = cc_query.filter(
                or_(
                    DBConfigChange.service_id == inc.service_id,
                    DBConfigChange.host_id == inc.host_id,
                )
            )
        elif inc.host_id:
            cc_query = cc_query.filter(DBConfigChange.host_id == inc.host_id)
        elif inc.service_id:
            cc_query = cc_query.filter(DBConfigChange.service_id == inc.service_id)

        db_config_changes = cc_query.all()

        # -------------------------------------------------------------------
        # 3. Convert DB ORM records -> CandidateChange Pydantic models
        # -------------------------------------------------------------------
        candidates: List[CandidateChange] = []

        for dep in db_deployments:
            d_time = dep.deployed_at
            if d_time.tzinfo is None:
                d_time = d_time.replace(tzinfo=timezone.utc)

            candidates.append(
                CandidateChange(
                    change_id=dep.id,
                    change_type=ChangeCategory.DEPLOYMENT,
                    timestamp=d_time,
                    service_id=dep.service_id,
                    host_id=dep.host_id,
                    service_name=dep.service.name if dep.service else None,
                    summary=f"Deployment version {dep.version} ({dep.status}) by {dep.deployed_by}",
                    details={
                        "version": dep.version,
                        "status": dep.status,
                        "commit_hash": dep.commit_hash,
                        "release_notes": dep.release_notes,
                        "environment": dep.environment,
                    },
                    diff=dep.release_notes,
                    changed_by=dep.deployed_by,
                )
            )

        for cc in db_config_changes:
            c_time = cc.changed_at
            if c_time.tzinfo is None:
                c_time = c_time.replace(tzinfo=timezone.utc)

            candidates.append(
                CandidateChange(
                    change_id=cc.id,
                    change_type=ChangeCategory.CONFIG_CHANGE,
                    timestamp=c_time,
                    service_id=cc.service_id,
                    host_id=cc.host_id,
                    service_name=cc.service.name if cc.service else None,
                    summary=f"Config change '{cc.config_file_path}' ({cc.change_type}) by {cc.changed_by}",
                    details={
                        "config_file_path": cc.config_file_path,
                        "change_type": cc.change_type,
                        "deployment_id": str(cc.deployment_id) if cc.deployment_id else None,
                        "previous_value": cc.previous_value,
                        "new_value": cc.new_value,
                    },
                    diff=cc.diff,
                    changed_by=cc.changed_by,
                )
            )

        # -------------------------------------------------------------------
        # 4. Run change correlator algorithm
        # -------------------------------------------------------------------
        from collector.app.detectors.models import DetectedIncident, IncidentSeverity

        det_inc = DetectedIncident(
            incident_id=inc.id,
            title=inc.title,
            description=inc.description or "",
            incident_type=str((inc.metadata_json or {}).get("incident_type", "custom_rule")),
            severity=IncidentSeverity.from_db_severity(inc.severity),
            host_id=inc.host_id,
            service_id=inc.service_id,
            first_seen=det_time,
            last_seen=det_time,
        )

        correlator = ChangeCorrelator(
            lookback_minutes=effective_lookback,
            min_score_threshold=self.min_score_threshold,
        )
        result = correlator.correlate_incident(
            incident=det_inc,
            candidate_changes=candidates,
        )

        # -------------------------------------------------------------------
        # 5. Persist correlation updates into DB
        # -------------------------------------------------------------------
        try:
            if result.correlated_deployment_id:
                inc.correlated_deployment_id = result.correlated_deployment_id
            if result.correlated_config_change_id:
                inc.correlated_config_change_id = result.correlated_config_change_id

            # Update metadata_json
            meta = dict(inc.metadata_json or {})
            meta["change_correlation"] = result.model_dump(mode="json")
            inc.metadata_json = meta

            # Add timeline IncidentEvent
            now_utc = datetime.now(timezone.utc)
            if result.primary_suspect:
                primary = result.primary_suspect
                msg = (
                    f"Correlated suspect change: {primary.candidate.summary} "
                    f"(Score: {primary.score:.2f}, Confidence: {primary.confidence.value.upper()})"
                )
            else:
                msg = f"Change correlation evaluated: no suspect changes found within {effective_lookback}m window."

            evt = DBIncidentEvent(
                incident_id=inc.id,
                event_type="change_correlated",
                message=msg,
                payload={
                    "total_evaluated": result.total_candidates_evaluated,
                    "primary_suspect_id": str(result.primary_suspect.candidate.change_id) if result.primary_suspect else None,
                    "primary_score": result.primary_suspect.score if result.primary_suspect else 0.0,
                    "correlated_deployment_id": str(result.correlated_deployment_id) if result.correlated_deployment_id else None,
                    "correlated_config_change_id": str(result.correlated_config_change_id) if result.correlated_config_change_id else None,
                    "correlation_does_not_prove_causation": True,
                },
                timestamp=now_utc,
            )
            db.add(evt)
            db.commit()
            db.refresh(inc)
        except SQLAlchemyError as exc:
            logger.error("Failed to commit change correlation for incident %s: %s", incident_id, exc)
            db.rollback()
            raise

        return result

    def correlate_active_incidents(
        self,
        db: Session,
        host_id: Optional[uuid.UUID] = None,
        lookback_minutes: Optional[int] = None,
    ) -> List[IncidentChangeCorrelation]:
        """
        Run change correlation for all active (open or investigating) database incidents.

        Args:
            db: SQLAlchemy Session.
            host_id: Optional filter for host UUID.
            lookback_minutes: Optional override for lookback window.

        Returns:
            List of IncidentChangeCorrelation results.
        """
        query = db.query(DBIncident).filter(DBIncident.status.in_(["open", "investigating"]))
        if host_id:
            query = query.filter(DBIncident.host_id == host_id)

        active_incidents = query.all()
        results: List[IncidentChangeCorrelation] = []

        for inc in active_incidents:
            try:
                res = self.correlate_and_persist_incident(
                    db=db,
                    incident_id=inc.id,
                    lookback_minutes=lookback_minutes,
                )
                if res:
                    results.append(res)
            except Exception as exc:
                logger.error("Failed to correlate active incident ID %s: %s", inc.id, exc)

        return results

    def get_incident_correlation_summary(
        self,
        db: Session,
        incident_id: uuid.UUID,
    ) -> Optional[Dict[str, Any]]:
        """
        Retrieve structured change correlation summary for an incident from DB.
        """
        inc = db.query(DBIncident).filter(DBIncident.id == incident_id).first()
        if not inc:
            return None

        meta = inc.metadata_json or {}
        corr_data = meta.get("change_correlation")

        dep_info = None
        if inc.correlated_deployment:
            dep = inc.correlated_deployment
            dep_info = {
                "id": str(dep.id),
                "version": dep.version,
                "status": dep.status,
                "deployed_by": dep.deployed_by,
                "deployed_at": dep.deployed_at.isoformat() if dep.deployed_at else None,
            }

        cc_info = None
        if inc.correlated_config_change:
            cc = inc.correlated_config_change
            cc_info = {
                "id": str(cc.id),
                "config_file_path": cc.config_file_path,
                "change_type": cc.change_type,
                "changed_by": cc.changed_by,
                "diff": cc.diff,
                "changed_at": cc.changed_at.isoformat() if cc.changed_at else None,
            }

        return {
            "incident_id": str(inc.id),
            "incident_title": inc.title,
            "detected_at": inc.detected_at.isoformat() if inc.detected_at else None,
            "correlated_deployment": dep_info,
            "correlated_config_change": cc_info,
            "correlation_details": corr_data,
            "causation_disclaimer": "Correlation indicates temporal/spatial proximity. Correlation does not prove causation.",
            "correlation_does_not_prove_causation": True,
        }

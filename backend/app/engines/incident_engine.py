"""
OpsTrace Backend — Incident Engine & DB Sync Service
Phase 7: Incident Detection & Incident Correlation

Provides persistence and correlation logic for syncing Phase 7 detection results
with the existing Phase 2 PostgreSQL database models (``Incident`` and ``IncidentEvent``).
"""

from __future__ import annotations

import logging
import uuid
from datetime import datetime, timezone
from typing import List, Optional

from sqlalchemy import or_
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session

from backend.app.models.incident import Incident
from backend.app.models.incident_event import IncidentEvent
from collector.app.detectors.models import (
    DetectedIncident,
    IncidentDetectionResult,
    IncidentSeverity,
)

logger = logging.getLogger(__name__)

# Severity hierarchy for escalation check
_SEVERITY_RANK = {
    "low": 1,
    "medium": 2,
    "high": 3,
    "critical": 4,
}


class IncidentEngine:
    """
    Phase 7 incident persistence and active incident correlation engine.

    Syncs ``DetectedIncident`` outputs with PostgreSQL ``Incident`` and
    ``IncidentEvent`` database tables.
    """

    def process_and_persist(
        self,
        db: Session,
        detection_result: IncidentDetectionResult,
        host_id: uuid.UUID,
        service_id: Optional[uuid.UUID] = None,
    ) -> List[Incident]:
        """
        Persist a batch of detected incidents into the database.

        Correlates recurring detections with active database incidents to avoid duplicate
        active incidents for the same underlying problem.

        Args:
            db: SQLAlchemy Session.
            detection_result: IncidentDetectionResult output from IncidentDetector.
            host_id: Target Host UUID.
            service_id: Optional target Service UUID.

        Returns:
            List of updated or newly created Incident ORM objects.
        """
        if not detection_result or not detection_result.incidents:
            return []

        persisted: List[Incident] = []

        for detected in detection_result.incidents:
            try:
                inc = self.sync_incident(
                    db=db,
                    detected=detected,
                    host_id=host_id,
                    service_id=service_id,
                )
                if inc:
                    persisted.append(inc)
            except Exception as exc:
                logger.error("Failed to sync detected incident '%s': %s", detected.title, exc)
                db.rollback()

        try:
            db.commit()
        except SQLAlchemyError as exc:
            logger.error("Failed to commit incident batch: %s", exc)
            db.rollback()

        return persisted

    def sync_incident(
        self,
        db: Session,
        detected: DetectedIncident,
        host_id: uuid.UUID,
        service_id: Optional[uuid.UUID] = None,
    ) -> Incident:
        """
        Sync a single ``DetectedIncident`` with DB.

        If an active incident matching the problem exists, update and correlate with it.
        Otherwise create a new ``Incident`` and initial ``IncidentEvent`` records.
        """
        effective_service_id = service_id or detected.service_id

        # Find candidate active incidents for the same host
        active_incidents = (
            db.query(Incident)
            .filter(
                Incident.host_id == host_id,
                Incident.status.in_(["open", "investigating"]),
            )
            .all()
        )

        matching_active: Optional[Incident] = None
        for candidate in active_incidents:
            if self._is_same_underlying_problem(candidate, detected, effective_service_id):
                matching_active = candidate
                break

        now_utc = datetime.now(timezone.utc)

        if matching_active:
            # -------------------------------------------------------------
            # CORRELATE with existing active incident
            # -------------------------------------------------------------
            logger.info(
                "Correlating detected incident '%s' with active DB Incident ID %s",
                detected.title,
                matching_active.id,
            )

            # Escalate severity if newly detected severity is higher
            new_db_sev = detected.db_severity
            current_rank = _SEVERITY_RANK.get(matching_active.severity, 1)
            new_rank = _SEVERITY_RANK.get(new_db_sev, 1)
            if new_rank > current_rank:
                matching_active.severity = new_db_sev

            # Update metadata_json
            meta = dict(matching_active.metadata_json or {})
            meta["last_seen"] = (
                detected.last_seen.isoformat() if detected.last_seen else now_utc.isoformat()
            )

            existing_fps = set(meta.get("related_fingerprints", []))
            for fp in detected.related_fingerprints:
                if fp:
                    existing_fps.add(fp)
            meta["related_fingerprints"] = list(existing_fps)
            meta["correlation_count"] = meta.get("correlation_count", 1) + 1
            matching_active.metadata_json = meta

            # Add timeline event
            update_evt = IncidentEvent(
                incident_id=matching_active.id,
                event_type="correlation_update",
                message=f"Correlated recurring events for incident '{detected.title}'",
                payload={
                    "incident_type": detected.incident_type,
                    "evidence_count": len(detected.evidence),
                    "severity": detected.severity.value,
                    "last_seen": meta["last_seen"],
                },
                timestamp=detected.last_seen or now_utc,
            )
            db.add(update_evt)
            db.flush()

            return matching_active

        else:
            # -------------------------------------------------------------
            # CREATE new Incident DB record
            # -------------------------------------------------------------
            logger.info("Creating new DB Incident for detected '%s'", detected.title)

            det_ts = detected.first_seen or now_utc
            if det_ts.tzinfo is None:
                det_ts = det_ts.replace(tzinfo=timezone.utc)

            last_ts = detected.last_seen or det_ts
            if last_ts.tzinfo is None:
                last_ts = last_ts.replace(tzinfo=timezone.utc)

            meta = {
                "incident_type": detected.incident_type,
                "first_seen": det_ts.isoformat(),
                "last_seen": last_ts.isoformat(),
                "related_fingerprints": detected.related_fingerprints,
                "metadata": detected.metadata,
                "correlation_count": 1,
            }

            inc = Incident(
                id=detected.incident_id or uuid.uuid4(),
                title=detected.title[:255],
                description=detected.description,
                status=detected.status if detected.status in (
                    "open", "investigating", "mitigated", "resolved", "closed"
                ) else "open",
                severity=detected.db_severity,
                host_id=host_id,
                service_id=effective_service_id,
                detected_at=det_ts,
                metadata_json=meta,
            )
            db.add(inc)
            db.flush()

            # Create primary detection event
            detect_evt = IncidentEvent(
                incident_id=inc.id,
                event_type="incident_detected",
                message=f"Incident detected: {detected.title}",
                payload={
                    "incident_type": detected.incident_type,
                    "severity": detected.severity.value,
                    "evidence_count": len(detected.evidence),
                },
                timestamp=det_ts,
            )
            db.add(detect_evt)

            # Create individual evidence timeline events
            for ev in detected.evidence:
                ev_ts = ev.timestamp or det_ts
                if ev_ts.tzinfo is None:
                    ev_ts = ev_ts.replace(tzinfo=timezone.utc)

                evt = IncidentEvent(
                    incident_id=inc.id,
                    event_type=ev.event_type or "evidence",
                    message=ev.message or "Evidence log event",
                    payload={
                        "fingerprint": ev.fingerprint,
                        "source": ev.source,
                        "details": ev.details,
                    },
                    timestamp=ev_ts,
                )
                db.add(evt)

            db.flush()
            return inc

    def _is_same_underlying_problem(
        self,
        existing: Incident,
        detected: DetectedIncident,
        service_id: Optional[uuid.UUID],
    ) -> bool:
        """Determine if a detected incident represents the same underlying problem as an active DB incident."""
        meta = existing.metadata_json or {}
        existing_fps = set(meta.get("related_fingerprints", []))
        detected_fps = set(detected.related_fingerprints)

        # 1. Matching fingerprints
        if existing_fps and detected_fps and bool(existing_fps.intersection(detected_fps)):
            return True

        # 2. Matching service ID and incident type
        if (
            service_id
            and existing.service_id == service_id
            and meta.get("incident_type") == detected.incident_type
        ):
            return True

        # 3. Matching exact title
        if existing.title == detected.title[:255]:
            return True

        return False

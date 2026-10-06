"""
OpsTrace Backend — Incident Timeline & Replay Engine
Phase 10: Incident Timeline & Replay

Reconstructs and explains the complete chronological lifecycle of an incident
from stored database events (IncidentEvent, Deployment, ConfigChange, Remediation).

Key Architecture Guarantees:
  1. Observation & Reconstruction: Never invents events or modifies historical records.
  2. Non-causal Attribution: Preserves Phase 9 guarantee that correlation != causation.
  3. Strictly Read-Only: Replay never executes shell commands, remediation, or DB writes.
  4. Deterministic Ordering: Events are sorted by (timestamp asc, source_rank, event_id/id).
"""

from __future__ import annotations

import logging
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

from sqlalchemy.orm import Session

from backend.app.models.audit_event import AuditEvent as DBAuditEvent
from backend.app.models.config_change import ConfigChange as DBConfigChange
from backend.app.models.deployment import Deployment as DBDeployment
from backend.app.models.incident import Incident as DBIncident
from backend.app.models.incident_event import IncidentEvent as DBIncidentEvent
from backend.app.models.remediation import Remediation as DBRemediation
from backend.app.schemas.timeline import (
    IncidentReplayResult,
    IncidentReplaySnapshot,
    IncidentTimeline,
    IncidentTimelineEvent,
    IncidentTimelineSummary,
)

logger = logging.getLogger(__name__)


# Source priority order for secondary sorting when timestamps are identical
_SOURCE_PRIORITY = {
    "deployment": 1,
    "config_change": 2,
    "incident_event": 3,
    "remediation": 4,
    "audit_event": 5,
}


class TimelineEngine:
    """
    Backend engine for building incident timelines, deterministic replay snapshots,
    and structured timeline summaries.
    """

    def build_timeline(
        self,
        db: Session,
        incident_id: uuid.UUID,
    ) -> Optional[IncidentTimeline]:
        """
        Reconstruct the chronological timeline for an incident.

        Args:
            db: SQLAlchemy Session.
            incident_id: Target Incident UUID.

        Returns:
            IncidentTimeline or None if incident does not exist.
        """
        inc = db.query(DBIncident).filter(DBIncident.id == incident_id).first()
        if not inc:
            logger.warning("Timeline requested for non-existent Incident ID %s", incident_id)
            return None

        # -------------------------------------------------------------------
        # 1. Load primary IncidentEvent DB records
        # -------------------------------------------------------------------
        db_events = (
            db.query(DBIncidentEvent)
            .filter(DBIncidentEvent.incident_id == incident_id)
            .all()
        )

        raw_events: List[Tuple[datetime, int, str, IncidentTimelineEvent]] = []

        # Convert IncidentEvent DB rows -> IncidentTimelineEvent
        for evt in db_events:
            ts = evt.timestamp
            if ts.tzinfo is None:
                ts = ts.replace(tzinfo=timezone.utc)

            payload = evt.payload or {}
            severity = payload.get("severity") or inc.severity

            item = IncidentTimelineEvent(
                event_id=evt.id,
                incident_id=inc.id,
                sequence=0,  # assigned after sorting
                event_type=evt.event_type,
                timestamp=ts,
                severity=severity,
                message=evt.message,
                source="incident_event",
                metadata=payload,
            )
            raw_events.append((ts, _SOURCE_PRIORITY.get("incident_event", 3), str(evt.id), item))

        # -------------------------------------------------------------------
        # 2. Check for correlated Deployment change event if not already present
        # -------------------------------------------------------------------
        if inc.correlated_deployment:
            dep = inc.correlated_deployment
            dep_ts = dep.deployed_at
            if dep_ts.tzinfo is None:
                dep_ts = dep_ts.replace(tzinfo=timezone.utc)

            # Avoid duplication if already in incident_events
            dep_msg = f"Candidate deployment version '{dep.version}' ({dep.status}) by {dep.deployed_by}"
            if not any(e[3].metadata.get("correlated_deployment_id") == str(dep.id) for e in raw_events):
                item = IncidentTimelineEvent(
                    event_id=dep.id,
                    incident_id=inc.id,
                    sequence=0,
                    event_type="deployment_recorded",
                    timestamp=dep_ts,
                    severity="low",
                    message=f"Correlated candidate deployment: version {dep.version} ({dep.status})",
                    source="deployment",
                    metadata={
                        "deployment_id": str(dep.id),
                        "version": dep.version,
                        "status": dep.status,
                        "deployed_by": dep.deployed_by,
                        "commit_hash": dep.commit_hash,
                        "correlation_note": "Candidate contributing change. Correlation does not prove causation.",
                    },
                )
                raw_events.append((dep_ts, _SOURCE_PRIORITY.get("deployment", 1), str(dep.id), item))

        # -------------------------------------------------------------------
        # 3. Check for correlated ConfigChange event if not already present
        # -------------------------------------------------------------------
        if inc.correlated_config_change:
            cc = inc.correlated_config_change
            cc_ts = cc.changed_at
            if cc_ts.tzinfo is None:
                cc_ts = cc_ts.replace(tzinfo=timezone.utc)

            if not any(e[3].metadata.get("correlated_config_change_id") == str(cc.id) for e in raw_events):
                item = IncidentTimelineEvent(
                    event_id=cc.id,
                    incident_id=inc.id,
                    sequence=0,
                    event_type="config_change_recorded",
                    timestamp=cc_ts,
                    severity="medium",
                    message=f"Correlated candidate configuration change: '{cc.config_file_path}' ({cc.change_type})",
                    source="config_change",
                    metadata={
                        "config_change_id": str(cc.id),
                        "config_file_path": cc.config_file_path,
                        "change_type": cc.change_type,
                        "changed_by": cc.changed_by,
                        "diff": cc.diff,
                        "correlation_note": "Candidate contributing change. Correlation does not prove causation.",
                    },
                )
                raw_events.append((cc_ts, _SOURCE_PRIORITY.get("config_change", 2), str(cc.id), item))

        # -------------------------------------------------------------------
        # 4. Include Phase 8 Remediation records
        # -------------------------------------------------------------------
        remediations = db.query(DBRemediation).filter(DBRemediation.incident_id == incident_id).all()
        for rem in remediations:
            r_ts = rem.executed_at or rem.created_at
            if r_ts is None:
                r_ts = datetime.now(timezone.utc)
            elif r_ts.tzinfo is None:
                r_ts = r_ts.replace(tzinfo=timezone.utc)

            # Check if remediation event is already in timeline events
            if not any(str(e[3].event_id) == str(rem.id) for e in raw_events):
                item = IncidentTimelineEvent(
                    event_id=rem.id,
                    incident_id=inc.id,
                    sequence=0,
                    event_type=f"remediation_{rem.status}",
                    timestamp=r_ts,
                    severity=inc.severity,
                    message=f"Remediation action '{rem.action_type}': status={rem.status}",
                    source="remediation",
                    metadata={
                        "remediation_id": str(rem.id),
                        "action_type": rem.action_type,
                        "status": rem.status,
                        "description": rem.description,
                        "requested_by": rem.requested_by,
                    },
                )
                raw_events.append((r_ts, _SOURCE_PRIORITY.get("remediation", 4), str(rem.id), item))

        # -------------------------------------------------------------------
        # 5. Deterministic Chronological Sorting
        # Primary: timestamp asc
        # Secondary: source priority rank asc
        # Tertiary: event_id / UUID string asc
        # -------------------------------------------------------------------
        raw_events.sort(key=lambda x: (x[0], x[1], x[2]))

        final_events: List[IncidentTimelineEvent] = []
        for idx, (_, _, _, evt_item) in enumerate(raw_events, start=1):
            evt_item.sequence = idx
            final_events.append(evt_item)

        # Timestamps calculations
        det_time = inc.detected_at
        if det_time.tzinfo is None:
            det_time = det_time.replace(tzinfo=timezone.utc)

        started_at = final_events[0].timestamp if final_events else det_time
        res_time = inc.resolved_at
        if res_time and res_time.tzinfo is None:
            res_time = res_time.replace(tzinfo=timezone.utc)

        last_time = final_events[-1].timestamp if final_events else det_time
        end_time = res_time or last_time

        duration_sec = round((end_time - started_at).total_seconds(), 2)
        if duration_sec < 0.0:
            duration_sec = 0.0

        summary_msg = (
            f"Incident '{inc.title}' ({inc.severity.upper()}) detected at {det_time.isoformat()}. "
            f"Status: {inc.status}. Reconstructed timeline contains {len(final_events)} events "
            f"spanning {duration_sec}s."
        )

        return IncidentTimeline(
            incident_id=inc.id,
            incident_title=inc.title,
            status=inc.status,
            severity=inc.severity,
            host_id=inc.host_id,
            service_id=inc.service_id,
            started_at=started_at,
            resolved_at=res_time,
            duration_seconds=duration_sec,
            total_events=len(final_events),
            events=final_events,
            summary=summary_msg,
        )

    def replay_incident(
        self,
        db: Session,
        incident_id: uuid.UUID,
    ) -> Optional[IncidentReplayResult]:
        """
        Reconstruct a deterministic, step-by-step replay of an incident lifecycle.

        READ-ONLY GUARANTEE: Never mutates DB records, never runs remediations or commands.

        Args:
            db: SQLAlchemy Session.
            incident_id: Target Incident UUID.

        Returns:
            IncidentReplayResult with step-by-step state snapshots.
        """
        timeline = self.build_timeline(db, incident_id)
        if not timeline:
            return None

        snapshots: List[IncidentReplaySnapshot] = []

        curr_severity = timeline.severity
        curr_status = "open"
        known_changes: List[Dict[str, Any]] = []
        known_remediations: List[Dict[str, Any]] = []

        for idx, evt in enumerate(timeline.events, start=1):
            # Track status & severity state changes
            if evt.severity and evt.severity in ("critical", "high", "medium", "low"):
                curr_severity = evt.severity

            if evt.event_type in ("incident_detected", "incident_escalated", "correlation_update"):
                if evt.metadata.get("severity"):
                    curr_severity = str(evt.metadata["severity"]).lower()
            elif evt.event_type in ("incident_mitigated", "mitigated"):
                curr_status = "mitigated"
            elif evt.event_type in ("incident_resolved", "resolved"):
                curr_status = "resolved"
            elif evt.event_type in ("incident_closed", "closed"):
                curr_status = "closed"

            # Track known candidate changes up to this step
            if evt.source in ("deployment", "config_change") or evt.event_type == "change_correlated":
                change_data = {
                    "event_type": evt.event_type,
                    "source": evt.source,
                    "timestamp": evt.timestamp.isoformat(),
                    "summary": evt.message,
                    "metadata": evt.metadata,
                    "disclaimer": "Candidate contributing change. Correlation does not prove causation.",
                }
                known_changes.append(change_data)

            # Track known remediations up to this step
            if evt.source == "remediation" or evt.event_type.startswith("remediation_"):
                rem_data = {
                    "event_type": evt.event_type,
                    "timestamp": evt.timestamp.isoformat(),
                    "summary": evt.message,
                    "metadata": evt.metadata,
                }
                known_remediations.append(rem_data)

            state_desc = (
                f"Step {idx}/{len(timeline.events)} [{evt.event_type}]: {evt.message} "
                f"(Reconstructed State: status={curr_status}, severity={curr_severity})"
            )

            snapshot = IncidentReplaySnapshot(
                step=idx,
                incident_id=timeline.incident_id,
                replay_timestamp=evt.timestamp,
                event_type=evt.event_type,
                event_description=evt.message,
                observed_severity=curr_severity,
                observed_status=curr_status,
                correlated_changes_known=list(known_changes),
                remediations_known=list(known_remediations),
                state_summary=state_desc,
                is_reconstructed_state=True,
            )
            snapshots.append(snapshot)

        return IncidentReplayResult(
            incident_id=timeline.incident_id,
            total_steps=len(snapshots),
            snapshots=snapshots,
            final_status=curr_status if snapshots else timeline.status,
            final_severity=curr_severity if snapshots else timeline.severity,
        )

    def get_timeline_summary(
        self,
        db: Session,
        incident_id: uuid.UUID,
    ) -> Optional[IncidentTimelineSummary]:
        """
        Generate a compact structured summary of an incident timeline.
        """
        inc = db.query(DBIncident).filter(DBIncident.id == incident_id).first()
        if not inc:
            return None

        timeline = self.build_timeline(db, incident_id)
        if not timeline:
            return None

        # Build severity transitions
        severity_transitions: List[Dict[str, Any]] = []
        prev_sev: Optional[str] = None
        for evt in timeline.events:
            sev = evt.severity
            if evt.metadata.get("severity"):
                sev = str(evt.metadata["severity"]).lower()

            if prev_sev is not None and sev and sev != prev_sev:
                severity_transitions.append(
                    {
                        "from_severity": prev_sev,
                        "to_severity": sev,
                        "timestamp": evt.timestamp.isoformat(),
                        "trigger_event": evt.event_type,
                    }
                )
            if sev:
                prev_sev = sev

        # Extract Phase 9 candidate contributing changes
        candidate_changes: List[Dict[str, Any]] = []
        meta = inc.metadata_json or {}
        corr_meta = meta.get("change_correlation")
        if corr_meta:
            primary = corr_meta.get("primary_suspect")
            if primary:
                cand = primary.get("candidate", {})
                candidate_changes.append(
                    {
                        "change_id": cand.get("change_id"),
                        "change_type": cand.get("change_type"),
                        "summary": cand.get("summary"),
                        "score": primary.get("score"),
                        "confidence": primary.get("confidence"),
                        "is_primary_suspect": True,
                        "attribution_note": (
                            "Candidate contributing change with "
                            f"{str(primary.get('confidence')).upper()} correlation confidence. "
                            "Correlation does not prove causation."
                        ),
                    }
                )

        if not candidate_changes:
            if inc.correlated_deployment:
                dep = inc.correlated_deployment
                candidate_changes.append(
                    {
                        "change_id": str(dep.id),
                        "change_type": "deployment",
                        "summary": f"Deployment version {dep.version} ({dep.status})",
                        "attribution_note": "Correlated candidate deployment. Correlation does not prove causation.",
                    }
                )
            if inc.correlated_config_change:
                cc = inc.correlated_config_change
                candidate_changes.append(
                    {
                        "change_id": str(cc.id),
                        "change_type": "config_change",
                        "summary": f"Config change '{cc.config_file_path}'",
                        "attribution_note": "Correlated candidate config change. Correlation does not prove causation.",
                    }
                )

        # Extract Phase 8 remediation summary
        remediation_summary: List[Dict[str, Any]] = []
        remediations = db.query(DBRemediation).filter(DBRemediation.incident_id == incident_id).all()
        for rem in remediations:
            remediation_summary.append(
                {
                    "remediation_id": str(rem.id),
                    "action_type": rem.action_type,
                    "status": rem.status,
                    "requested_by": rem.requested_by,
                    "executed_at": rem.executed_at.isoformat() if rem.executed_at else None,
                }
            )

        inc_type = meta.get("incident_type", "custom_rule")

        first_obs = timeline.started_at
        last_obs = timeline.events[-1].timestamp if timeline.events else timeline.started_at
        duration = round((last_obs - first_obs).total_seconds(), 2)

        return IncidentTimelineSummary(
            incident_id=inc.id,
            incident_type=inc_type,
            current_status=inc.status,
            current_severity=inc.severity,
            first_observed_at=first_obs,
            last_observed_at=last_obs,
            duration_seconds=max(0.0, duration),
            total_events=timeline.total_events,
            severity_transitions=severity_transitions,
            candidate_contributing_changes=candidate_changes,
            remediation_summary=remediation_summary,
            final_state=f"Status: {inc.status}, Severity: {inc.severity}, Events: {timeline.total_events}",
        )

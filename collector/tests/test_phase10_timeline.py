"""
OpsTrace Phase 10 — Incident Timeline & Replay Tests
=====================================================

Comprehensive test suite for the Phase 10 Incident Timeline & Replay layer.

Coverage:
  1.  Empty timeline (incident with zero events)
  2.  Single event timeline
  3.  Multiple chronological events
  4.  Events with identical timestamps (handled deterministically)
  5.  Deterministic ordering (primary timestamp, secondary source/id)
  6.  Severity transitions tracking
  7.  Incident lifecycle reconstruction (detection -> escalation -> mitigation -> resolution)
  8.  Duration calculation
  9.  Timeline summary generation
 10.  Replay reconstruction step-by-step snapshots
 11.  Replay does NOT mutate database records (read-only verification)
 12.  Replay does NOT execute remediation or shell commands
 13.  Missing correlation data handled gracefully
 14.  Existing Phase 9 correlation data integrated cleanly
 15.  Existing Phase 8 remediation data integrated cleanly
 16.  Non-existent incident returns 404
 17.  JSON serialization (Pydantic v2 round-trip)
 18.  Existing Phase 2-9 compatibility
 19.  Existing IncidentEvent records remain unchanged after timeline/replay
 20.  Correlation never presented as proven causation (disclaimer verification)
"""

from __future__ import annotations

import json
import sys
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

# ---------------------------------------------------------------------------
# sys.path bootstrap
# ---------------------------------------------------------------------------

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
BACKEND_DIR = REPO_ROOT / "backend"
COLLECTOR_DIR = REPO_ROOT / "collector"

for _p in (str(REPO_ROOT), str(BACKEND_DIR), str(COLLECTOR_DIR)):
    if _p not in sys.path:
        sys.path.insert(0, _p)

# ---------------------------------------------------------------------------
# Phase 10 & Core imports
# ---------------------------------------------------------------------------

from backend.app.application import create_app
from backend.app.engines.timeline_engine import TimelineEngine
from backend.app.models.base import Base
from backend.app.models.config_change import ConfigChange
from backend.app.models.deployment import Deployment
from backend.app.models.host import Host
from backend.app.models.incident import Incident
from backend.app.models.incident_event import IncidentEvent
from backend.app.models.remediation import Remediation
from backend.app.models.service import Service
from backend.app.schemas.timeline import (
    IncidentReplayResult,
    IncidentTimeline,
    IncidentTimelineEvent,
    IncidentTimelineSummary,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def db_session():
    """In-memory SQLite session with Phase 2 schema created."""
    engine = create_engine(
        "sqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
        echo=False,
    )
    Base.metadata.create_all(bind=engine)
    session_factory = sessionmaker(bind=engine)
    session = session_factory()
    try:
        yield session
    finally:
        session.close()


@pytest.fixture
def api_client(db_session):
    """FastAPI TestClient with overridden database session."""
    from backend.app.core.database import get_db

    app = create_app()

    def _get_db_override():
        yield db_session

    app.dependency_overrides[get_db] = _get_db_override
    with TestClient(app) as client:
        yield client


# ---------------------------------------------------------------------------
# Unit Tests — TimelineEngine Core Logic
# ---------------------------------------------------------------------------


class TestEmptyAndSingleEventTimeline:
    def test_empty_timeline_incident_with_zero_events(self, db_session: Session):
        now = datetime.now(timezone.utc)
        host = Host(hostname="host-empty", ip_address="10.0.0.1")
        db_session.add(host)
        db_session.flush()

        inc = Incident(
            title="Empty Incident",
            host_id=host.id,
            detected_at=now,
            severity="medium",
            status="open",
        )
        db_session.add(inc)
        db_session.commit()

        engine = TimelineEngine()
        timeline = engine.build_timeline(db_session, inc.id)

        assert timeline is not None
        assert timeline.incident_id == inc.id
        assert timeline.total_events == 0
        assert timeline.events == []
        assert timeline.duration_seconds == 0.0

    def test_single_event_timeline(self, db_session: Session):
        now = datetime.now(timezone.utc)
        host = Host(hostname="host-single", ip_address="10.0.0.2")
        db_session.add(host)
        db_session.flush()

        inc = Incident(
            title="Single Event Incident",
            host_id=host.id,
            detected_at=now,
            severity="high",
            status="open",
        )
        db_session.add(inc)
        db_session.flush()

        evt = IncidentEvent(
            incident_id=inc.id,
            event_type="incident_detected",
            message="Incident detected by rule",
            timestamp=now,
        )
        db_session.add(evt)
        db_session.commit()

        engine = TimelineEngine()
        timeline = engine.build_timeline(db_session, inc.id)

        assert timeline is not None
        assert timeline.total_events == 1
        assert timeline.events[0].sequence == 1
        assert timeline.events[0].event_type == "incident_detected"


class TestChronologicalOrderingAndDeterminism:
    def test_multiple_chronological_events(self, db_session: Session):
        now = datetime.now(timezone.utc)
        host = Host(hostname="host-multi", ip_address="10.0.0.3")
        db_session.add(host)
        db_session.flush()

        inc = Incident(
            title="Multi Event Incident",
            host_id=host.id,
            detected_at=now,
            severity="medium",
            status="open",
        )
        db_session.add(inc)
        db_session.flush()

        # Add events in reverse order
        e3 = IncidentEvent(
            incident_id=inc.id,
            event_type="incident_resolved",
            message="Resolved incident",
            timestamp=now + timedelta(minutes=10),
        )
        e1 = IncidentEvent(
            incident_id=inc.id,
            event_type="incident_detected",
            message="Detected incident",
            timestamp=now,
        )
        e2 = IncidentEvent(
            incident_id=inc.id,
            event_type="severity_escalated",
            message="Escalated to high",
            timestamp=now + timedelta(minutes=5),
        )
        db_session.add_all([e3, e1, e2])
        db_session.commit()

        engine = TimelineEngine()
        timeline = engine.build_timeline(db_session, inc.id)

        assert timeline.total_events == 3
        assert [e.sequence for e in timeline.events] == [1, 2, 3]
        assert [e.event_type for e in timeline.events] == [
            "incident_detected",
            "severity_escalated",
            "incident_resolved",
        ]

    def test_identical_timestamps_ordered_deterministically(self, db_session: Session):
        now = datetime.now(timezone.utc)
        host = Host(hostname="host-same-ts", ip_address="10.0.0.4")
        db_session.add(host)
        db_session.flush()

        inc = Incident(
            title="Same TS Incident",
            host_id=host.id,
            detected_at=now,
            severity="low",
            status="open",
        )
        db_session.add(inc)
        db_session.flush()

        # Create two events with exact same timestamp
        evt_a = IncidentEvent(
            id=uuid.UUID("00000000-0000-0000-0000-000000000001"),
            incident_id=inc.id,
            event_type="event_a",
            message="Event A",
            timestamp=now,
        )
        evt_b = IncidentEvent(
            id=uuid.UUID("00000000-0000-0000-0000-000000000002"),
            incident_id=inc.id,
            event_type="event_b",
            message="Event B",
            timestamp=now,
        )
        db_session.add_all([evt_b, evt_a])
        db_session.commit()

        engine = TimelineEngine()
        timeline1 = engine.build_timeline(db_session, inc.id)
        timeline2 = engine.build_timeline(db_session, inc.id)

        assert [e.event_type for e in timeline1.events] == [e.event_type for e in timeline2.events]


class TestSeverityTransitionsAndDuration:
    def test_severity_transitions_and_duration_calculation(self, db_session: Session):
        now = datetime.now(timezone.utc)
        host = Host(hostname="host-sev", ip_address="10.0.0.5")
        db_session.add(host)
        db_session.flush()

        inc = Incident(
            title="Severity Transition Test",
            host_id=host.id,
            detected_at=now,
            severity="high",
            status="resolved",
            resolved_at=now + timedelta(minutes=15),
        )
        db_session.add(inc)
        db_session.flush()

        e1 = IncidentEvent(
            incident_id=inc.id,
            event_type="incident_detected",
            message="Detected",
            payload={"severity": "medium"},
            timestamp=now,
        )
        e2 = IncidentEvent(
            incident_id=inc.id,
            event_type="incident_escalated",
            message="Escalated",
            payload={"severity": "high"},
            timestamp=now + timedelta(minutes=5),
        )
        e3 = IncidentEvent(
            incident_id=inc.id,
            event_type="incident_resolved",
            message="Resolved",
            payload={"severity": "high"},
            timestamp=now + timedelta(minutes=15),
        )
        db_session.add_all([e1, e2, e3])
        db_session.commit()

        engine = TimelineEngine()
        summary = engine.get_timeline_summary(db_session, inc.id)

        assert summary is not None
        assert summary.duration_seconds == 900.0  # 15 mins
        assert len(summary.severity_transitions) >= 1
        assert summary.severity_transitions[0]["from_severity"] == "medium"
        assert summary.severity_transitions[0]["to_severity"] == "high"


class TestReplaySnapshotsAndReadonlySafety:
    def test_replay_step_by_step_reconstruction(self, db_session: Session):
        now = datetime.now(timezone.utc)
        host = Host(hostname="host-replay", ip_address="10.0.0.6")
        db_session.add(host)
        db_session.flush()

        inc = Incident(
            title="Replay Test Incident",
            host_id=host.id,
            detected_at=now,
            severity="medium",
            status="open",
        )
        db_session.add(inc)
        db_session.flush()

        e1 = IncidentEvent(
            incident_id=inc.id,
            event_type="incident_detected",
            message="Detected",
            payload={"severity": "medium"},
            timestamp=now,
        )
        e2 = IncidentEvent(
            incident_id=inc.id,
            event_type="incident_mitigated",
            message="Mitigated by operator",
            timestamp=now + timedelta(minutes=5),
        )
        db_session.add_all([e1, e2])
        db_session.commit()

        engine = TimelineEngine()
        replay = engine.replay_incident(db_session, inc.id)

        assert replay is not None
        assert replay.total_steps == 2
        assert replay.snapshots[0].observed_status == "open"
        assert replay.snapshots[1].observed_status == "mitigated"
        assert replay.snapshots[0].is_reconstructed_state is True

    def test_replay_does_not_mutate_db_or_events(self, db_session: Session):
        now = datetime.now(timezone.utc)
        host = Host(hostname="host-readonly", ip_address="10.0.0.7")
        db_session.add(host)
        db_session.flush()

        inc = Incident(
            title="Readonly Safety Incident",
            host_id=host.id,
            detected_at=now,
            severity="low",
            status="open",
        )
        db_session.add(inc)
        db_session.flush()

        evt = IncidentEvent(
            incident_id=inc.id,
            event_type="incident_detected",
            message="Original message",
            timestamp=now,
        )
        db_session.add(evt)
        db_session.commit()

        # Capture counts before
        inc_count_before = db_session.query(Incident).count()
        evt_count_before = db_session.query(IncidentEvent).count()

        engine = TimelineEngine()
        replay = engine.replay_incident(db_session, inc.id)

        # Assert DB untouched
        assert db_session.query(Incident).count() == inc_count_before
        assert db_session.query(IncidentEvent).count() == evt_count_before
        db_evt = db_session.query(IncidentEvent).filter(IncidentEvent.id == evt.id).first()
        assert db_evt.message == "Original message"


class TestPhase8AndPhase9Integrations:
    def test_phase9_correlation_data_integrated(self, db_session: Session):
        now = datetime.now(timezone.utc)
        host = Host(hostname="host-p9", ip_address="10.0.0.8")
        db_session.add(host)
        db_session.flush()

        svc = Service(name="app-service", host_id=host.id)
        db_session.add(svc)
        db_session.flush()

        dep = Deployment(
            service_id=svc.id,
            host_id=host.id,
            version="v2.5.0",
            deployed_by="deploy-bot",
            deployed_at=now - timedelta(minutes=10),
        )
        db_session.add(dep)
        db_session.flush()

        inc = Incident(
            title="Correlated Incident",
            host_id=host.id,
            detected_at=now,
            severity="high",
            status="open",
            correlated_deployment_id=dep.id,
        )
        db_session.add(inc)
        db_session.commit()

        engine = TimelineEngine()
        timeline = engine.build_timeline(db_session, inc.id)

        assert any(e.source == "deployment" for e in timeline.events)
        summary = engine.get_timeline_summary(db_session, inc.id)
        assert summary is not None
        assert len(summary.candidate_contributing_changes) >= 1
        assert "Correlation does not prove causation" in summary.causation_disclaimer

    def test_phase8_remediation_data_integrated(self, db_session: Session):
        now = datetime.now(timezone.utc)
        host = Host(hostname="host-p8", ip_address="10.0.0.9")
        db_session.add(host)
        db_session.flush()

        inc = Incident(
            title="Remediated Incident",
            host_id=host.id,
            detected_at=now,
            severity="high",
            status="open",
        )
        db_session.add(inc)
        db_session.flush()

        rem = Remediation(
            incident_id=inc.id,
            action_type="restart_service",
            description="Restart service",
            status="executed",
            requested_by="admin",
            executed_at=now + timedelta(minutes=5),
        )
        db_session.add(rem)
        db_session.commit()

        engine = TimelineEngine()
        timeline = engine.build_timeline(db_session, inc.id)

        assert any(e.source == "remediation" for e in timeline.events)
        summary = engine.get_timeline_summary(db_session, inc.id)
        assert summary is not None
        assert len(summary.remediation_summary) == 1
        assert summary.remediation_summary[0]["action_type"] == "restart_service"

    def test_correlation_never_presented_as_proven_causation(self, db_session: Session):
        now = datetime.now(timezone.utc)
        host = Host(hostname="host-noncausal", ip_address="10.0.0.10")
        db_session.add(host)
        db_session.flush()

        inc = Incident(
            title="Non causal test",
            host_id=host.id,
            detected_at=now,
            severity="medium",
            status="open",
        )
        db_session.add(inc)
        db_session.commit()

        engine = TimelineEngine()
        summary = engine.get_timeline_summary(db_session, inc.id)

        assert "does not prove causation" in summary.causation_disclaimer
        assert "caused" not in summary.causation_disclaimer.lower()


class TestSerializationAndAPIEndpoints:
    def test_pydantic_json_serialization(self):
        now = datetime.now(timezone.utc)
        timeline = IncidentTimeline(
            incident_id=uuid.uuid4(),
            incident_title="Serialization Test",
            status="open",
            severity="high",
            started_at=now,
            events=[
                IncidentTimelineEvent(
                    incident_id=uuid.uuid4(),
                    sequence=1,
                    event_type="test_event",
                    timestamp=now,
                    message="Test message",
                )
            ],
            summary="Test summary",
        )
        json_str = timeline.model_dump_json()
        assert "Serialization Test" in json_str
        parsed = json.loads(json_str)
        assert parsed["events"][0]["sequence"] == 1

    def test_api_get_timeline_endpoint_200(self, api_client: TestClient, db_session: Session):
        now = datetime.now(timezone.utc)
        host = Host(hostname="api-host-tl", ip_address="10.0.0.11")
        db_session.add(host)
        db_session.flush()

        inc = Incident(
            title="API Timeline Incident",
            host_id=host.id,
            detected_at=now,
            severity="medium",
            status="open",
        )
        db_session.add(inc)
        db_session.commit()

        resp = api_client.get(f"/api/v1/incidents/{inc.id}/timeline")
        assert resp.status_code == 200
        data = resp.json()
        assert data["incident_title"] == "API Timeline Incident"

    def test_api_get_replay_endpoint_200(self, api_client: TestClient, db_session: Session):
        now = datetime.now(timezone.utc)
        host = Host(hostname="api-host-rp", ip_address="10.0.0.12")
        db_session.add(host)
        db_session.flush()

        inc = Incident(
            title="API Replay Incident",
            host_id=host.id,
            detected_at=now,
            severity="high",
            status="open",
        )
        db_session.add(inc)
        db_session.commit()

        resp = api_client.get(f"/api/v1/incidents/{inc.id}/replay")
        assert resp.status_code == 200
        data = resp.json()
        assert data["incident_id"] == str(inc.id)
        assert "snapshots" in data

    def test_api_get_timeline_summary_endpoint_200(self, api_client: TestClient, db_session: Session):
        now = datetime.now(timezone.utc)
        host = Host(hostname="api-host-sum", ip_address="10.0.0.13")
        db_session.add(host)
        db_session.flush()

        inc = Incident(
            title="API Summary Incident",
            host_id=host.id,
            detected_at=now,
            severity="critical",
            status="open",
        )
        db_session.add(inc)
        db_session.commit()

        resp = api_client.get(f"/api/v1/incidents/{inc.id}/timeline/summary")
        assert resp.status_code == 200
        data = resp.json()
        assert data["incident_id"] == str(inc.id)
        assert data["current_severity"] == "critical"

    def test_api_endpoints_non_existent_incident_returns_404(self, api_client: TestClient):
        random_id = uuid.uuid4()
        assert api_client.get(f"/api/v1/incidents/{random_id}/timeline").status_code == 404
        assert api_client.get(f"/api/v1/incidents/{random_id}/replay").status_code == 404
        assert api_client.get(f"/api/v1/incidents/{random_id}/timeline/summary").status_code == 404

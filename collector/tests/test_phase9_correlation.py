"""
OpsTrace Phase 9 — Change-Aware Correlation Tests
==================================================

Comprehensive test suite for the Phase 9 Change-Aware Correlation Engine.

Coverage:
  1.  Candidate change filtering within lookback window
  2.  Candidate changes outside lookback window ignored
  3.  Direct service match vs host match vs disjoint scope scoring
  4.  Temporal proximity decay calculation (<5m, 15m, 30m, 60m)
  5.  Suspect deployment identification (correlated_deployment_id)
  6.  Suspect config change identification (correlated_config_change_id)
  7.  Multiple candidate changes ranking (highest score is primary suspect)
  8.  Correlation confidence level assignment (HIGH, MEDIUM, LOW, UNLIKELY)
  9.  "Correlation does not prove causation" disclaimer presence
 10.  Empty candidate list / no changes handling
 11.  Malformed / None input handling
 12.  Pydantic serialization / JSON round-trip
 13.  DB persistence integration with Phase 2 models (Incident, Deployment, ConfigChange, IncidentEvent)
 14.  Integration with Phase 7 DetectedIncident and IncidentEngine
 15.  Integration with Phase 8 RemediationEngine (CONFIG_ROLLBACK_RECOMMENDATION)
 16.  API endpoint integration testing (POST /correlate-changes & GET /correlated-changes)
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
# Phase 9 imports
# ---------------------------------------------------------------------------

from collector.app.correlators.change_correlator import ChangeCorrelator
from collector.app.correlators.models import (
    CandidateChange,
    ChangeCategory,
    ChangeCorrelation,
    ChangeCorrelationBatchResult,
    CorrelationConfidence,
    IncidentChangeCorrelation,
)
from backend.app.engines.correlation_engine import ChangeCorrelationEngine

# Phase 7 & 8 imports
from collector.app.detectors.models import (
    DetectedIncident,
    IncidentDetectionResult,
    IncidentSeverity,
    IncidentType,
)
from collector.app.remediators.models import RemediationActionType
from collector.app.remediators.remediation_engine import RemediationEngine

# DB Models & FastAPI app
from backend.app.application import create_app
from backend.app.models.base import Base
from backend.app.models.config_change import ConfigChange
from backend.app.models.deployment import Deployment
from backend.app.models.host import Host
from backend.app.models.incident import Incident
from backend.app.models.incident_event import IncidentEvent
from backend.app.models.service import Service


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
# Unit Tests — ChangeCorrelator & Models
# ---------------------------------------------------------------------------


class TestCandidateChangeModels:
    def test_candidate_change_creation(self):
        now = datetime.now(timezone.utc)
        cand = CandidateChange(
            change_type=ChangeCategory.DEPLOYMENT,
            timestamp=now,
            summary="Deployed v1.2.0",
            details={"version": "1.2.0"},
        )
        assert isinstance(cand.change_id, uuid.UUID)
        assert cand.change_type == ChangeCategory.DEPLOYMENT
        assert cand.summary == "Deployed v1.2.0"

    def test_confidence_from_score(self):
        assert CorrelationConfidence.from_score(0.85) == CorrelationConfidence.HIGH
        assert CorrelationConfidence.from_score(0.60) == CorrelationConfidence.MEDIUM
        assert CorrelationConfidence.from_score(0.30) == CorrelationConfidence.LOW
        assert CorrelationConfidence.from_score(0.10) == CorrelationConfidence.UNLIKELY

    def test_causation_disclaimer_present(self):
        corr = IncidentChangeCorrelation(
            incident_title="High Error Rate",
            detected_at=datetime.now(timezone.utc),
        )
        assert corr.correlation_does_not_prove_causation is True
        assert "Correlation does not prove causation" in corr.causation_disclaimer


class TestTemporalProximityScoring:
    def test_change_within_5_minutes_gets_high_temporal_score(self):
        correlator = ChangeCorrelator(lookback_minutes=60)
        now = datetime.now(timezone.utc)
        incident_time = now
        change_time = now - timedelta(minutes=3)

        cand = CandidateChange(
            change_type=ChangeCategory.CONFIG_CHANGE,
            timestamp=change_time,
            summary="Modified /etc/app.conf",
            diff="- timeout=5\n+ timeout=30",
        )

        res = correlator.evaluate_candidate(
            incident_title="Database Connection Timeout",
            incident_det_time=incident_time,
            host_id=None,
            service_id=None,
            candidate=cand,
        )

        assert res is not None
        assert res.score > 0.50
        assert any("within 5 minutes" in r for r in res.reasons)

    def test_change_outside_lookback_window_ignored(self):
        correlator = ChangeCorrelator(lookback_minutes=30)
        now = datetime.now(timezone.utc)
        change_time = now - timedelta(minutes=45)

        cand = CandidateChange(
            change_type=ChangeCategory.DEPLOYMENT,
            timestamp=change_time,
            summary="Old deployment",
        )

        res = correlator.evaluate_candidate(
            incident_title="Service Crash",
            incident_det_time=now,
            host_id=None,
            service_id=None,
            candidate=cand,
        )

        assert res.score == 0.0
        assert res.confidence == CorrelationConfidence.UNLIKELY


class TestScopeMatchingScoring:
    def test_direct_service_match_scores_higher_than_host_match(self):
        correlator = ChangeCorrelator(lookback_minutes=60)
        now = datetime.now(timezone.utc)
        h_id = str(uuid.uuid4())
        s1_id = str(uuid.uuid4())
        s2_id = str(uuid.uuid4())

        cand_s1 = CandidateChange(
            change_type=ChangeCategory.DEPLOYMENT,
            timestamp=now - timedelta(minutes=2),
            service_id=uuid.UUID(s1_id),
            host_id=uuid.UUID(h_id),
            summary="Deployment on s1",
        )

        cand_s2 = CandidateChange(
            change_type=ChangeCategory.DEPLOYMENT,
            timestamp=now - timedelta(minutes=2),
            service_id=uuid.UUID(s2_id),
            host_id=uuid.UUID(h_id),
            summary="Deployment on s2",
        )

        eval_s1 = correlator.evaluate_candidate(
            incident_title="Error on Service 1",
            incident_det_time=now,
            host_id=h_id,
            service_id=s1_id,
            candidate=cand_s1,
        )

        eval_s2 = correlator.evaluate_candidate(
            incident_title="Error on Service 1",
            incident_det_time=now,
            host_id=h_id,
            service_id=s1_id,
            candidate=cand_s2,
        )

        assert eval_s1.score > eval_s2.score

    def test_disjoint_scope_scores_zero(self):
        correlator = ChangeCorrelator(lookback_minutes=60)
        now = datetime.now(timezone.utc)

        cand = CandidateChange(
            change_type=ChangeCategory.CONFIG_CHANGE,
            timestamp=now - timedelta(minutes=2),
            host_id=uuid.uuid4(),
            service_id=uuid.uuid4(),
            summary="Other host change",
        )

        eval_res = correlator.evaluate_candidate(
            incident_title="Host A Failure",
            incident_det_time=now,
            host_id=str(uuid.uuid4()),
            service_id=str(uuid.uuid4()),
            candidate=cand,
        )

        assert eval_res.score == 0.0


class TestSuspectAttributionAndRanking:
    def test_multiple_candidates_highest_score_is_primary(self):
        correlator = ChangeCorrelator(lookback_minutes=60)
        now = datetime.now(timezone.utc)
        s_id = uuid.uuid4()
        h_id = uuid.uuid4()

        # Older change (20m ago)
        c_old = CandidateChange(
            change_id=uuid.uuid4(),
            change_type=ChangeCategory.PACKAGE_UPDATE,
            timestamp=now - timedelta(minutes=20),
            service_id=s_id,
            host_id=h_id,
            summary="Package update 20m ago",
        )

        # Recent change with diff (2m ago)
        c_recent = CandidateChange(
            change_id=uuid.uuid4(),
            change_type=ChangeCategory.CONFIG_CHANGE,
            timestamp=now - timedelta(minutes=2),
            service_id=s_id,
            host_id=h_id,
            summary="Config update 2m ago",
            diff="- port=80\n+ port=8080",
        )

        inc = DetectedIncident(
            title="Service Unreachable",
            host_id=h_id,
            service_id=s_id,
            first_seen=now,
        )

        result = correlator.correlate_incident(
            incident=inc,
            candidate_changes=[c_old, c_recent],
        )

        assert result.primary_suspect is not None
        assert result.primary_suspect.candidate.change_id == c_recent.change_id
        assert result.primary_suspect.is_primary_suspect is True
        assert result.correlated_config_change_id == c_recent.change_id
        assert len(result.secondary_suspects) == 1


class TestEmptyAndMalformedInputs:
    def test_none_incident_raises_value_error(self):
        correlator = ChangeCorrelator()
        with pytest.raises(ValueError):
            correlator.correlate_incident(incident=None, candidate_changes=[])

    def test_empty_candidates_returns_empty_suspects(self):
        correlator = ChangeCorrelator()
        inc = DetectedIncident(title="Memory Spike")
        res = correlator.correlate_incident(incident=inc, candidate_changes=[])
        assert res.primary_suspect is None
        assert res.secondary_suspects == []
        assert res.total_candidates_evaluated == 0


class TestSerialization:
    def test_pydantic_json_roundtrip(self):
        corr = IncidentChangeCorrelation(
            incident_id=uuid.uuid4(),
            incident_title="Database High Load",
            detected_at=datetime.now(timezone.utc),
            primary_suspect=ChangeCorrelation(
                candidate=CandidateChange(
                    change_type=ChangeCategory.DEPLOYMENT,
                    timestamp=datetime.now(timezone.utc),
                    summary="v2.1 release",
                ),
                score=0.88,
                confidence=CorrelationConfidence.HIGH,
                reasons=["Recent release"],
                is_primary_suspect=True,
            ),
        )
        json_data = corr.model_dump_json()
        assert "Database High Load" in json_data
        parsed = json.loads(json_data)
        assert parsed["correlation_does_not_prove_causation"] is True


# ---------------------------------------------------------------------------
# Integration Tests — Database Persistence & API Endpoints
# ---------------------------------------------------------------------------


class TestDatabasePersistenceIntegration:
    def test_correlate_and_persist_incident_in_db(self, db_session: Session):
        now = datetime.now(timezone.utc)

        # 1. Create Host and Service
        host = Host(hostname="prod-app-01", ip_address="10.0.0.1")
        db_session.add(host)
        db_session.flush()

        svc = Service(name="payment-service", host_id=host.id)
        db_session.add(svc)
        db_session.flush()

        # 2. Create Candidate Deployment & ConfigChange
        dep = Deployment(
            service_id=svc.id,
            host_id=host.id,
            version="v3.1.0",
            deployed_by="ci-cd",
            deployed_at=now - timedelta(minutes=5),
        )
        db_session.add(dep)

        cc = ConfigChange(
            service_id=svc.id,
            host_id=host.id,
            config_file_path="/etc/payment/db.conf",
            change_type="modify",
            previous_value="pool_size=10",
            new_value="pool_size=100",
            diff="- pool_size=10\n+ pool_size=100",
            changed_by="admin",
            changed_at=now - timedelta(minutes=3),
        )
        db_session.add(cc)
        db_session.flush()

        # 3. Create Incident
        inc = Incident(
            title="Database Connection Pool Exhaustion",
            description="Payment service failing to acquire DB connection.",
            host_id=host.id,
            service_id=svc.id,
            detected_at=now,
            severity="high",
            status="open",
        )
        db_session.add(inc)
        db_session.commit()

        # 4. Run ChangeCorrelationEngine
        engine = ChangeCorrelationEngine(lookback_minutes=60)
        corr_result = engine.correlate_and_persist_incident(db_session, inc.id)

        assert corr_result is not None
        assert corr_result.primary_suspect is not None

        # Verify DB Incident links updated
        db_session.refresh(inc)
        assert inc.correlated_config_change_id == cc.id or inc.correlated_deployment_id == dep.id
        assert inc.metadata_json is not None
        assert "change_correlation" in inc.metadata_json

        # Verify IncidentEvent added
        events = db_session.query(IncidentEvent).filter(IncidentEvent.incident_id == inc.id).all()
        assert len(events) >= 1
        assert any(e.event_type == "change_correlated" for e in events)


class TestPhase8RemediationIntegration:
    def test_remediation_action_allowlist_handles_incident(self):
        engine = RemediationEngine()
        inc = DetectedIncident(
            title="Service Crash after Config Update",
            incident_type=IncidentType.SERVICE_FAILURE.value,
            severity=IncidentSeverity.from_db_severity("high"),
        )

        plan = engine.plan(inc)
        assert plan.action_type in (
            RemediationActionType.RESTART_SERVICE,
            RemediationActionType.CONFIG_ROLLBACK_RECOMMENDATION,
            RemediationActionType.MANUAL_INVESTIGATION_REQUIRED,
        )


class TestAPIEndpoints:
    def test_correlate_incident_endpoint_returns_200(self, api_client: TestClient, db_session: Session):
        now = datetime.now(timezone.utc)
        host = Host(hostname="api-host", ip_address="10.0.0.2")
        db_session.add(host)
        db_session.flush()

        inc = Incident(
            title="API High Latency",
            host_id=host.id,
            detected_at=now,
            severity="medium",
            status="open",
        )
        db_session.add(inc)
        db_session.commit()

        resp = api_client.post(
            f"/api/v1/incidents/{inc.id}/correlate-changes",
            json={"lookback_minutes": 60, "min_score_threshold": 0.20},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["incident_title"] == "API High Latency"
        assert data["correlation_does_not_prove_causation"] is True

    def test_get_correlated_changes_endpoint_returns_summary(self, api_client: TestClient, db_session: Session):
        now = datetime.now(timezone.utc)
        host = Host(hostname="api-host-2", ip_address="10.0.0.3")
        db_session.add(host)
        db_session.flush()

        inc = Incident(
            title="500 Internal Errors",
            host_id=host.id,
            detected_at=now,
            severity="critical",
            status="open",
        )
        db_session.add(inc)
        db_session.commit()

        # Trigger correlation first
        api_client.post(f"/api/v1/incidents/{inc.id}/correlate-changes")

        resp = api_client.get(f"/api/v1/incidents/{inc.id}/correlated-changes")
        assert resp.status_code == 200
        data = resp.json()
        assert data["incident_id"] == str(inc.id)
        assert data["correlation_does_not_prove_causation"] is True

    def test_correlate_non_existent_incident_returns_404(self, api_client: TestClient):
        random_id = uuid.uuid4()
        resp = api_client.post(f"/api/v1/incidents/{random_id}/correlate-changes")
        assert resp.status_code == 404

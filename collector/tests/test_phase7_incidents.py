"""
OpsTrace Phase 7 — Incident Detection & Incident Correlation Tests
===================================================================

Comprehensive unit and integration test suite for Phase 7.

Coverage:
  1.  No incident for normal INFO logs
  2.  Warning threshold detection
  3.  Error threshold detection
  4.  Critical incident detection
  5.  Repeated fingerprint detection
  6.  Service failure detection (correlation into single incident)
  7.  Incident severity calculation and DB mapping
  8.  Incident correlation (multi-rule merging)
  9.  Duplicate incident prevention (active DB incident update)
 10.  First seen / last seen timestamp tracking
 11.  Incident event creation & timeline correlation
 12.  Malformed input handling (safe recovery)
 13.  Empty input handling
 14.  Multiple independent incidents detected separately
 15.  Serialization (Pydantic v2 JSON dumping)
 16.  Full integration with Phase 6 analysis & Phase 2/3 DB models
"""

from __future__ import annotations

import json
import sys
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import List

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker

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
# Imports
# ---------------------------------------------------------------------------

from backend.app.models.base import Base
from backend.app.models.host import Host
from backend.app.models.incident import Incident
from backend.app.models.incident_event import IncidentEvent
from backend.app.models.service import Service

from collector.app.collectors.log_models import CollectedLogEvent, LogLevel
from collector.app.analyzers.log_analyzer import LogAnalyzer
from collector.app.analyzers.models import AnalysisResult, ErrorGroupSummary

from collector.app.detectors.models import (
    DetectedIncident,
    DetectionRuleConfig,
    IncidentDetectionResult,
    IncidentEvidence,
    IncidentSeverity,
    IncidentType,
)
from collector.app.detectors.rules import (
    CriticalErrorRule,
    HighErrorRateRule,
    MultipleRelatedErrorsRule,
    RepeatedFingerprintRule,
    ServiceFailureRule,
)
from collector.app.detectors.incident_detector import IncidentDetector
from backend.app.engines.incident_engine import IncidentEngine


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def db_session():
    """In-memory SQLite database session fixture with Phase 2 tables created."""
    engine = create_engine("sqlite:///:memory:", echo=False)
    Base.metadata.create_all(bind=engine)
    TestingSessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False)
    session = TestingSessionLocal()

    # Pre-create test host
    host = Host(id=uuid.uuid4(), hostname="test-host-01", status="healthy")
    session.add(host)
    session.commit()
    session.refresh(host)

    try:
        yield session
    finally:
        session.close()


@pytest.fixture
def sample_host_and_service(db_session: Session):
    """Fixture providing host and service DB objects."""
    host = db_session.query(Host).filter(Host.hostname == "test-host-01").first()
    service = Service(id=uuid.uuid4(), name="postgres", host_id=host.id, status="active")
    db_session.add(service)
    db_session.commit()
    db_session.refresh(service)
    return host, service


# ---------------------------------------------------------------------------
# 1. No incident for normal INFO logs
# ---------------------------------------------------------------------------

class TestNoIncidentForNormalLogs:
    def test_info_logs_produce_no_incidents(self):
        detector = IncidentDetector()
        events = [
            CollectedLogEvent(
                timestamp=datetime.now(timezone.utc),
                level=LogLevel.INFO,
                message=f"System operation {i} normal",
                source="app",
            )
            for i in range(10)
        ]

        analyzer = LogAnalyzer()
        analysis = analyzer.analyze(events)

        result = detector.detect(analysis_result=analysis, events=events)
        assert result.total_incidents_detected == 0
        assert len(result.incidents) == 0


# ---------------------------------------------------------------------------
# 2. Threshold Detections (Warning, Error, Critical)
# ---------------------------------------------------------------------------

class TestThresholdDetections:
    def test_warning_threshold_detection(self):
        cfg = DetectionRuleConfig(error_rate_warning_threshold=10.0, error_rate_error_threshold=30.0)
        detector = IncidentDetector(config=cfg)

        analysis = AnalysisResult(
            error_rate_per_minute=15.0,
            total_errors=15,
            analysis_window_seconds=60.0,
            window_start=datetime.now(timezone.utc) - timedelta(seconds=60),
            window_end=datetime.now(timezone.utc),
        )

        result = detector.detect(analysis_result=analysis)
        assert result.total_incidents_detected == 1
        inc = result.incidents[0]
        assert inc.severity == IncidentSeverity.WARNING
        assert "High Error Rate" in inc.title

    def test_error_threshold_detection(self):
        cfg = DetectionRuleConfig(error_rate_warning_threshold=10.0, error_rate_error_threshold=30.0)
        detector = IncidentDetector(config=cfg)

        analysis = AnalysisResult(
            error_rate_per_minute=35.0,
            total_errors=35,
            analysis_window_seconds=60.0,
            window_start=datetime.now(timezone.utc) - timedelta(seconds=60),
            window_end=datetime.now(timezone.utc),
        )

        result = detector.detect(analysis_result=analysis)
        assert result.total_incidents_detected == 1
        inc = result.incidents[0]
        assert inc.severity == IncidentSeverity.ERROR

    def test_critical_threshold_detection(self):
        cfg = DetectionRuleConfig(error_rate_critical_threshold=60.0)
        detector = IncidentDetector(config=cfg)

        analysis = AnalysisResult(
            error_rate_per_minute=75.0,
            total_errors=75,
            analysis_window_seconds=60.0,
            window_start=datetime.now(timezone.utc) - timedelta(seconds=60),
            window_end=datetime.now(timezone.utc),
        )

        result = detector.detect(analysis_result=analysis)
        assert result.total_incidents_detected == 1
        inc = result.incidents[0]
        assert inc.severity == IncidentSeverity.CRITICAL


# ---------------------------------------------------------------------------
# 3. Critical Incident Detection
# ---------------------------------------------------------------------------

class TestCriticalIncidentDetection:
    def test_critical_log_triggers_critical_incident(self):
        detector = IncidentDetector()
        analysis = AnalysisResult(
            total_critical=1,
            total_errors=1,
            error_groups=[
                ErrorGroupSummary(
                    fingerprint="a" * 64,
                    count=1,
                    sample_message="Kernel panic - not syncing: Fatal hardware error",
                    level="CRITICAL",
                    source="kernel",
                )
            ],
        )

        result = detector.detect(analysis_result=analysis)
        assert result.total_incidents_detected >= 1
        inc = result.incidents[0]
        assert inc.severity == IncidentSeverity.CRITICAL


# ---------------------------------------------------------------------------
# 4. Repeated Fingerprint Detection
# ---------------------------------------------------------------------------

class TestRepeatedFingerprintDetection:
    def test_repeated_fingerprint_exceeding_threshold(self):
        cfg = DetectionRuleConfig(repeated_fingerprint_threshold=3)
        detector = IncidentDetector(config=cfg)

        fp = "b" * 64
        analysis = AnalysisResult(
            total_errors=5,
            unique_error_fingerprints=1,
            error_groups=[
                ErrorGroupSummary(
                    fingerprint=fp,
                    count=5,
                    sample_message="NullPointerException in UserAuthService.java:42",
                    level="ERROR",
                    source="auth-service",
                )
            ],
        )

        result = detector.detect(analysis_result=analysis)
        assert result.total_incidents_detected >= 1
        assert any(fp in inc.related_fingerprints for inc in result.incidents)


# ---------------------------------------------------------------------------
# 5. Service Failure Detection & Event Correlation
# ---------------------------------------------------------------------------

class TestServiceFailureDetection:
    def test_correlates_multiple_service_error_logs_into_one_incident(self):
        """
        Requirements test:
        ERROR Database connection failed
        ERROR Database connection failed
        ERROR Database connection failed
        CRITICAL Database service unavailable

        Must be recognized as ONE incident 'Database Service Failure' instead of 4 separate incidents.
        """
        detector = IncidentDetector()
        now = datetime.now(timezone.utc)

        events = [
            CollectedLogEvent(
                timestamp=now - timedelta(seconds=30),
                level=LogLevel.ERROR,
                message="Database connection failed",
                source="db-driver",
            ),
            CollectedLogEvent(
                timestamp=now - timedelta(seconds=20),
                level=LogLevel.ERROR,
                message="Database connection failed",
                source="db-driver",
            ),
            CollectedLogEvent(
                timestamp=now - timedelta(seconds=10),
                level=LogLevel.ERROR,
                message="Database connection failed",
                source="db-driver",
            ),
            CollectedLogEvent(
                timestamp=now,
                level=LogLevel.CRITICAL,
                message="Database service unavailable",
                source="db-driver",
            ),
        ]

        analyzer = LogAnalyzer()
        analysis = analyzer.analyze(events)

        result = detector.detect(analysis_result=analysis, events=events, host_name="db-01", service_name="postgres")

        assert result.total_incidents_detected == 1
        inc = result.incidents[0]
        assert "Failure" in inc.title or "Unavailability" in inc.title
        assert inc.severity == IncidentSeverity.CRITICAL
        assert len(inc.evidence) >= 1


# ---------------------------------------------------------------------------
# 6. Incident Severity Calculation & DB Mapping
# ---------------------------------------------------------------------------

class TestIncidentSeverityCalculation:
    def test_severity_ranks_and_db_mapping(self):
        assert IncidentSeverity.INFO.to_db_severity() == "low"
        assert IncidentSeverity.WARNING.to_db_severity() == "medium"
        assert IncidentSeverity.ERROR.to_db_severity() == "high"
        assert IncidentSeverity.CRITICAL.to_db_severity() == "critical"

        assert IncidentSeverity.from_db_severity("low") == IncidentSeverity.INFO
        assert IncidentSeverity.from_db_severity("medium") == IncidentSeverity.WARNING
        assert IncidentSeverity.from_db_severity("high") == IncidentSeverity.ERROR
        assert IncidentSeverity.from_db_severity("critical") == IncidentSeverity.CRITICAL

        assert IncidentSeverity.CRITICAL.rank > IncidentSeverity.ERROR.rank
        assert IncidentSeverity.ERROR.rank > IncidentSeverity.WARNING.rank
        assert IncidentSeverity.WARNING.rank > IncidentSeverity.INFO.rank


# ---------------------------------------------------------------------------
# 7. Incident Correlation (Multi-Rule Merging)
# ---------------------------------------------------------------------------

class TestIncidentCorrelation:
    def test_merges_incidents_with_overlapping_fingerprints(self):
        detector = IncidentDetector()
        fp = "c" * 64

        inc1 = DetectedIncident(
            incident_type=IncidentType.REPEATED_FINGERPRINT.value,
            title="Repeated Auth Error",
            severity=IncidentSeverity.WARNING,
            related_fingerprints=[fp],
            evidence=[IncidentEvidence(message="Auth failed 1")],
        )
        inc2 = DetectedIncident(
            incident_type=IncidentType.SERVICE_FAILURE.value,
            title="Auth Service Failure",
            severity=IncidentSeverity.CRITICAL,
            related_fingerprints=[fp],
            evidence=[IncidentEvidence(message="Auth service down")],
        )

        merged = detector.correlate_incidents([inc1, inc2])
        assert len(merged) == 1
        assert merged[0].severity == IncidentSeverity.CRITICAL
        assert len(merged[0].evidence) == 2


# ---------------------------------------------------------------------------
# 8. Duplicate Incident Prevention & DB Correlation
# ---------------------------------------------------------------------------

class TestDuplicateIncidentPrevention:
    def test_prevents_duplicate_active_db_incidents(self, db_session: Session, sample_host_and_service):
        host, service = sample_host_and_service
        engine = IncidentEngine()
        fp = "d" * 64
        now = datetime.now(timezone.utc)

        # Batch 1 -> creates new DB Incident
        det1 = DetectedIncident(
            incident_type=IncidentType.SERVICE_FAILURE.value,
            title="Database Connection Failure",
            description="DB connection drops",
            severity=IncidentSeverity.ERROR,
            status="open",
            first_seen=now - timedelta(minutes=5),
            last_seen=now - timedelta(minutes=4),
            related_fingerprints=[fp],
        )
        res1 = IncidentDetectionResult(incidents=[det1])
        persisted1 = engine.process_and_persist(db_session, res1, host_id=host.id, service_id=service.id)
        assert len(persisted1) == 1
        inc_id = persisted1[0].id

        # Verify DB has 1 incident
        db_inc_count = db_session.query(Incident).count()
        assert db_inc_count == 1

        # Batch 2 (1 minute later with same problem/fingerprint)
        det2 = DetectedIncident(
            incident_type=IncidentType.SERVICE_FAILURE.value,
            title="Database Connection Failure",
            description="Continued DB connection drops",
            severity=IncidentSeverity.CRITICAL,
            status="open",
            first_seen=now - timedelta(minutes=2),
            last_seen=now,
            related_fingerprints=[fp],
        )
        res2 = IncidentDetectionResult(incidents=[det2])
        persisted2 = engine.process_and_persist(db_session, res2, host_id=host.id, service_id=service.id)

        # Asserts DB still has only 1 incident row (no duplicate row created)
        assert db_session.query(Incident).count() == 1
        updated_inc = db_session.get(Incident, inc_id)
        assert updated_inc.severity == "critical"  # Escalated
        assert updated_inc.metadata_json["correlation_count"] == 2

        # Asserts IncidentEvents timeline was updated
        events = db_session.query(IncidentEvent).filter(IncidentEvent.incident_id == inc_id).all()
        assert len(events) >= 2


# ---------------------------------------------------------------------------
# 9. First Seen / Last Seen Timestamps
# ---------------------------------------------------------------------------

class TestFirstSeenLastSeenTimestamps:
    def test_first_seen_and_last_seen_tracking(self):
        t1 = datetime(2026, 10, 4, 10, 0, 0, tzinfo=timezone.utc)
        t2 = datetime(2026, 10, 4, 10, 5, 0, tzinfo=timezone.utc)

        events = [
            CollectedLogEvent(timestamp=t1, level=LogLevel.ERROR, message="Service unavailable", source="api"),
            CollectedLogEvent(timestamp=t2, level=LogLevel.CRITICAL, message="Service unavailable", source="api"),
        ]

        analyzer = LogAnalyzer()
        analysis = analyzer.analyze(events)

        detector = IncidentDetector()
        res = detector.detect(analysis_result=analysis, events=events)

        assert res.total_incidents_detected >= 1
        inc = res.incidents[0]
        assert inc.first_seen == t1
        assert inc.last_seen == t2


# ---------------------------------------------------------------------------
# 10. Incident Event Creation & Timeline
# ---------------------------------------------------------------------------

class TestIncidentEventCreation:
    def test_creates_timeline_events_in_db(self, db_session: Session, sample_host_and_service):
        host, service = sample_host_and_service
        engine = IncidentEngine()
        now = datetime.now(timezone.utc)

        detected = DetectedIncident(
            incident_type=IncidentType.SERVICE_FAILURE.value,
            title="Payment Gateway Timeout",
            severity=IncidentSeverity.ERROR,
            first_seen=now,
            last_seen=now,
            evidence=[
                IncidentEvidence(event_type="log_evidence", message="Timeout contacting Stripe API"),
                IncidentEvidence(event_type="log_evidence", message="HTTP 504 Gateway Timeout"),
            ],
        )

        res = IncidentDetectionResult(incidents=[detected])
        persisted = engine.process_and_persist(db_session, res, host_id=host.id, service_id=service.id)

        inc = persisted[0]
        db_events = db_session.query(IncidentEvent).filter(IncidentEvent.incident_id == inc.id).all()
        assert len(db_events) == 3  # 1 detect event + 2 evidence events
        event_types = [e.event_type for e in db_events]
        assert "incident_detected" in event_types


# ---------------------------------------------------------------------------
# 11. Malformed and Empty Input Handling
# ---------------------------------------------------------------------------

class TestMalformedAndEmptyInputHandling:
    def test_empty_input_returns_zero_incidents(self):
        detector = IncidentDetector()
        result = detector.detect(analysis_result=None, events=[])
        assert result.total_incidents_detected == 0
        assert result.incidents == []
        assert len(result.detection_errors) == 0

    def test_malformed_event_handled_gracefully(self):
        detector = IncidentDetector()
        # Raw dict or invalid items passed to detector
        malformed_events = [
            {"timestamp": None, "level": "INVALID", "message": None},
            "not_an_event_object",  # Invalid type
            None,
        ]

        # Must not raise exception
        result = detector.detect(analysis_result=AnalysisResult(), events=malformed_events)
        assert isinstance(result, IncidentDetectionResult)


# ---------------------------------------------------------------------------
# 12. Multiple Independent Incidents
# ---------------------------------------------------------------------------

class TestMultipleIndependentIncidents:
    def test_detects_separate_independent_incidents(self):
        detector = IncidentDetector()
        now = datetime.now(timezone.utc)

        # 5 repeated ERROR events for auth-service
        events = [
            CollectedLogEvent(timestamp=now, level=LogLevel.ERROR, message=f"Invalid auth token {i}", source="auth-service")
            for i in range(5)
        ]
        # 1 critical service failure event for postgres
        events.append(
            CollectedLogEvent(timestamp=now, level=LogLevel.CRITICAL, message="Postgres connection refused", source="postgres")
        )

        analyzer = LogAnalyzer()
        analysis = analyzer.analyze(events)

        result = detector.detect(analysis_result=analysis, events=events)
        assert result.total_incidents_detected >= 2


# ---------------------------------------------------------------------------
# 13. Serialization
# ---------------------------------------------------------------------------

class TestSerialization:
    def test_pydantic_models_serialize_to_json(self):
        now = datetime.now(timezone.utc)
        detected = DetectedIncident(
            incident_id=uuid.uuid4(),
            incident_type=IncidentType.SERVICE_FAILURE.value,
            title="Serialization Test Incident",
            description="Testing JSON output",
            severity=IncidentSeverity.CRITICAL,
            first_seen=now,
            last_seen=now,
            evidence=[IncidentEvidence(message="Test evidence")],
        )

        json_str = detected.model_dump_json()
        assert "Serialization Test Incident" in json_str
        assert "CRITICAL" in json_str

        res = IncidentDetectionResult(incidents=[detected])
        res_json = res.model_dump_json()
        assert "incidents" in res_json


# ---------------------------------------------------------------------------
# 14. Full End-to-End Integration
# ---------------------------------------------------------------------------

class TestPhase7Integration:
    def test_full_pipeline_raw_logs_to_db_incident(self, db_session: Session, sample_host_and_service):
        host, service = sample_host_and_service
        now = datetime.now(timezone.utc)

        # 1. Phase 5: Collector creates raw log events
        raw_events = [
            CollectedLogEvent(
                timestamp=now - timedelta(seconds=i * 5),
                level=LogLevel.ERROR if i < 4 else LogLevel.CRITICAL,
                message="Database connection failed" if i < 4 else "Database service unavailable",
                source="postgres",
            )
            for i in range(5)
        ]

        # 2. Phase 6: Analysis Engine
        analyzer = LogAnalyzer()
        analysis_result = analyzer.analyze(raw_events)
        assert analysis_result.total_errors == 5

        # 3. Phase 7: Incident Detector
        detector = IncidentDetector()
        detection_result = detector.detect(
            analysis_result=analysis_result,
            events=raw_events,
            host_name=host.hostname,
            service_name=service.name,
        )
        assert detection_result.total_incidents_detected == 1

        # 4. Phase 7: Incident Engine DB Persistence
        engine = IncidentEngine()
        persisted_incidents = engine.process_and_persist(
            db=db_session,
            detection_result=detection_result,
            host_id=host.id,
            service_id=service.id,
        )

        assert len(persisted_incidents) == 1
        db_inc = db_session.get(Incident, persisted_incidents[0].id)
        assert db_inc is not None
        assert db_inc.severity == "critical"
        assert db_inc.host_id == host.id
        assert db_inc.service_id == service.id

        # Verify timeline events
        db_events = db_session.query(IncidentEvent).filter(IncidentEvent.incident_id == db_inc.id).all()
        assert len(db_events) > 1

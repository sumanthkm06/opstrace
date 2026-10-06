"""Cross-phase persisted collector-to-replay integration coverage."""

from datetime import datetime, timedelta, timezone
from uuid import UUID

from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from backend.app.application import create_app
from backend.app.core.database import get_db
from backend.app.engines.correlation_engine import ChangeCorrelationEngine
from backend.app.engines.dependency_engine import DependencyEngine
from backend.app.engines.incident_engine import IncidentEngine
from backend.app.engines.remediation_engine import RemediationPersistenceEngine
from backend.app.engines.timeline_engine import TimelineEngine
from backend.app.models import (
    AuditEvent, Base, ConfigChange, Deployment, Host, Incident, Log, Metric,
    Remediation, Service, ServiceDependency,
)
from collector.app.analyzers.log_analyzer import LogAnalyzer
from collector.app.collectors.log_models import CollectedLogEvent
from collector.app.detectors.incident_detector import IncidentDetector


def test_collector_ingest_persists_through_correlation_dependency_and_replay(monkeypatch):
    engine = create_engine(
        "sqlite:///:memory:", connect_args={"check_same_thread": False}, poolclass=StaticPool
    )
    TestingSession = sessionmaker(autocommit=False, autoflush=False, bind=engine)
    Base.metadata.create_all(bind=engine)

    def override_db():
        with TestingSession() as session:
            yield session

    app = create_app()
    app.dependency_overrides[get_db] = override_db
    monkeypatch.setattr(
        "backend.app.api.v1.telemetry.get_settings",
        lambda: type("Settings", (), {"COLLECTOR_API_KEY": "integration-key", "ENVIRONMENT": "testing"})(),
    )
    monkeypatch.setattr(
        "backend.app.api.v1.logs.get_settings",
        lambda: type("Settings", (), {"COLLECTOR_API_KEY": "integration-key", "ENVIRONMENT": "testing"})(),
    )
    headers = {"Authorization": "Bearer integration-key"}
    now = datetime.now(timezone.utc)
    telemetry = {
        "collected_at": now.isoformat(),
        "host": {"hostname": "phase21-host", "os_name": "Linux", "os_version": "test",
                 "os_release": "test-kernel", "cpu_count_logical": 2,
                 "total_memory_bytes": 8192, "collector_version": "0.4.0"},
        "cpu": {"cpu_percent": 35.0},
        "services": [{"name": "payment-api", "active_state": "active"}],
    }
    log_batch = {
        "collected_at": now.isoformat(), "hostname": "phase21-host",
        "events": [{"timestamp": now.isoformat(), "hostname": "phase21-host",
                    "service_name": "payment-api", "level": "CRITICAL",
                    "message": "payment service unavailable: database connection pool exhausted",
                    "source": "payment-api", "source_type": "journal"}],
    }

    try:
        with TestClient(app) as client:
            assert client.post("/api/v1/telemetry", json=telemetry, headers=headers).status_code == 200
            assert client.post("/api/v1/logs/ingest", json=log_batch, headers=headers).json()["accepted"] == 1
            assert client.post(
                "/api/v1/telemetry", json=telemetry,
                headers={"Authorization": "Bearer invalid"},
            ).status_code == 403
            assert client.post(
                "/api/v1/logs/ingest", json=log_batch,
                headers={"Authorization": "Bearer invalid"},
            ).status_code == 403
            assert client.post("/api/v1/telemetry", json={"host": "malformed"}, headers=headers).status_code == 422
            assert client.post("/api/v1/logs/ingest", json={"unexpected": True}, headers=headers).status_code == 422

        with TestingSession() as db:
            host = db.query(Host).filter_by(hostname="phase21-host").one()
            service = db.query(Service).filter_by(host_id=host.id, name="payment-api").one()
            assert db.query(Metric).filter_by(host_id=host.id).count() > 0
            stored_log = db.query(Log).filter_by(host_id=host.id).one()
            event = CollectedLogEvent(
                timestamp=stored_log.timestamp.replace(tzinfo=timezone.utc),
                hostname=host.hostname, service_name=service.name,
                level=stored_log.level, message=stored_log.message, source=stored_log.source,
            )
            analysis = LogAnalyzer().analyze([event])
            detection = IncidentDetector().detect(
                analysis_result=analysis, events=[event], host_name=host.hostname, service_name=service.name
            )
            assert analysis.total_errors >= 1
            assert detection.incidents
            persisted = IncidentEngine().process_and_persist(db, detection, host.id, service.id)
            assert persisted
            incident = persisted[0]
            # Phase 7 persistence assigns the database ID; carry it into the
            # detection result so Phase 8 can satisfy its incident FK.
            for detected in detection.incidents:
                detected.incident_id = incident.id

            # Create a caller chain so a failed provider's blast radius is exercised.
            api = Service(host_id=host.id, name="api-gateway", status="active")
            frontend = Service(host_id=host.id, name="web-frontend", status="active")
            db.add_all([api, frontend])
            db.flush()
            db.add_all([
                ServiceDependency(service_id=api.id, depends_on_service_id=service.id,
                                  dependency_type="synchronous", criticality="critical"),
                ServiceDependency(service_id=frontend.id, depends_on_service_id=api.id,
                                  dependency_type="synchronous", criticality="critical"),
            ])
            deployment = Deployment(
                service_id=service.id, host_id=host.id, version="2.1.0", deployed_by="release-bot",
                deployed_at=now - timedelta(minutes=3), release_notes="payment pool configuration rollout",
            )
            change = ConfigChange(
                service_id=service.id, host_id=host.id, config_file_path="/etc/payment/pool.conf",
                change_type="modify", changed_by="release-bot", changed_at=now - timedelta(minutes=2),
                diff="pool_size: 20 -> 2",
            )
            db.add_all([deployment, change])
            db.commit()

            correlation = ChangeCorrelationEngine().correlate_and_persist_incident(db, incident.id)
            assert correlation and correlation.primary_suspect
            summary = ChangeCorrelationEngine().get_incident_correlation_summary(db, incident.id)
            assert summary["correlation_does_not_prove_causation"] is True

            impact = DependencyEngine().analyze_impact(db, service.id)
            assert {node.service_name for node in impact.downstream_impacts} == {"api-gateway", "web-frontend"}

            remediation = RemediationPersistenceEngine(dry_run=True).process_and_persist(db, detection)
            assert remediation.plans and all(plan.dry_run for plan in remediation.plans)
            assert db.query(Remediation).filter_by(incident_id=incident.id).count() >= 1
            assert db.query(AuditEvent).count() >= 1

            timeline_engine = TimelineEngine()
            timeline = timeline_engine.build_timeline(db, incident.id)
            replay = timeline_engine.replay_incident(db, incident.id)
            assert timeline and len(timeline.events) >= 3
            assert replay and replay.total_steps >= 1
            before = db.query(Incident).filter_by(id=incident.id).one().metadata_json.copy()
            timeline_engine.replay_incident(db, incident.id)
            after = db.query(Incident).filter_by(id=incident.id).one().metadata_json.copy()
            assert before == after
    finally:
        app.dependency_overrides.clear()
        Base.metadata.drop_all(bind=engine)
        engine.dispose()

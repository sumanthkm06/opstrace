"""Phase 13 collector ingestion and Prometheus exposition tests."""

import sys
import uuid
from datetime import datetime, timezone
from pathlib import Path

from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

REPO_ROOT = Path(__file__).resolve().parents[2]
for path in (REPO_ROOT, REPO_ROOT / "backend"):
    if str(path) not in sys.path:
        sys.path.insert(0, str(path))

from backend.app.api.v1.telemetry import _require_collector_auth
from backend.app.application import create_app
from backend.app.core.database import get_db
from backend.app.models import Base, Host, Incident, Metric, Service

engine = create_engine(
    "sqlite:///:memory:",
    connect_args={"check_same_thread": False},
    poolclass=StaticPool,
)
TestingSession = sessionmaker(autocommit=False, autoflush=False, bind=engine)


def override_get_db():
    session = TestingSession()
    try:
        yield session
    finally:
        session.close()


def test_telemetry_is_persisted_and_exported():
    Base.metadata.create_all(bind=engine)
    app = create_app()
    app.dependency_overrides[get_db] = override_get_db
    app.dependency_overrides[_require_collector_auth] = lambda: None
    payload = {
        "collected_at": "2026-10-05T10:00:00Z",
        "host": {
            "hostname": "metrics-host",
            "os_name": "Linux",
            "os_version": "Test OS",
            "os_release": "test-kernel",
            "cpu_count_logical": 4,
            "total_memory_bytes": 8192,
            "collector_version": "0.4.0",
        },
        "cpu": {"cpu_percent": 42.5},
        "memory": {
            "total_bytes": 8192,
            "available_bytes": 4096,
            "used_bytes": 4096,
            "memory_percent": 50.0,
        },
        "disk": [{
            "path": "/",
            "total_bytes": 1000,
            "used_bytes": 600,
            "free_bytes": 400,
            "percent": 60.0,
        }],
        "network": [{
            "interface": "eth0",
            "bytes_sent": 100,
            "bytes_received": 200,
            "packets_sent": 3,
            "packets_received": 4,
        }],
        "services": [{"name": "api.service", "active_state": "active"}],
    }

    try:
        with TestClient(app) as client:
            response = client.post("/api/v1/telemetry", json=payload)
            assert response.status_code == 200, response.text
            result = response.json()
            assert result["accepted"] is True
            assert result["metrics_recorded"] == 18
            assert result["services_updated"] == 1

            with TestingSession() as session:
                session.add(Incident(
                    host_id=uuid.UUID(result["host_id"]),
                    title="Test incident",
                    status="open",
                    severity="critical",
                    detected_at=datetime.now(timezone.utc),
                ))
                session.commit()

            scrape = client.get("/metrics")
            assert scrape.status_code == 200
            assert "text/plain" in scrape.headers["content-type"]
            assert 'opstrace_host_cpu_usage_percent{hostname="metrics-host"} 42.5' in scrape.text
            assert 'opstrace_host_disk_usage_percent{hostname="metrics-host",mountpoint="/"} 60.0' in scrape.text
            assert 'opstrace_host_network_bytes_total{direction="sent",hostname="metrics-host",interface="eth0"} 100.0' in scrape.text
            assert 'opstrace_service_up{hostname="metrics-host",service="api.service"} 1.0' in scrape.text
            assert 'opstrace_incidents{severity="critical",status="open"} 1.0' in scrape.text

        with TestingSession() as session:
            assert session.query(Host).filter_by(hostname="metrics-host").count() == 1
            assert session.query(Service).filter_by(name="api.service").count() == 1
            assert session.query(Metric).filter_by(host_id=uuid.UUID(result["host_id"])).count() == 18
    finally:
        app.dependency_overrides.clear()
        Base.metadata.drop_all(bind=engine)

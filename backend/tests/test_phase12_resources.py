"""
OpsTrace Phase 12 — Observability Resources API Tests
======================================================
Tests the Phase 12 resource API endpoints (hosts, services, incidents, remediations).

Run:
    pytest backend/tests/test_phase12_resources.py -v
"""

import sys
import uuid
from datetime import datetime, timezone
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import StaticPool, create_engine
from sqlalchemy.orm import sessionmaker

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
BACKEND_DIR = REPO_ROOT / "backend"
for _p in (str(REPO_ROOT), str(BACKEND_DIR)):
    if _p not in sys.path:
        sys.path.insert(0, _p)

from backend.app.application import create_app
from backend.app.core.database import get_db
from backend.app.models import Base, Host, Service, Incident, Remediation

SQLITE_TEST_URL = "sqlite:///:memory:"

_test_engine = create_engine(
    SQLITE_TEST_URL,
    connect_args={"check_same_thread": False},
    poolclass=StaticPool,
)
_TestingSessionLocal = sessionmaker(
    autocommit=False,
    autoflush=False,
    bind=_test_engine,
)


def _override_get_db():
    db = _TestingSessionLocal()
    try:
        yield db
    finally:
        db.close()


@pytest.fixture(scope="module")
def session():
    Base.metadata.create_all(bind=_test_engine)
    db = _TestingSessionLocal()
    try:
        yield db
    finally:
        db.close()
        Base.metadata.drop_all(bind=_test_engine)
        _test_engine.dispose()


@pytest.fixture(scope="module")
def client(session) -> TestClient:
    app = create_app()
    app.dependency_overrides[get_db] = _override_get_db
    with TestClient(app, raise_server_exceptions=True) as c:
        yield c


@pytest.fixture(scope="module")
def seed_data(session):
    h = Host(
        hostname="web-server-01",
        ip_address="192.168.1.10",
        status="healthy",
        os_info="Ubuntu 22.04 LTS",
        kernel_version="5.15.0-88-generic",
    )
    session.add(h)
    session.flush()

    s = Service(
        name="web-api",
        host_id=h.id,
        service_type="web",
        port=8080,
        status="degraded",
    )
    session.add(s)
    session.flush()

    inc = Incident(
        title="High CPU Usage",
        description="CPU utilization exceeded 90%",
        status="open",
        severity="critical",
        detected_at=datetime.now(timezone.utc),
        host_id=h.id,
        service_id=s.id,
    )
    session.add(inc)
    session.flush()

    rem = Remediation(
        incident_id=inc.id,
        action_type="restart_service",
        description="Restart web-api systemd service",
        status="executed",
        execution_output="Service restarted successfully.",
    )
    session.add(rem)
    session.commit()
    return {"host": h, "service": s, "incident": inc, "remediation": rem}


class TestResourcesAPI:
    def test_list_hosts(self, client, seed_data):
        res = client.get("/api/v1/hosts")
        assert res.status_code == 200
        hosts = res.json()
        assert len(hosts) >= 1
        assert hosts[0]["hostname"] == "web-server-01"
        assert hosts[0]["services_count"] == 1

    def test_list_services(self, client, seed_data):
        res = client.get("/api/v1/services")
        assert res.status_code == 200
        services = res.json()
        assert len(services) >= 1
        assert services[0]["name"] == "web-api"
        assert services[0]["hostname"] == "web-server-01"

    def test_list_incidents(self, client, seed_data):
        res = client.get("/api/v1/incidents")
        assert res.status_code == 200
        incidents = res.json()
        assert len(incidents) >= 1
        assert incidents[0]["title"] == "High CPU Usage"
        assert incidents[0]["severity"] == "critical"

    def test_get_single_incident(self, client, seed_data):
        inc_id = str(seed_data["incident"].id)
        res = client.get(f"/api/v1/incidents/{inc_id}")
        assert res.status_code == 200
        inc = res.json()
        assert inc["id"] == inc_id
        assert len(inc["remediations"]) == 1
        assert inc["remediations"][0]["action_type"] == "restart_service"

    def test_get_nonexistent_incident(self, client):
        fake_id = str(uuid.uuid4())
        res = client.get(f"/api/v1/incidents/{fake_id}")
        assert res.status_code == 404

    def test_list_remediations(self, client, seed_data):
        res = client.get("/api/v1/remediations")
        assert res.status_code == 200
        rems = res.json()
        assert len(rems) >= 1
        assert rems[0]["status"] == "executed"

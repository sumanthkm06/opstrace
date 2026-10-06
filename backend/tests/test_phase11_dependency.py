import pytest
import uuid
from fastapi.testclient import TestClient
import sys
from pathlib import Path

# sys.path bootstrap
REPO_ROOT = Path(__file__).resolve().parent.parent.parent
BACKEND_DIR = REPO_ROOT / "backend"
for _p in (str(REPO_ROOT), str(BACKEND_DIR)):
    if _p not in sys.path:
        sys.path.insert(0, _p)

from backend.app.application import create_app
from backend.app.core.database import get_db
from backend.app.models.host import Host
from backend.app.models.service import Service
from backend.app.models.service_dependency import ServiceDependency
from backend.app.schemas.dependency import DependencyImpactAnalysis
from backend.app.models import Base
from sqlalchemy import create_engine, StaticPool
from sqlalchemy.orm import sessionmaker

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

@pytest.fixture
def session():
    Base.metadata.create_all(bind=_test_engine)
    db = _TestingSessionLocal()
    yield db
    db.close()
    Base.metadata.drop_all(bind=_test_engine)

@pytest.fixture
def client(session):
    app = create_app()
    app.dependency_overrides[get_db] = _override_get_db
    with TestClient(app) as c:
        yield c
    app.dependency_overrides.clear()

@pytest.fixture
def graph_data(session):
    host1 = Host(id=uuid.uuid4(), hostname="host1", ip_address="10.0.0.1", os_info="ubuntu")
    host2 = Host(id=uuid.uuid4(), hostname="host2", ip_address="10.0.0.2", os_info="ubuntu")
    session.add_all([host1, host2])
    
    # A -> B -> C
    # A -> D
    svc_a = Service(id=uuid.uuid4(), host_id=host1.id, name="service_a", port=8080)
    svc_b = Service(id=uuid.uuid4(), host_id=host1.id, name="service_b", port=8081)
    svc_c = Service(id=uuid.uuid4(), host_id=host2.id, name="service_c", port=8082)
    svc_d = Service(id=uuid.uuid4(), host_id=host2.id, name="service_d", port=8083)
    session.add_all([svc_a, svc_b, svc_c, svc_d])
    
    # dependencies: 
    # A depends on B
    dep1 = ServiceDependency(service_id=svc_a.id, depends_on_service_id=svc_b.id, dependency_type="synchronous")
    # B depends on C
    dep2 = ServiceDependency(service_id=svc_b.id, depends_on_service_id=svc_c.id, dependency_type="asynchronous")
    # A depends on D
    dep3 = ServiceDependency(service_id=svc_a.id, depends_on_service_id=svc_d.id, dependency_type="database")
    
    session.add_all([dep1, dep2, dep3])
    session.commit()
    
    return {
        "host1": host1, "host2": host2,
        "svc_a": svc_a, "svc_b": svc_b, "svc_c": svc_c, "svc_d": svc_d
    }

class TestDependencyAPI:
    def test_get_impact_downstream(self, client, graph_data):
        svc_c = graph_data["svc_c"]
        resp = client.get(f"/api/v1/dependencies/service/{svc_c.id}/impact")
        assert resp.status_code == 200
        data = resp.json()
        assert data["service_id"] == str(svc_c.id)
        # B depends on C, A depends on B.
        # So C's downstream impacts are B and A.
        assert len(data["downstream_impacts"]) == 2
        # C has no upstream dependencies
        assert len(data["upstream_dependencies"]) == 0
        
        downstream_names = set([n["service_name"] for n in data["downstream_impacts"]])
        assert "service_b" in downstream_names
        assert "service_a" in downstream_names

    def test_get_impact_upstream(self, client, graph_data):
        svc_a = graph_data["svc_a"]
        resp = client.get(f"/api/v1/dependencies/service/{svc_a.id}/impact")
        assert resp.status_code == 200
        data = resp.json()
        assert data["service_id"] == str(svc_a.id)
        # A's downstream is empty
        assert len(data["downstream_impacts"]) == 0
        # A depends on B, D. B depends on C.
        assert len(data["upstream_dependencies"]) == 3
        
        upstream_names = set([n["service_name"] for n in data["upstream_dependencies"]])
        assert "service_b" in upstream_names
        assert "service_c" in upstream_names
        assert "service_d" in upstream_names

    def test_get_impact_not_found(self, client):
        resp = client.get(f"/api/v1/dependencies/service/{uuid.uuid4()}/impact")
        assert resp.status_code == 404, f"Expected 404 but got {resp.status_code}: {resp.text}"

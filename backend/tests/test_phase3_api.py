"""
OpsTrace Phase 3 — FastAPI Backend Foundation Tests
====================================================
Tests the FastAPI application layer built in Phase 3.

All tests use FastAPI's TestClient with a SQLite in-memory database
override so no PostgreSQL connection is required.

Run from the repository root:
    pytest backend/tests/test_phase3_api.py -v

Run alongside Phase 2 tests:
    pytest backend/tests/ -v
"""

import sys
from datetime import datetime
from pathlib import Path
from typing import Generator

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import StaticPool, create_engine
from sqlalchemy.orm import sessionmaker

# ---------------------------------------------------------------------------
# sys.path bootstrap — identical to test_phase2_models.py
# ---------------------------------------------------------------------------
REPO_ROOT = Path(__file__).resolve().parent.parent.parent   # opstrace/
BACKEND_DIR = REPO_ROOT / "backend"
for _p in (str(REPO_ROOT), str(BACKEND_DIR)):
    if _p not in sys.path:
        sys.path.insert(0, _p)

# ---------------------------------------------------------------------------
# Imports under test
# ---------------------------------------------------------------------------
from backend.app.application import create_app          # noqa: E402
from backend.app.core.database import get_db            # noqa: E402
from backend.app.models import Base                     # noqa: E402

# ---------------------------------------------------------------------------
# SQLite in-memory database for tests
# ---------------------------------------------------------------------------

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


def _override_get_db() -> Generator:
    """Dependency override: yields a SQLite session instead of PostgreSQL."""
    db = _TestingSessionLocal()
    try:
        yield db
    finally:
        db.close()


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture(scope="module")
def test_app():
    """
    Module-scoped FastAPI app with:
      - All Phase 2 tables created in SQLite in-memory.
      - get_db dependency overridden to use SQLite.
    """
    # Create all Phase 2 tables in SQLite
    Base.metadata.create_all(bind=_test_engine)

    app = create_app()
    app.dependency_overrides[get_db] = _override_get_db
    yield app

    # Teardown
    app.dependency_overrides.clear()
    Base.metadata.drop_all(bind=_test_engine)
    _test_engine.dispose()


@pytest.fixture(scope="module")
def client(test_app) -> TestClient:
    """Module-scoped TestClient bound to the test application."""
    with TestClient(test_app, raise_server_exceptions=True) as c:
        yield c


# ===========================================================================
# TEST SECTION 1: Application Imports
# ===========================================================================

class TestApplicationImports:
    """Phase 3 module imports succeed without errors."""

    def test_create_app_importable(self):
        """create_app factory function is importable."""
        from backend.app.application import create_app as _ca
        assert callable(_ca)

    def test_app_schemas_importable(self):
        """Health response schemas are importable."""
        from backend.app.schemas.health import HealthResponse, APIHealthResponse
        assert HealthResponse is not None
        assert APIHealthResponse is not None

    def test_root_health_router_importable(self):
        """Root health router is importable."""
        from backend.app.api.health import router
        assert router is not None

    def test_v1_health_router_importable(self):
        """API v1 health router is importable."""
        from backend.app.api.v1.health import router
        assert router is not None

    def test_v1_router_importable(self):
        """API v1 router registry is importable."""
        from backend.app.api.v1.router import api_v1_router
        assert api_v1_router is not None

    def test_main_module_has_app(self):
        """backend.main exposes an 'app' FastAPI instance."""
        # Import lazily to avoid creating a second engine at collection time
        import importlib
        main_mod = importlib.import_module("backend.main")
        assert hasattr(main_mod, "app"), "backend.main must expose 'app'"

    def test_phase2_models_still_importable(self):
        """Phase 2 models are unaffected by Phase 3 changes."""
        from backend.app.models import (
            Base, Host, Service, Metric, Log, Deployment,
            ConfigChange, Incident, IncidentEvent, Remediation, AuditEvent,
            ServiceDependency,
        )
        assert len(Base.metadata.tables) == 11


# ===========================================================================
# TEST SECTION 2: Application Creation
# ===========================================================================

class TestApplicationCreation:
    """FastAPI application instance is created correctly."""

    def test_create_app_returns_fastapi_instance(self):
        """create_app() returns a FastAPI object."""
        from fastapi import FastAPI
        app = create_app()
        assert isinstance(app, FastAPI)

    def test_app_title(self, test_app):
        """Application title is set correctly."""
        assert test_app.title == "OpsTrace"

    def test_app_version(self, test_app):
        """Application version is set."""
        assert test_app.version == "0.3.0"

    def test_app_has_docs_url(self, test_app):
        """OpenAPI docs URL is configured."""
        assert test_app.docs_url == "/docs"

    def test_app_has_redoc_url(self, test_app):
        """ReDoc URL is configured."""
        assert test_app.redoc_url == "/redoc"

    def test_app_has_openapi_url(self, test_app):
        """OpenAPI JSON URL is configured."""
        assert test_app.openapi_url == "/openapi.json"


# ===========================================================================
# TEST SECTION 3: OpenAPI Endpoints
# ===========================================================================

class TestOpenAPIEndpoints:
    """FastAPI auto-generated OpenAPI documentation endpoints."""

    def test_openapi_json_returns_200(self, client):
        """GET /openapi.json returns HTTP 200."""
        response = client.get("/openapi.json")
        assert response.status_code == 200

    def test_openapi_json_is_valid_json(self, client):
        """GET /openapi.json response body is valid JSON."""
        response = client.get("/openapi.json")
        data = response.json()
        assert isinstance(data, dict)
        assert "openapi" in data
        assert "info" in data

    def test_openapi_json_contains_health_paths(self, client):
        """OpenAPI spec contains the health endpoint paths."""
        response = client.get("/openapi.json")
        paths = response.json().get("paths", {})
        assert "/health" in paths, f"Expected /health in paths, got: {list(paths.keys())}"
        assert "/api/v1/health" in paths, "Expected /api/v1/health in paths"

    def test_docs_url_returns_200(self, client):
        """GET /docs returns HTTP 200."""
        response = client.get("/docs")
        assert response.status_code == 200

    def test_redoc_url_returns_200(self, client):
        """GET /redoc returns HTTP 200."""
        response = client.get("/redoc")
        assert response.status_code == 200


# ===========================================================================
# TEST SECTION 4: GET /health (Root Liveness Probe)
# ===========================================================================

class TestRootHealthEndpoint:
    """GET /health — lightweight liveness probe."""

    def test_health_returns_200(self, client):
        """GET /health returns HTTP 200."""
        response = client.get("/health")
        assert response.status_code == 200

    def test_health_content_type_is_json(self, client):
        """GET /health returns application/json."""
        response = client.get("/health")
        assert "application/json" in response.headers.get("content-type", "")

    def test_health_response_is_valid_json(self, client):
        """GET /health response body is valid JSON."""
        response = client.get("/health")
        data = response.json()
        assert isinstance(data, dict)

    def test_health_status_is_ok(self, client):
        """GET /health returns status='ok'."""
        data = client.get("/health").json()
        assert data["status"] == "ok"

    def test_health_service_field(self, client):
        """GET /health response includes 'service' field."""
        data = client.get("/health").json()
        assert data["service"] == "opstrace-backend"

    def test_health_version_field(self, client):
        """GET /health response includes 'version' field."""
        data = client.get("/health").json()
        assert "version" in data
        assert isinstance(data["version"], str)
        assert len(data["version"]) > 0

    def test_health_environment_field(self, client):
        """GET /health response includes 'environment' field."""
        data = client.get("/health").json()
        assert "environment" in data
        assert isinstance(data["environment"], str)

    def test_health_timestamp_field(self, client):
        """GET /health response includes a parseable 'timestamp' field."""
        data = client.get("/health").json()
        assert "timestamp" in data
        # Should be an ISO 8601 string
        ts = data["timestamp"]
        assert isinstance(ts, str)
        # Attempt to parse it
        parsed = datetime.fromisoformat(ts.replace("Z", "+00:00"))
        assert isinstance(parsed, datetime)

    def test_health_has_all_required_fields(self, client):
        """GET /health response has all schema-required fields."""
        data = client.get("/health").json()
        required = {"status", "service", "version", "environment", "timestamp"}
        missing = required - set(data.keys())
        assert not missing, f"Missing fields: {missing}"


# ===========================================================================
# TEST SECTION 5: GET /api/v1/health (API Readiness Probe)
# ===========================================================================

class TestAPIv1HealthEndpoint:
    """GET /api/v1/health — readiness probe with database status."""

    def test_api_v1_health_returns_200(self, client):
        """GET /api/v1/health returns HTTP 200."""
        response = client.get("/api/v1/health")
        assert response.status_code == 200

    def test_api_v1_health_content_type_is_json(self, client):
        """GET /api/v1/health returns application/json."""
        response = client.get("/api/v1/health")
        assert "application/json" in response.headers.get("content-type", "")

    def test_api_v1_health_response_is_valid_json(self, client):
        """GET /api/v1/health response body is valid JSON."""
        data = client.get("/api/v1/health").json()
        assert isinstance(data, dict)

    def test_api_v1_health_has_all_required_fields(self, client):
        """GET /api/v1/health has all schema-required fields."""
        data = client.get("/api/v1/health").json()
        required = {
            "status", "service", "version", "environment",
            "api_version", "database", "timestamp",
        }
        missing = required - set(data.keys())
        assert not missing, f"Missing fields: {missing}"

    def test_api_v1_health_service_field(self, client):
        """GET /api/v1/health 'service' is 'opstrace-backend'."""
        data = client.get("/api/v1/health").json()
        assert data["service"] == "opstrace-backend"

    def test_api_v1_health_api_version_field(self, client):
        """GET /api/v1/health 'api_version' is 'v1'."""
        data = client.get("/api/v1/health").json()
        assert data["api_version"] == "v1"

    def test_api_v1_health_database_field_is_dict(self, client):
        """GET /api/v1/health 'database' field is a dict."""
        data = client.get("/api/v1/health").json()
        assert isinstance(data["database"], dict)

    def test_api_v1_health_database_has_connected_field(self, client):
        """GET /api/v1/health database status has 'connected' bool."""
        data = client.get("/api/v1/health").json()
        db = data["database"]
        assert "connected" in db
        assert isinstance(db["connected"], bool)

    def test_api_v1_health_database_has_message_field(self, client):
        """GET /api/v1/health database status has 'message' string."""
        data = client.get("/api/v1/health").json()
        db = data["database"]
        assert "message" in db
        assert isinstance(db["message"], str)

    def test_api_v1_health_status_is_ok_or_degraded(self, client):
        """GET /api/v1/health 'status' is one of the allowed values."""
        data = client.get("/api/v1/health").json()
        assert data["status"] in ("ok", "degraded", "error")

    def test_api_v1_health_timestamp_parseable(self, client):
        """GET /api/v1/health 'timestamp' is a parseable ISO 8601 string."""
        data = client.get("/api/v1/health").json()
        ts = data["timestamp"]
        assert isinstance(ts, str)
        parsed = datetime.fromisoformat(ts.replace("Z", "+00:00"))
        assert isinstance(parsed, datetime)

    def test_api_v1_health_version_matches_root(self, client):
        """Both health endpoints report the same version."""
        root_version = client.get("/health").json()["version"]
        v1_version = client.get("/api/v1/health").json()["version"]
        assert root_version == v1_version


# ===========================================================================
# TEST SECTION 6: CORS Middleware
# ===========================================================================

class TestCORSMiddleware:
    """CORS headers are present for development origins."""

    def test_cors_headers_present_for_local_origin(self, client):
        """CORS allows requests from localhost in development mode."""
        response = client.get(
            "/health",
            headers={"Origin": "http://localhost:3000"},
        )
        assert response.status_code == 200
        # In development, allow_origins=["*"] so any origin passes
        # The access-control-allow-origin header should be set
        cors_header = response.headers.get("access-control-allow-origin")
        assert cors_header is not None, (
            "Expected 'access-control-allow-origin' header in response"
        )

    def test_options_preflight_returns_200(self, client):
        """OPTIONS preflight request to /health returns 200."""
        response = client.options(
            "/health",
            headers={
                "Origin": "http://localhost:3000",
                "Access-Control-Request-Method": "GET",
            },
        )
        assert response.status_code == 200


# ===========================================================================
# TEST SECTION 7: 404 Handling
# ===========================================================================

class TestErrorHandling:
    """Unknown routes return clean JSON responses."""

    def test_unknown_route_returns_404(self, client):
        """GET on an unknown path returns HTTP 404."""
        response = client.get("/nonexistent-endpoint-xyz")
        assert response.status_code == 404

    def test_unknown_route_response_is_json(self, client):
        """404 response body is valid JSON."""
        response = client.get("/nonexistent-endpoint-xyz")
        data = response.json()
        assert isinstance(data, dict)

    def test_unknown_api_v1_route_returns_404(self, client):
        """Unknown /api/v1/* routes return HTTP 404."""
        response = client.get("/api/v1/nonexistent")
        assert response.status_code == 404


# ===========================================================================
# TEST SECTION 8: Phase 2 Independence
# ===========================================================================

class TestPhase2Independence:
    """Phase 3 changes do not affect Phase 2 test isolation."""

    def test_all_11_tables_still_in_base_metadata(self):
        """Phase 2 Base.metadata still contains exactly 11 tables."""
        from backend.app.models import Base as Phase2Base
        tables = set(Phase2Base.metadata.tables.keys())
        expected = {
            "hosts", "services", "service_dependencies", "metrics", "logs",
            "deployments", "config_changes", "incidents", "incident_events",
            "remediations", "audit_events",
        }
        assert tables == expected, f"Unexpected table set: {tables}"

    def test_phase2_config_still_works(self):
        """Phase 2 get_settings() is still importable and functional."""
        from backend.app.core.config import get_settings
        settings = get_settings()
        assert settings.ENVIRONMENT is not None

    def test_phase2_database_get_db_still_importable(self):
        """Phase 2 get_db dependency is still importable."""
        from backend.app.core.database import get_db
        assert callable(get_db)

    def test_phase2_check_database_connection_importable(self):
        """Phase 2 check_database_connection is still importable."""
        from backend.app.core.database import check_database_connection
        assert callable(check_database_connection)

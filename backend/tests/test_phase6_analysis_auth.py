"""Dashboard log analysis API contract and authentication coverage."""

from datetime import datetime, timezone

from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from backend.app.application import create_app
from backend.app.core.database import get_db
from backend.app.models import Base, Host, Log


def test_log_analysis_is_readable_without_collector_key_and_preserves_filters():
    engine = create_engine(
        "sqlite:///:memory:", connect_args={"check_same_thread": False}, poolclass=StaticPool
    )
    testing_session = sessionmaker(autocommit=False, autoflush=False, bind=engine)
    Base.metadata.create_all(bind=engine)

    def override_get_db():
        with testing_session() as session:
            yield session

    app = create_app()
    app.dependency_overrides[get_db] = override_get_db
    try:
        with testing_session() as session:
            host = Host(hostname="analysis-dashboard-host")
            session.add(host)
            session.flush()
            session.add_all([
                Log(
                    host_id=host.id,
                    timestamp=datetime(2026, 10, 8, 10, 0, tzinfo=timezone.utc),
                    level="ERROR",
                    message="database connection failed",
                    source="app.log",
                ),
                Log(
                    host_id=host.id,
                    timestamp=datetime(2026, 10, 8, 10, 1, tzinfo=timezone.utc),
                    level="INFO",
                    message="request completed",
                    source="app.log",
                ),
            ])
            session.commit()

        with TestClient(app) as client:
            # No Authorization header: dashboard analysis is a read-only route.
            response = client.get("/api/v1/logs/analyze?limit=1&level=ERROR")

        assert response.status_code == 200, response.text
        payload = response.json()
        assert {
            "analyzed_at",
            "total_logs_analyzed",
            "total_info",
            "total_warnings",
            "total_errors",
            "total_critical",
            "total_unknown",
            "error_groups",
            "unique_error_fingerprints",
            "error_rate_per_minute",
            "error_rate_per_hour",
            "analysis_window_seconds",
            "window_start",
            "window_end",
            "analysis_warnings",
            "analysis_errors",
        } == payload.keys()
        assert payload["total_logs_analyzed"] == 1
        assert payload["total_errors"] == 1
        assert payload["error_groups"][0]["sample_message"] == "database connection failed"
    finally:
        app.dependency_overrides.clear()
        Base.metadata.drop_all(bind=engine)
        engine.dispose()

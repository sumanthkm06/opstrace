from types import SimpleNamespace
import subprocess

import pytest
from fastapi import HTTPException
from fastapi.testclient import TestClient
from pydantic import ValidationError
from sqlalchemy.engine import make_url

from backend.app.api import auth
from backend.app.api.v1 import correlation, logs, simulations
from backend.app.application import create_app
from backend.app.core.config import Settings
from backend.app.schemas.correlation import CorrelateIncidentRequest
from backend.app.schemas.logs import LogIngestRequest
from collector.app.remediators.models import RemediationActionType


def test_invalid_and_missing_collector_keys_are_rejected(monkeypatch):
    monkeypatch.setattr(logs, "get_settings", lambda: SimpleNamespace(
        COLLECTOR_API_KEY="expected-key", ENVIRONMENT="production"
    ))
    client = TestClient(create_app())
    payload = {"events": []}
    assert client.post("/api/v1/logs/ingest", json=payload).status_code == 403
    assert client.post(
        "/api/v1/logs/ingest", json=payload,
        headers={"Authorization": "Bearer wrong-key"},
    ).status_code == 403


def test_production_rejects_protected_request_when_key_is_unconfigured(monkeypatch):
    monkeypatch.setattr(logs, "get_settings", lambda: SimpleNamespace(
        COLLECTOR_API_KEY=None, ENVIRONMENT="production"
    ))
    response = TestClient(create_app()).post("/api/v1/logs/ingest", json={"events": []})
    assert response.status_code == 503
    assert "key" not in response.text.lower()


def test_development_can_leave_collector_auth_unconfigured():
    auth.require_bearer_token("", None, "development")
    with pytest.raises(HTTPException) as caught:
        auth.require_bearer_token("", None, "staging")
    assert caught.value.status_code == 503


def test_admin_key_protects_simulation_endpoint_in_production(monkeypatch):
    monkeypatch.setattr(simulations, "get_settings", lambda: SimpleNamespace(
        ADMIN_API_KEY="admin-key", ENVIRONMENT="production"
    ))
    client = TestClient(create_app())
    body = {"scenario": "SERVICE_FAILURE"}
    assert client.post("/api/v1/simulations/failures", json=body).status_code == 403
    response = client.post(
        "/api/v1/simulations/failures", json=body,
        headers={"Authorization": "Bearer admin-key"},
    )
    assert response.status_code == 200
    assert response.json()["dry_run"] is True


def test_production_configuration_rejects_placeholder_or_short_secrets():
    with pytest.raises(ValidationError, match="Production requires unique credentials"):
        Settings(
            ENVIRONMENT="production",
            POSTGRES_PASSWORD="change_this_in_production",
            COLLECTOR_API_KEY="change_collector_token_secret",
            ADMIN_API_KEY="change_admin_token_secret",
        )
    valid = Settings(
        ENVIRONMENT="production",
        POSTGRES_PASSWORD="p" * 40,
        COLLECTOR_API_KEY="c" * 40,
        ADMIN_API_KEY="a" * 40,
    )
    assert valid.ENVIRONMENT == "production"
    with pytest.raises(ValidationError, match="wildcard origins"):
        Settings(
            ENVIRONMENT="production",
            POSTGRES_PASSWORD="p" * 40,
            COLLECTOR_API_KEY="c" * 40,
            ADMIN_API_KEY="a" * 40,
            CORS_ALLOWED_ORIGINS="*",
        )


def test_database_url_escapes_password_characters():
    # Do not inherit POSTGRES_HOST=database from Docker Compose; this test
    # verifies URL escaping against an explicitly isolated local setting.
    url = make_url(Settings(
        POSTGRES_PASSWORD="p@ss:/?# word",
        POSTGRES_HOST="localhost",
    ).sqlalchemy_database_uri)
    assert url.password == "p@ss:/?# word"
    assert url.host == "localhost"


def test_settings_serialization_does_not_include_secrets_or_database_uri():
    settings = Settings(
        POSTGRES_PASSWORD="p" * 40,
        COLLECTOR_API_KEY="c" * 40,
        ADMIN_API_KEY="a" * 40,
    )
    serialized = str(settings.model_dump())
    assert "p" * 40 not in serialized
    assert "c" * 40 not in serialized
    assert "a" * 40 not in serialized
    assert "sqlalchemy_database_uri" not in serialized


def test_malformed_and_unexpected_request_fields_are_rejected():
    with pytest.raises(ValidationError):
        LogIngestRequest.model_validate({"events": [], "command": "shutdown"})
    with pytest.raises(ValidationError):
        LogIngestRequest.model_validate({"events": [{"message": "x", "unexpected": True}]})
    with pytest.raises(ValidationError):
        CorrelateIncidentRequest.model_validate({"lookback_minutes": 60, "shell": "true"})
    with pytest.raises(ValidationError):
        LogIngestRequest.model_validate({"events": [{"message": "x" * 16_385}]})


def test_invalid_remediation_action_is_rejected():
    with pytest.raises(ValueError):
        RemediationActionType("run_command")


def test_failure_simulation_never_invokes_subprocess(monkeypatch):
    from backend.app.services.failure_simulation import FailureScenario, FailureSimulator, SimulationRequest

    def reject_command(*args, **kwargs):
        raise AssertionError("simulation attempted to execute a process")

    monkeypatch.setattr(subprocess, "run", reject_command)
    result = FailureSimulator().run(SimulationRequest(scenario=FailureScenario.SERVICE_FAILURE))
    assert result.incident is not None


def test_correlation_error_response_does_not_expose_exception_text(monkeypatch):
    class BrokenEngine:
        def __init__(self, **kwargs):
            pass

        def correlate_and_persist_incident(self, **kwargs):
            raise RuntimeError("secret-database-password")

    monkeypatch.setattr(correlation, "ChangeCorrelationEngine", BrokenEngine)
    with pytest.raises(HTTPException) as caught:
        correlation.correlate_incident_changes(
            incident_id="00000000-0000-0000-0000-000000000001",
            payload=CorrelateIncidentRequest(),
            db=object(),
        )
    assert caught.value.status_code == 500
    assert "secret-database-password" not in caught.value.detail


def test_cors_is_explicit_and_does_not_reflect_arbitrary_origins():
    client = TestClient(create_app())
    response = client.get("/health", headers={"Origin": "https://attacker.invalid"})
    assert "access-control-allow-origin" not in response.headers
    local = client.get("/health", headers={"Origin": "http://localhost:3000"})
    assert local.headers.get("access-control-allow-origin") == "http://localhost:3000"


def test_internal_metrics_route_is_not_registered_under_versioned_api():
    paths = create_app().openapi()["paths"]
    assert not any("metrics" in path and path.startswith("/api/v1") for path in paths)
    assert not any(path.startswith("/api/v1/database") for path in paths)


def test_path_like_log_source_is_data_and_does_not_open_a_file(monkeypatch, tmp_path):
    # A path-looking log label is accepted as text; the ingest schema does not
    # map it to a filesystem operation. No API provides arbitrary file reads.
    payload = LogIngestRequest.model_validate({
        "events": [{"message": "fixture", "source": "../../../../Windows/System32/hosts"}]
    })
    assert payload.events[0].source.endswith("hosts")
    assert list(tmp_path.iterdir()) == []

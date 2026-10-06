import pytest
from fastapi.testclient import TestClient
from pydantic import ValidationError
from types import SimpleNamespace

from backend.app.api.v1 import simulations
from backend.app.application import create_app
from backend.app.services.failure_simulation import (
    CORRELATION_DISCLAIMER,
    FailureScenario,
    FailureSimulator,
    SimulationRequest,
)


@pytest.mark.parametrize("scenario", list(FailureScenario))
def test_all_scenarios_are_safe_and_detectable(scenario):
    result = FailureSimulator().run(SimulationRequest(scenario=scenario))
    assert result.dry_run is True
    assert result.generated_events
    assert result.incident
    assert result.remediation
    assert all(item["dry_run"] for item in result.remediation["results"])


def test_simulation_request_rejects_unsafe_fields_and_execution_mode():
    with pytest.raises(ValidationError):
        SimulationRequest(scenario="SERVICE_FAILURE", dry_run=False)
    with pytest.raises(ValidationError):
        SimulationRequest(scenario="SERVICE_FAILURE", command="shutdown")
    with pytest.raises(ValidationError):
        SimulationRequest(scenario="NOT_A_SCENARIO")


def test_high_error_rate_generates_100_requests_with_30_errors():
    result = FailureSimulator().run(SimulationRequest(scenario=FailureScenario.HIGH_ERROR_RATE))
    assert len(result.generated_events) == 100
    assert result.analysis["total_errors"] == 30
    assert result.incident["incident_type"] == "HIGH_ERROR_RATE"


def test_dependency_impact_uses_isolated_phase11_engine():
    result = FailureSimulator().run(SimulationRequest(scenario=FailureScenario.DEPENDENCY_FAILURE))
    assert result.impacted_services == ["service-b", "service-a"]


def test_change_scenario_preserves_non_causal_disclaimer():
    result = FailureSimulator().run(SimulationRequest(scenario=FailureScenario.CHANGE_RELATED_FAILURE))
    assert result.candidate_change
    assert result.correlation_disclaimer == CORRELATION_DISCLAIMER


def test_repeated_runs_have_same_synthetic_fixture_output():
    request = SimulationRequest(scenario=FailureScenario.CRITICAL_ERROR)
    first = FailureSimulator().run(request)
    second = FailureSimulator().run(request)
    assert {k: v for k, v in first.analysis.items() if k != "analyzed_at"} == {
        k: v for k, v in second.analysis.items() if k != "analyzed_at"
    }
    assert first.generated_events == second.generated_events


def test_api_registers_safe_endpoint_and_rejects_extra_commands(monkeypatch):
    # Isolate this local-development contract from ADMIN_API_KEY inherited
    # from a surrounding Compose environment. Production auth is covered by
    # the Phase 20 security suite.
    monkeypatch.setattr(
        simulations,
        "get_settings",
        lambda: SimpleNamespace(ADMIN_API_KEY=None, ENVIRONMENT="testing"),
    )
    client = TestClient(create_app())
    response = client.post("/api/v1/simulations/failures", json={"scenario": "SERVICE_FAILURE"})
    assert response.status_code == 200
    assert response.json()["dry_run"] is True
    unsafe = client.post("/api/v1/simulations/failures", json={"scenario": "SERVICE_FAILURE", "command": "shutdown"})
    assert unsafe.status_code == 422
    with pytest.raises(ValidationError):
        SimulationRequest(scenario="SERVICE_FAILURE", command="shutdown")

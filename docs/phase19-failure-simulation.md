# Phase 19 — Controlled Failure Simulation

## Purpose

Phase 19 adds a fixture-only demonstration of how OpsTrace analyzes synthetic failure events. It is intended for local demonstrations and automated tests, not fault injection against running infrastructure.

## Scenarios

`POST /api/v1/simulations/failures` accepts one `scenario` enum:

| Scenario | Synthetic input |
| --- | --- |
| `SERVICE_FAILURE` | An unavailable payment service event |
| `HIGH_ERROR_RATE` | 100 request events, 30 marked as errors |
| `CRITICAL_ERROR` | A critical database connection-pool event |
| `DEPENDENCY_FAILURE` | Service C unavailable in A → B → C graph |
| `CHANGE_RELATED_FAILURE` | A service failure after a synthetic configuration-change fixture |

The API returns generated events, Phase 6 analysis, Phase 7 incident output, a Phase 8 dry-run remediation plan, dependency impacts for the dependency scenario, candidate change attribution where applicable, and an ordered demonstration timeline.

## Safety and dry-run behavior

`dry_run` defaults to `true`; requests that set it to `false` are rejected. Extra request fields are forbidden, so the API has no command or target field. Scenarios are selected from a closed enum. Events and the service graph exist only as test fixtures. Dependency analysis uses a fresh in-memory SQLite database per dependency simulation. No configured OpsTrace database, host process, Windows service, filesystem target, network service, cloud resource, or shell command is accessed. Remediation uses the existing allowlisted Phase 8 planner in dry-run mode; it does not execute service actions.

## Architecture and workflow

The Phase 19 service creates deterministic synthetic `CollectedLogEvent` fixtures and sends them through the existing Phase 6 `LogAnalyzer`, then the Phase 7 `IncidentDetector`. It passes detections to the existing Phase 8 `RemediationEngine` with `dry_run=True`. For `DEPENDENCY_FAILURE`, it seeds only an in-memory graph and calls the existing Phase 11 `DependencyEngine`.

The response timeline is a fixture-level chronological demonstration assembled from generated logs and detected incident output. The Phase 10 database timeline engine is read-only and requires persisted incident records; Phase 19 does not persist these demonstration records. The change-related scenario provides an explicit synthetic candidate change and the required disclaimer; it does not claim a Phase 9 persisted correlation result.

## Example

```json
{
  "scenario": "DEPENDENCY_FAILURE"
}
```

The response identifies Service C as the failed fixture and reports downstream services B and A from the Phase 11 graph traversal. The response also contains the detected incident and dry-run recommendation.

## Dashboard

No dashboard controls were added. The API is available for a later small UI integration without changing the existing dashboard layout in this phase.

## Tests

`backend/tests/test_phase19_simulation.py` covers all five scenarios, dry-run enforcement, closed request fields, high-error counts, dependency traversal, change disclaimer, deterministic fixture outputs, and API request behavior. Verification: `python -m pytest collector/tests/ -v --tb=short` passed (340 tests); `python -m pytest backend/tests/ -v --tb=short` passed (119 tests). Docker is unavailable in this environment, so isolated Compose execution was not run. No AWS resources were used or created.

## Limitations

- Simulation output is returned in the API response and is not retained for later retrieval.
- Phase 9 correlation is represented as a synthetic candidate fixture rather than invoking database-backed correlation persistence.
- Phase 10 timelines are represented in the response and are not persisted/replayed by the database-backed timeline engine.
- The dashboard has no simulation panel.
- No Docker-based or AWS execution is part of Phase 19.

## Demonstration

Run the backend locally, then send a JSON POST to `/api/v1/simulations/failures` with one enum scenario. The run is always dry-run. Inspect `analysis`, `incident`, `remediation`, and, for dependency failure, `impacted_services`. Change-related output includes `correlation_disclaimer` verbatim.

"""Safe, fixture-only demonstrations of the OpsTrace incident workflow."""
from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone
from enum import Enum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator
from sqlalchemy import create_engine
from sqlalchemy.orm import Session

from backend.app.engines.dependency_engine import DependencyEngine
from backend.app.models import Host, Service, ServiceDependency
from backend.app.models.base import Base
from collector.app.analyzers.log_analyzer import LogAnalyzer
from collector.app.collectors.log_models import CollectedLogEvent, LogLevel
from collector.app.detectors.incident_detector import IncidentDetector
from collector.app.detectors.models import DetectionRuleConfig, IncidentDetectionResult
from collector.app.remediators.remediation_engine import RemediationEngine

CORRELATION_DISCLAIMER = "Candidate contributing change. Correlation does not prove causation."


class FailureScenario(str, Enum):
    SERVICE_FAILURE = "SERVICE_FAILURE"
    HIGH_ERROR_RATE = "HIGH_ERROR_RATE"
    CRITICAL_ERROR = "CRITICAL_ERROR"
    DEPENDENCY_FAILURE = "DEPENDENCY_FAILURE"
    CHANGE_RELATED_FAILURE = "CHANGE_RELATED_FAILURE"


class SimulationRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    scenario: FailureScenario
    dry_run: bool = True

    @field_validator("dry_run")
    @classmethod
    def validate_dry_run(cls, value: bool) -> bool:
        if value is not True:
            raise ValueError("Failure simulations are fixture-only and require dry_run=true")
        return value

class SimulationResult(BaseModel):
    simulation_id: uuid.UUID
    scenario: FailureScenario
    dry_run: bool = True
    generated_events: list[dict[str, Any]]
    analysis: dict[str, Any]
    incident: dict[str, Any] | None
    impacted_services: list[str] = Field(default_factory=list)
    candidate_change: str | None = None
    correlation_disclaimer: str | None = None
    remediation: dict[str, Any] | None = None
    timeline: list[dict[str, Any]] = Field(default_factory=list)
    safety: str = "Synthetic fixtures only; no configured database, host service, or infrastructure was accessed."


class FailureSimulator:
    """Run deterministic fixtures through existing analysis/detection/planning code."""

    def run(self, request: SimulationRequest) -> SimulationResult:
        now = datetime(2026, 1, 1, tzinfo=timezone.utc)
        service = "payment-service"
        messages: list[tuple[LogLevel, str]]
        if request.scenario in (FailureScenario.SERVICE_FAILURE, FailureScenario.DEPENDENCY_FAILURE):
            messages = [(LogLevel.ERROR, "service unavailable: synthetic fixture")]
            service = "service-c" if request.scenario == FailureScenario.DEPENDENCY_FAILURE else service
        elif request.scenario == FailureScenario.HIGH_ERROR_RATE:
            messages = [(LogLevel.ERROR if n < 30 else LogLevel.INFO, "synthetic request error" if n < 30 else "synthetic request ok") for n in range(100)]
        elif request.scenario == FailureScenario.CRITICAL_ERROR:
            messages = [(LogLevel.CRITICAL, "Database connection pool exhausted")]
        else:
            messages = [(LogLevel.ERROR, "service unavailable after synthetic configuration change")]

        events = [CollectedLogEvent(timestamp=now + timedelta(seconds=i), hostname="simulation-host", service_name=service,
                                    level=level, message=message, source=service, metadata={"simulation": True})
                  for i, (level, message) in enumerate(messages)]
        analysis = LogAnalyzer().analyze(events)
        config = DetectionRuleConfig(error_rate_warning_threshold=10, error_rate_error_threshold=30,
                                     error_rate_critical_threshold=60)
        detection = IncidentDetector(config=config).detect(analysis, events, "simulation-host", service)
        incident = detection.incidents[0] if detection.incidents else None
        remediation = RemediationEngine(dry_run=True).process(detection).model_dump(mode="json") if incident else None

        impacts: list[str] = []
        if request.scenario == FailureScenario.DEPENDENCY_FAILURE:
            impacts = self._dependency_fixture()

        change = None
        disclaimer = None
        if request.scenario == FailureScenario.CHANGE_RELATED_FAILURE:
            change = "Synthetic config change at 2025-12-31T23:59:00Z (fixture)"
            disclaimer = CORRELATION_DISCLAIMER

        timeline = [{"timestamp": e.timestamp.isoformat(), "event": "synthetic_log", "message": e.message} for e in events]
        if incident:
            timeline.append({"timestamp": incident.first_seen.isoformat() if incident.first_seen else now.isoformat(),
                             "event": "incident_detected", "title": incident.title})
        return SimulationResult(simulation_id=uuid.uuid4(), scenario=request.scenario, generated_events=[e.model_dump(mode="json") for e in events],
                                analysis=analysis.model_dump(mode="json"), incident=incident.model_dump(mode="json") if incident else None,
                                impacted_services=impacts, candidate_change=change, correlation_disclaimer=disclaimer,
                                remediation=remediation, timeline=timeline)

    @staticmethod
    def _dependency_fixture() -> list[str]:
        """Use the Phase 11 engine against an isolated per-run SQLite graph."""
        engine = create_engine("sqlite:///:memory:")
        Base.metadata.create_all(engine)
        with Session(engine) as db:
            host = Host(hostname="simulation-host")
            db.add(host)
            db.flush()
            a, b, c = [Service(host_id=host.id, name=n) for n in ("service-a", "service-b", "service-c")]
            db.add_all([a, b, c]); db.flush()
            db.add_all([ServiceDependency(service_id=a.id, depends_on_service_id=b.id),
                        ServiceDependency(service_id=b.id, depends_on_service_id=c.id)])
            db.flush()
            impact = DependencyEngine().analyze_impact(db, c.id)
            return [node.service_name for node in impact.downstream_impacts]

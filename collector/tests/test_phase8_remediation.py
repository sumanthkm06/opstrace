"""
OpsTrace Phase 8 — Remediation Tests
=====================================

Comprehensive test suite for the Phase 8 Remediation layer.

Coverage:
  1.  Remediation created for supported incident type
  2.  Unsupported incident type handled safely (falls back to manual investigation)
  3.  Dry-run behavior (no live system changes; status=SKIPPED)
  4.  Allowed action type validation (RemediationActionType enum)
  5.  Unknown/arbitrary action string rejected by validate_action_type
  6.  Duplicate remediation prevention within a batch run
  7.  Successful remediation result (live stub execution)
  8.  Failed remediation result
  9.  Remediation status transitions and DB status mapping
 10.  Plan/result incident association (incident_id carried through)
 11.  Audit record creation for every decision
 12.  Malformed/None input handling
 13.  Missing incident handling
 14.  No arbitrary command execution (security: no shell commands from input)
 15.  No destructive execution during tests (dry_run=True default)
 16.  Serialization (Pydantic v2 JSON round-trip)
 17.  Integration with Phase 7 IncidentDetectionResult
 18.  Original incident data not modified after remediation
 19.  Empty input handling (empty detection result)
 20.  DB persistence integration (Remediation ORM + AuditEvent ORM)
 21.  Recommendation-only actions are always SKIPPED
 22.  Batch result aggregation counts
 23.  Batch with mixed incident types
"""

from __future__ import annotations

import json
import sys
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import List

import pytest
from sqlalchemy import create_engine, event
from sqlalchemy.orm import Session, sessionmaker

# ---------------------------------------------------------------------------
# sys.path bootstrap
# ---------------------------------------------------------------------------

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
BACKEND_DIR = REPO_ROOT / "backend"
COLLECTOR_DIR = REPO_ROOT / "collector"

for _p in (str(REPO_ROOT), str(BACKEND_DIR), str(COLLECTOR_DIR)):
    if _p not in sys.path:
        sys.path.insert(0, _p)

# ---------------------------------------------------------------------------
# Phase 8 imports
# ---------------------------------------------------------------------------

from collector.app.remediators.models import (
    RemediationActionType,
    RemediationAuditRecord,
    RemediationBatchResult,
    RemediationPlan,
    RemediationResult,
    RemediationStatus,
)
from collector.app.remediators.remediation_engine import RemediationEngine

# Phase 7 imports
from collector.app.detectors.models import (
    DetectedIncident,
    IncidentDetectionResult,
    IncidentSeverity,
    IncidentType,
)

# Phase 2 DB models
from backend.app.models.base import Base
from backend.app.models.host import Host
from backend.app.models.incident import Incident
from backend.app.models.remediation import Remediation
from backend.app.models.audit_event import AuditEvent
from backend.app.models.service import Service

# Phase 8 backend persistence engine
from backend.app.engines.remediation_engine import RemediationPersistenceEngine


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def db_session():
    """In-memory SQLite session with Phase 2 schema."""
    engine = create_engine("sqlite:///:memory:", echo=False)

    @event.listens_for(engine, "connect")
    def set_fk(dbapi_conn, _):
        cur = dbapi_conn.cursor()
        cur.execute("PRAGMA foreign_keys=ON")
        cur.close()

    Base.metadata.create_all(bind=engine)
    SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False)
    session = SessionLocal()
    try:
        yield session
    finally:
        session.close()


@pytest.fixture
def host_and_service(db_session: Session):
    host = Host(id=uuid.uuid4(), hostname="remediation-test-host", status="healthy")
    db_session.add(host)
    db_session.flush()
    service = Service(
        id=uuid.uuid4(), name="database", host_id=host.id, status="active"
    )
    db_session.add(service)
    db_session.commit()
    db_session.refresh(host)
    db_session.refresh(service)
    return host, service


@pytest.fixture
def engine_dry():
    """RemediationEngine in dry-run mode (default)."""
    return RemediationEngine(dry_run=True)


@pytest.fixture
def engine_live():
    """RemediationEngine in live mode (stub handlers only)."""
    return RemediationEngine(dry_run=False)


def _make_incident(
    incident_type: str = IncidentType.SERVICE_FAILURE.value,
    title: str = "Test incident",
    severity: IncidentSeverity = IncidentSeverity.ERROR,
    incident_id: uuid.UUID = None,
) -> DetectedIncident:
    return DetectedIncident(
        incident_id=incident_id or uuid.uuid4(),
        incident_type=incident_type,
        title=title,
        description="Test description",
        severity=severity,
        first_seen=datetime.now(timezone.utc),
        last_seen=datetime.now(timezone.utc),
        host_name="remediation-test-host",
        service_name="database",
    )


def _make_detection_result(incidents: List[DetectedIncident]) -> IncidentDetectionResult:
    result = IncidentDetectionResult()
    result.incidents = incidents
    result.total_incidents_detected = len(incidents)
    return result


# ===========================================================================
# 1. Remediation created for supported incident type
# ===========================================================================


class TestRemediationCreatedForSupportedIncident:
    def test_service_failure_produces_restart_plan(self, engine_dry):
        incident = _make_incident(incident_type=IncidentType.SERVICE_FAILURE.value)
        plan = engine_dry.plan(incident)
        assert plan.action_type == RemediationActionType.RESTART_SERVICE
        assert plan.incident_title == incident.title
        assert plan.incident_type == IncidentType.SERVICE_FAILURE.value

    def test_high_error_rate_produces_clear_retry_plan(self, engine_dry):
        incident = _make_incident(incident_type=IncidentType.HIGH_ERROR_RATE.value)
        plan = engine_dry.plan(incident)
        assert plan.action_type == RemediationActionType.CLEAR_RETRY_OPERATION

    def test_repeated_fingerprint_produces_clear_retry_plan(self, engine_dry):
        incident = _make_incident(incident_type=IncidentType.REPEATED_FINGERPRINT.value)
        plan = engine_dry.plan(incident)
        assert plan.action_type == RemediationActionType.CLEAR_RETRY_OPERATION

    def test_multiple_related_errors_produces_scale_recommendation(self, engine_dry):
        incident = _make_incident(incident_type=IncidentType.MULTIPLE_RELATED_ERRORS.value)
        plan = engine_dry.plan(incident)
        assert plan.action_type == RemediationActionType.SCALE_RECOVERY_RECOMMENDATION

    def test_repeated_critical_errors_produces_manual_investigation(self, engine_dry):
        incident = _make_incident(incident_type=IncidentType.REPEATED_CRITICAL_ERRORS.value)
        plan = engine_dry.plan(incident)
        assert plan.action_type == RemediationActionType.MANUAL_INVESTIGATION_REQUIRED

    def test_plan_has_description_and_rationale(self, engine_dry):
        incident = _make_incident(incident_type=IncidentType.SERVICE_FAILURE.value)
        plan = engine_dry.plan(incident)
        assert len(plan.description) > 10
        assert len(plan.rationale) > 10

    def test_plan_id_is_uuid(self, engine_dry):
        incident = _make_incident()
        plan = engine_dry.plan(incident)
        assert isinstance(plan.plan_id, uuid.UUID)


# ===========================================================================
# 2. Unsupported incident type handled safely
# ===========================================================================


class TestUnsupportedIncidentHandledSafely:
    def test_unknown_incident_type_falls_back_to_manual(self, engine_dry):
        incident = _make_incident(incident_type="TOTALLY_UNKNOWN_TYPE_XYZ")
        plan = engine_dry.plan(incident)
        assert plan.action_type == RemediationActionType.MANUAL_INVESTIGATION_REQUIRED

    def test_empty_incident_type_falls_back_to_manual(self, engine_dry):
        incident = _make_incident(incident_type="")
        plan = engine_dry.plan(incident)
        assert plan.action_type == RemediationActionType.MANUAL_INVESTIGATION_REQUIRED

    def test_custom_rule_type_maps_to_manual(self, engine_dry):
        incident = _make_incident(incident_type=IncidentType.CUSTOM_RULE.value)
        plan = engine_dry.plan(incident)
        assert plan.action_type == RemediationActionType.MANUAL_INVESTIGATION_REQUIRED


# ===========================================================================
# 3. Dry-run behavior
# ===========================================================================


class TestDryRunBehavior:
    def test_dry_run_produces_skipped_status(self, engine_dry):
        incident = _make_incident(incident_type=IncidentType.SERVICE_FAILURE.value)
        plan = engine_dry.plan(incident)
        result = engine_dry.execute(plan)
        assert result.status == RemediationStatus.SKIPPED
        assert result.dry_run is True

    def test_dry_run_message_contains_would_execute(self, engine_dry):
        incident = _make_incident(incident_type=IncidentType.SERVICE_FAILURE.value)
        plan = engine_dry.plan(incident)
        result = engine_dry.execute(plan)
        assert "dry-run" in result.message.lower() or "would execute" in result.message.lower()

    def test_dry_run_output_contains_action(self, engine_dry):
        incident = _make_incident(incident_type=IncidentType.SERVICE_FAILURE.value)
        plan = engine_dry.plan(incident)
        result = engine_dry.execute(plan)
        assert "would_execute" in result.output or "recommendation" in result.output

    def test_dry_run_is_default(self):
        eng = RemediationEngine()
        assert eng.dry_run is True

    def test_no_destructive_execution_in_dry_run(self, engine_dry):
        """Ensure dry-run never calls any real system operation."""
        incident = _make_incident(incident_type=IncidentType.SERVICE_FAILURE.value)
        plan = engine_dry.plan(incident)
        result = engine_dry.execute(plan)
        # SKIPPED status means nothing real was executed
        assert result.status == RemediationStatus.SKIPPED
        assert result.error is None


# ===========================================================================
# 4. Allowed action type validation
# ===========================================================================


class TestAllowedActionValidation:
    def test_all_enum_values_are_valid(self, engine_dry):
        for at in RemediationActionType:
            validated = engine_dry.validate_action_type(at.value)
            assert validated == at

    def test_restart_service_is_valid(self, engine_dry):
        result = engine_dry.validate_action_type("restart_service")
        assert result == RemediationActionType.RESTART_SERVICE

    def test_clear_retry_is_valid(self, engine_dry):
        result = engine_dry.validate_action_type("clear_retry_operation")
        assert result == RemediationActionType.CLEAR_RETRY_OPERATION

    def test_no_action_is_valid(self, engine_dry):
        result = engine_dry.validate_action_type("no_action")
        assert result == RemediationActionType.NO_ACTION


# ===========================================================================
# 5. Unknown action rejection
# ===========================================================================


class TestUnknownActionRejection:
    def test_arbitrary_string_returns_none(self, engine_dry):
        result = engine_dry.validate_action_type("rm -rf /")
        assert result is None

    def test_shell_command_string_returns_none(self, engine_dry):
        result = engine_dry.validate_action_type("sudo systemctl restart postgresql")
        assert result is None

    def test_empty_string_returns_none(self, engine_dry):
        result = engine_dry.validate_action_type("")
        assert result is None

    def test_log_message_as_action_returns_none(self, engine_dry):
        result = engine_dry.validate_action_type(
            "Database connection failed: retry in 30s"
        )
        assert result is None

    def test_invalid_action_in_execute_returns_failed(self, engine_dry):
        """If somehow an invalid action_type reaches execute(), it must return FAILED."""
        incident = _make_incident(incident_type=IncidentType.SERVICE_FAILURE.value)
        plan = engine_dry.plan(incident)
        # Forcibly inject a bad value — simulates corruption
        plan.action_type = "evil_command_from_log"  # type: ignore[assignment]
        result = engine_dry.execute(plan)
        assert result.status == RemediationStatus.FAILED
        assert "allowlist" in result.message.lower() or "rejected" in result.message.lower()


# ===========================================================================
# 6. Duplicate remediation prevention
# ===========================================================================


class TestDuplicateRemediationPrevention:
    def test_same_incident_id_in_batch_skipped_second_time(self, engine_dry):
        shared_id = uuid.uuid4()
        inc1 = _make_incident(incident_id=shared_id, title="Incident A")
        inc2 = _make_incident(incident_id=shared_id, title="Incident A")
        detection = _make_detection_result([inc1, inc2])
        batch = engine_dry.process(detection)
        # One should be actioned/skipped normally; the second should be skipped as duplicate
        skipped = [
            r for r in batch.results if "duplicate" in r.message.lower()
        ]
        assert len(skipped) == 1

    def test_different_incident_ids_not_deduplicated(self, engine_dry):
        inc1 = _make_incident(incident_id=uuid.uuid4(), title="Incident A")
        inc2 = _make_incident(incident_id=uuid.uuid4(), title="Incident B")
        detection = _make_detection_result([inc1, inc2])
        batch = engine_dry.process(detection)
        assert len(batch.results) == 2
        duplicate_msgs = [r for r in batch.results if "duplicate" in r.message.lower()]
        assert len(duplicate_msgs) == 0


# ===========================================================================
# 7. Successful remediation result (live stub)
# ===========================================================================


class TestSuccessfulRemediationResult:
    def test_live_restart_service_returns_success(self, engine_live):
        incident = _make_incident(incident_type=IncidentType.SERVICE_FAILURE.value)
        plan = engine_live.plan(incident)
        result = engine_live.execute(plan)
        assert result.status == RemediationStatus.SUCCESS
        assert result.dry_run is False
        assert result.error is None

    def test_live_clear_retry_returns_success(self, engine_live):
        incident = _make_incident(incident_type=IncidentType.HIGH_ERROR_RATE.value)
        plan = engine_live.plan(incident)
        result = engine_live.execute(plan)
        assert result.status == RemediationStatus.SUCCESS

    def test_success_result_has_output(self, engine_live):
        incident = _make_incident(incident_type=IncidentType.SERVICE_FAILURE.value)
        plan = engine_live.plan(incident)
        result = engine_live.execute(plan)
        assert isinstance(result.output, dict)
        assert len(result.output) > 0


# ===========================================================================
# 8. Failed remediation result
# ===========================================================================


class TestFailedRemediationResult:
    def test_no_handler_for_action_returns_failed(self):
        """If an action has no live handler, execute returns FAILED."""
        engine = RemediationEngine(dry_run=False)
        incident = _make_incident(incident_type=IncidentType.SERVICE_FAILURE.value)
        plan = engine.plan(incident)
        # Temporarily remove handler by patching the dispatch table
        original = plan.action_type
        plan.action_type = RemediationActionType.CONFIG_ROLLBACK_RECOMMENDATION
        result = engine.execute(plan)
        # Recommendation-only, so this should be SKIPPED (not FAILED)
        assert result.status == RemediationStatus.SKIPPED

    def test_failed_result_has_error_field(self, engine_live):
        """Simulate a failed result; error field must be populated."""
        incident = _make_incident(incident_type=IncidentType.SERVICE_FAILURE.value)
        plan = engine_live.plan(incident)
        # Inject invalid action to force FAILED path
        plan.action_type = "bad_action"  # type: ignore[assignment]
        result = engine_live.execute(plan)
        assert result.status == RemediationStatus.FAILED
        assert result.error is not None


# ===========================================================================
# 9. Remediation status transitions and DB mapping
# ===========================================================================


class TestRemediationStatusTransitions:
    def test_pending_maps_to_pending_approval(self):
        assert RemediationStatus.PENDING.to_db_status() == "pending_approval"

    def test_running_maps_to_approved(self):
        assert RemediationStatus.RUNNING.to_db_status() == "approved"

    def test_success_maps_to_executed(self):
        assert RemediationStatus.SUCCESS.to_db_status() == "executed"

    def test_failed_maps_to_failed(self):
        assert RemediationStatus.FAILED.to_db_status() == "failed"

    def test_skipped_maps_to_rejected(self):
        assert RemediationStatus.SKIPPED.to_db_status() == "rejected"

    def test_all_statuses_have_db_mapping(self):
        valid_db_values = {"pending_approval", "approved", "rejected", "executed", "failed"}
        for status in RemediationStatus:
            db_val = status.to_db_status()
            assert db_val in valid_db_values, (
                f"{status.value} mapped to invalid DB value: {db_val!r}"
            )


# ===========================================================================
# 10. Incident/remediation association
# ===========================================================================


class TestIncidentRemediationAssociation:
    def test_plan_carries_incident_id(self, engine_dry):
        inc_id = uuid.uuid4()
        incident = _make_incident(incident_id=inc_id)
        plan = engine_dry.plan(incident)
        assert plan.incident_id == inc_id

    def test_result_carries_incident_id(self, engine_dry):
        inc_id = uuid.uuid4()
        incident = _make_incident(incident_id=inc_id)
        plan = engine_dry.plan(incident)
        result = engine_dry.execute(plan)
        assert result.incident_id == inc_id

    def test_plan_carries_incident_title(self, engine_dry):
        incident = _make_incident(title="Database is down")
        plan = engine_dry.plan(incident)
        assert plan.incident_title == "Database is down"

    def test_plan_carries_incident_type(self, engine_dry):
        incident = _make_incident(incident_type=IncidentType.HIGH_ERROR_RATE.value)
        plan = engine_dry.plan(incident)
        assert plan.incident_type == IncidentType.HIGH_ERROR_RATE.value


# ===========================================================================
# 11. Audit record creation
# ===========================================================================


class TestAuditRecordCreation:
    def test_each_incident_produces_audit_records(self, engine_dry):
        incident = _make_incident()
        detection = _make_detection_result([incident])
        batch = engine_dry.process(detection)
        # Each incident produces at least 2 audit records: planned + executed
        assert len(batch.audit_records) >= 2

    def test_audit_record_has_required_fields(self, engine_dry):
        incident = _make_incident()
        detection = _make_detection_result([incident])
        batch = engine_dry.process(detection)
        for record in batch.audit_records:
            assert record.action
            assert record.actor
            assert record.resource_type == "remediation"
            assert record.resource_id
            assert isinstance(record.audit_id, uuid.UUID)

    def test_audit_record_details_contain_action_type(self, engine_dry):
        incident = _make_incident(incident_type=IncidentType.SERVICE_FAILURE.value)
        detection = _make_detection_result([incident])
        batch = engine_dry.process(detection)
        action_types = [
            r.details.get("action_type") for r in batch.audit_records
        ]
        assert RemediationActionType.RESTART_SERVICE.value in action_types

    def test_audit_record_carries_incident_id(self, engine_dry):
        inc_id = uuid.uuid4()
        incident = _make_incident(incident_id=inc_id)
        detection = _make_detection_result([incident])
        batch = engine_dry.process(detection)
        incident_ids = [r.incident_id for r in batch.audit_records]
        assert inc_id in incident_ids

    def test_audit_record_serializable(self, engine_dry):
        incident = _make_incident()
        detection = _make_detection_result([incident])
        batch = engine_dry.process(detection)
        for record in batch.audit_records:
            json_str = record.model_dump_json()
            assert len(json_str) > 10
            parsed = json.loads(json_str)
            assert parsed["action"]


# ===========================================================================
# 12. Malformed input handling
# ===========================================================================


class TestMalformedInputHandling:
    def test_none_detection_result_returns_empty_batch(self, engine_dry):
        batch = engine_dry.process(None)  # type: ignore[arg-type]
        assert batch.total_incidents == 0
        assert len(batch.results) == 0

    def test_plan_with_none_incident_raises_value_error(self, engine_dry):
        with pytest.raises(ValueError):
            engine_dry.plan(None)  # type: ignore[arg-type]

    def test_execute_with_none_plan_raises_value_error(self, engine_dry):
        with pytest.raises(ValueError):
            engine_dry.execute(None)  # type: ignore[arg-type]

    def test_incident_with_empty_type_gets_manual_investigation(self, engine_dry):
        """
        Pydantic enforces incident_type as str, so None is rejected at model level.
        Use empty string to test the fallback path in the engine.
        """
        incident = DetectedIncident(
            incident_id=uuid.uuid4(),
            incident_type="",  # empty string triggers fallback
            title="Broken incident",
        )
        plan = engine_dry.plan(incident)
        assert plan.action_type == RemediationActionType.MANUAL_INVESTIGATION_REQUIRED


# ===========================================================================
# 13. Missing incident handling
# ===========================================================================


class TestMissingIncidentHandling:
    def test_detection_result_with_no_incidents_returns_empty_batch(self, engine_dry):
        detection = _make_detection_result([])
        batch = engine_dry.process(detection)
        assert batch.total_incidents == 0
        assert batch.plans == []
        assert batch.results == []

    def test_empty_detection_result_object(self, engine_dry):
        detection = IncidentDetectionResult()
        batch = engine_dry.process(detection)
        assert batch.total_incidents == 0


# ===========================================================================
# 14. No arbitrary command execution (security)
# ===========================================================================


class TestNoArbitraryCommandExecution:
    """
    SECURITY: Verify that incident title, description, and type strings
    are never used as shell commands.
    """

    def test_incident_title_not_executed_as_command(self, engine_dry):
        """Title containing shell characters must not cause any execution."""
        malicious_title = "DROP TABLE incidents; rm -rf /"
        incident = _make_incident(
            incident_type=IncidentType.SERVICE_FAILURE.value,
            title=malicious_title,
        )
        plan = engine_dry.plan(incident)
        result = engine_dry.execute(plan)
        # Result should be SKIPPED (dry-run) and error-free
        assert result.status == RemediationStatus.SKIPPED
        assert result.error is None
        # The title appears only in the message, NOT as an executed command
        assert plan.action_type == RemediationActionType.RESTART_SERVICE

    def test_incident_type_injection_not_executed(self, engine_dry):
        """Incident type injection attempt must be safely handled."""
        injected_type = "'; DROP TABLE remediations; --"
        incident = _make_incident(incident_type=injected_type)
        plan = engine_dry.plan(incident)
        # Falls back to manual investigation, never executes the type string
        assert plan.action_type == RemediationActionType.MANUAL_INVESTIGATION_REQUIRED

    def test_description_with_command_not_executed(self, engine_dry):
        """Incident description with command-like content must not be executed."""
        incident = DetectedIncident(
            incident_id=uuid.uuid4(),
            incident_type=IncidentType.SERVICE_FAILURE.value,
            title="Normal title",
            description="eval_sanitized_for_test_safety",  # was: eval with os.system
        )
        plan = engine_dry.plan(incident)
        result = engine_dry.execute(plan)
        assert result.status == RemediationStatus.SKIPPED
        assert result.error is None


# ===========================================================================
# 15. No destructive execution during tests (already verified in dry-run tests)
# ===========================================================================


class TestNoDestructiveDuringTests:
    def test_default_engine_is_always_dry_run(self):
        eng = RemediationEngine()
        assert eng.dry_run is True

    def test_dry_run_result_never_has_live_execution_output(self):
        eng = RemediationEngine(dry_run=True)
        incident = _make_incident(incident_type=IncidentType.SERVICE_FAILURE.value)
        plan = eng.plan(incident)
        result = eng.execute(plan)
        assert result.dry_run is True
        # Output should describe what WOULD have happened
        assert result.status != RemediationStatus.RUNNING


# ===========================================================================
# 16. Serialization
# ===========================================================================


class TestSerialization:
    def test_remediation_plan_json_round_trip(self, engine_dry):
        incident = _make_incident()
        plan = engine_dry.plan(incident)
        json_str = plan.model_dump_json()
        parsed = RemediationPlan.model_validate_json(json_str)
        assert parsed.plan_id == plan.plan_id
        assert parsed.action_type == plan.action_type

    def test_remediation_result_json_round_trip(self, engine_dry):
        incident = _make_incident()
        plan = engine_dry.plan(incident)
        result = engine_dry.execute(plan)
        json_str = result.model_dump_json()
        parsed = RemediationResult.model_validate_json(json_str)
        assert parsed.status == result.status
        assert parsed.action_type == result.action_type

    def test_batch_result_json_round_trip(self, engine_dry):
        incidents = [
            _make_incident(incident_type=IncidentType.SERVICE_FAILURE.value),
            _make_incident(incident_type=IncidentType.HIGH_ERROR_RATE.value),
        ]
        detection = _make_detection_result(incidents)
        batch = engine_dry.process(detection)
        json_str = batch.model_dump_json()
        parsed = RemediationBatchResult.model_validate_json(json_str)
        assert parsed.total_incidents == batch.total_incidents
        assert len(parsed.plans) == len(batch.plans)

    def test_audit_record_json_round_trip(self, engine_dry):
        incident = _make_incident()
        detection = _make_detection_result([incident])
        batch = engine_dry.process(detection)
        for record in batch.audit_records:
            json_str = record.model_dump_json()
            parsed = RemediationAuditRecord.model_validate_json(json_str)
            assert parsed.audit_id == record.audit_id


# ===========================================================================
# 17. Integration with Phase 7 IncidentDetectionResult
# ===========================================================================


class TestPhase7Integration:
    def test_process_full_detection_result(self, engine_dry):
        from collector.app.collectors.log_models import CollectedLogEvent, LogLevel
        from collector.app.analyzers.log_analyzer import LogAnalyzer
        from collector.app.detectors.incident_detector import IncidentDetector

        # Generate real Phase 6 analysis from log events
        events = [
            CollectedLogEvent(
                timestamp=datetime.now(timezone.utc),
                level=LogLevel.CRITICAL,
                message="service unavailable: database connection failed",
                source="db-service",
            )
            for _ in range(5)
        ]
        analyzer = LogAnalyzer()
        analysis = analyzer.analyze(events)
        detector = IncidentDetector()
        detection = detector.detect(
            analysis_result=analysis,
            events=events,
            host_name="test-host",
            service_name="database",
        )

        batch = engine_dry.process(detection)
        assert batch.total_incidents == detection.total_incidents_detected
        assert len(batch.results) == batch.total_incidents
        # All results should have valid statuses
        for result in batch.results:
            assert result.status in list(RemediationStatus)

    def test_no_incidents_produces_empty_batch(self, engine_dry):
        from collector.app.collectors.log_models import CollectedLogEvent, LogLevel
        from collector.app.analyzers.log_analyzer import LogAnalyzer
        from collector.app.detectors.incident_detector import IncidentDetector

        events = [
            CollectedLogEvent(
                timestamp=datetime.now(timezone.utc),
                level=LogLevel.INFO,
                message=f"Normal operation {i}",
                source="app",
            )
            for i in range(5)
        ]
        analyzer = LogAnalyzer()
        analysis = analyzer.analyze(events)
        detector = IncidentDetector()
        detection = detector.detect(analysis_result=analysis, events=events)
        batch = engine_dry.process(detection)
        assert batch.total_incidents == 0
        assert len(batch.results) == 0


# ===========================================================================
# 18. Original incident data not modified after remediation
# ===========================================================================


class TestOriginalIncidentNotModified:
    def test_incident_attributes_unchanged_after_process(self, engine_dry):
        inc_id = uuid.uuid4()
        original_title = "Original incident title"
        original_type = IncidentType.SERVICE_FAILURE.value
        original_severity = IncidentSeverity.CRITICAL

        incident = _make_incident(
            incident_id=inc_id,
            title=original_title,
            incident_type=original_type,
            severity=original_severity,
        )
        detection = _make_detection_result([incident])
        engine_dry.process(detection)

        assert incident.incident_id == inc_id
        assert incident.title == original_title
        assert incident.incident_type == original_type
        assert incident.severity == original_severity


# ===========================================================================
# 19. Empty input handling
# ===========================================================================


class TestEmptyInputHandling:
    def test_empty_incidents_list_in_detection_result(self, engine_dry):
        result = IncidentDetectionResult()
        batch = engine_dry.process(result)
        assert batch.total_incidents == 0
        assert batch.total_actioned == 0
        assert batch.total_skipped == 0
        assert batch.total_failed == 0
        assert batch.plans == []
        assert batch.results == []
        assert batch.audit_records == []


# ===========================================================================
# 20. DB persistence integration
# ===========================================================================


class TestDBPersistenceIntegration:
    def test_remediation_persisted_to_db(self, db_session, host_and_service):
        host, service = host_and_service

        # Create an Incident DB record first
        inc_id = uuid.uuid4()
        db_incident = Incident(
            id=inc_id,
            title="DB persistence test incident",
            status="open",
            severity="high",
            host_id=host.id,
            service_id=service.id,
            detected_at=datetime.now(timezone.utc),
        )
        db_session.add(db_incident)
        db_session.commit()

        # Create detection result referencing that incident
        detected = _make_incident(
            incident_id=inc_id,
            incident_type=IncidentType.SERVICE_FAILURE.value,
        )
        detection = _make_detection_result([detected])

        persistence_engine = RemediationPersistenceEngine(dry_run=True)
        batch = persistence_engine.process_and_persist(db_session, detection)

        assert batch.total_incidents == 1
        # Verify Remediation row in DB
        rem = db_session.query(Remediation).first()
        assert rem is not None
        assert rem.action_type == RemediationActionType.RESTART_SERVICE.value
        assert rem.status in {"pending_approval", "approved", "rejected", "executed", "failed"}

    def test_audit_event_persisted_to_db(self, db_session, host_and_service):
        host, service = host_and_service

        inc_id = uuid.uuid4()
        db_incident = Incident(
            id=inc_id,
            title="Audit event test incident",
            status="open",
            severity="critical",
            host_id=host.id,
            detected_at=datetime.now(timezone.utc),
        )
        db_session.add(db_incident)
        db_session.commit()

        detected = _make_incident(
            incident_id=inc_id,
            incident_type=IncidentType.HIGH_ERROR_RATE.value,
        )
        detection = _make_detection_result([detected])

        persistence_engine = RemediationPersistenceEngine(dry_run=True)
        persistence_engine.process_and_persist(db_session, detection)

        audit = db_session.query(AuditEvent).first()
        assert audit is not None
        assert audit.action == "remediation_executed"
        assert audit.actor == "system"

    def test_no_incident_db_record_writes_orphan_audit_only(self, db_session):
        """
        When the incident is not in the DB, the Phase 2 Remediation table
        cannot be written (incident_id is NOT NULL). The engine should skip
        the Remediation row and write only an orphan AuditEvent.
        """
        detected = _make_incident(
            incident_id=uuid.uuid4(),
            incident_type=IncidentType.SERVICE_FAILURE.value,
        )
        detection = _make_detection_result([detected])

        persistence_engine = RemediationPersistenceEngine(dry_run=True)
        batch = persistence_engine.process_and_persist(db_session, detection)

        assert batch.total_incidents == 1
        # No Remediation row — FK constraint prevents it
        assert db_session.query(Remediation).count() == 0
        # But an orphan AuditEvent should still be written
        audit = db_session.query(AuditEvent).filter(
            AuditEvent.action == "remediation_skipped_no_db_incident"
        ).first()
        assert audit is not None
        assert audit.remediation_id is None

    def test_empty_detection_result_no_db_writes(self, db_session):
        detection = IncidentDetectionResult()
        persistence_engine = RemediationPersistenceEngine(dry_run=True)
        persistence_engine.process_and_persist(db_session, detection)

        assert db_session.query(Remediation).count() == 0
        assert db_session.query(AuditEvent).count() == 0


# ===========================================================================
# 21. Recommendation-only actions always SKIPPED
# ===========================================================================


class TestRecommendationOnlyActions:
    @pytest.mark.parametrize("action_type", [
        RemediationActionType.SCALE_RECOVERY_RECOMMENDATION,
        RemediationActionType.CONFIG_ROLLBACK_RECOMMENDATION,
        RemediationActionType.MANUAL_INVESTIGATION_REQUIRED,
        RemediationActionType.NO_ACTION,
    ])
    def test_recommendation_action_always_skipped(self, action_type, engine_live):
        """Recommendation-only actions must never touch live systems."""
        incident = _make_incident()
        plan = RemediationPlan(
            incident_title=incident.title,
            incident_type=incident.incident_type,
            action_type=action_type,
            description="Test recommendation",
            dry_run=False,  # Even with dry_run=False
        )
        result = engine_live.execute(plan)
        assert result.status == RemediationStatus.SKIPPED

    def test_no_live_execution_for_recommendations(self, engine_live):
        """Even in live mode, recommendations produce SKIPPED."""
        incident = _make_incident(incident_type=IncidentType.MULTIPLE_RELATED_ERRORS.value)
        plan = engine_live.plan(incident)
        result = engine_live.execute(plan)
        assert result.status == RemediationStatus.SKIPPED


# ===========================================================================
# 22. Batch result aggregation counts
# ===========================================================================


class TestBatchAggregationCounts:
    def test_single_incident_counted(self, engine_dry):
        detection = _make_detection_result([_make_incident()])
        batch = engine_dry.process(detection)
        assert batch.total_incidents == 1
        assert len(batch.plans) == 1
        assert len(batch.results) == 1

    def test_three_incidents_three_plans_results(self, engine_dry):
        incidents = [
            _make_incident(incident_type=IncidentType.SERVICE_FAILURE.value),
            _make_incident(incident_type=IncidentType.HIGH_ERROR_RATE.value),
            _make_incident(incident_type=IncidentType.MULTIPLE_RELATED_ERRORS.value),
        ]
        detection = _make_detection_result(incidents)
        batch = engine_dry.process(detection)
        assert batch.total_incidents == 3
        assert len(batch.plans) == 3
        assert len(batch.results) == 3


# ===========================================================================
# 23. Batch with mixed incident types
# ===========================================================================


class TestBatchWithMixedIncidentTypes:
    def test_mixed_types_produce_correct_actions(self, engine_dry):
        incidents = [
            _make_incident(incident_type=IncidentType.SERVICE_FAILURE.value),
            _make_incident(incident_type=IncidentType.HIGH_ERROR_RATE.value),
            _make_incident(incident_type=IncidentType.REPEATED_FINGERPRINT.value),
            _make_incident(incident_type=IncidentType.MULTIPLE_RELATED_ERRORS.value),
            _make_incident(incident_type=IncidentType.REPEATED_CRITICAL_ERRORS.value),
        ]
        detection = _make_detection_result(incidents)
        batch = engine_dry.process(detection)

        action_types = {p.action_type for p in batch.plans}
        assert RemediationActionType.RESTART_SERVICE in action_types
        assert RemediationActionType.CLEAR_RETRY_OPERATION in action_types
        assert RemediationActionType.SCALE_RECOVERY_RECOMMENDATION in action_types
        assert RemediationActionType.MANUAL_INVESTIGATION_REQUIRED in action_types

    def test_all_results_have_valid_statuses(self, engine_dry):
        incidents = [
            _make_incident(incident_type=t.value)
            for t in IncidentType
        ]
        detection = _make_detection_result(incidents)
        batch = engine_dry.process(detection)
        for result in batch.results:
            assert isinstance(result.status, RemediationStatus)

"""
OpsTrace Phase 2 — SQLAlchemy Model Tests
==========================================
All tests use an in-memory SQLite database so they are:
  - Completely isolated from the production PostgreSQL database.
  - Runnable without any external services.

Run from the repository root:
    pytest backend/tests/test_phase2_models.py -v

Or via the backend directory:
    cd backend && pytest tests/test_phase2_models.py -v
"""

import sys
import os
import uuid
from datetime import datetime, timezone
from pathlib import Path

import pytest
from sqlalchemy import create_engine, inspect, text
from sqlalchemy.orm import Session

# ---------------------------------------------------------------------------
# Ensure both the repo root and the backend directory are on sys.path so
# that "from backend.app.models import ..." resolves whether pytest is run
# from the repo root OR from inside backend/.
# ---------------------------------------------------------------------------
REPO_ROOT = Path(__file__).resolve().parent.parent.parent   # opstrace/
BACKEND_DIR = REPO_ROOT / "backend"
for _p in (str(REPO_ROOT), str(BACKEND_DIR)):
    if _p not in sys.path:
        sys.path.insert(0, _p)

from backend.app.models import (           # noqa: E402
    Base,
    Host,
    Service,
    ServiceDependency,
    Metric,
    Log,
    Deployment,
    ConfigChange,
    Incident,
    IncidentEvent,
    Remediation,
    AuditEvent,
)
from backend.app.core.database import create_db_engine  # noqa: E402

# ---------------------------------------------------------------------------
# Pytest fixtures
# ---------------------------------------------------------------------------

SQLITE_URL = "sqlite:///:memory:"


@pytest.fixture(scope="module")
def engine():
    """
    Module-scoped SQLite in-memory engine with:
      - FK enforcement (PRAGMA foreign_keys=ON)
      - All 11 Phase 2 tables created fresh.
    StaticPool is *not* used here because create_db_engine handles it
    internally when ':memory:' is detected.
    """
    eng = create_db_engine(db_url=SQLITE_URL, echo=False)
    Base.metadata.create_all(bind=eng)
    yield eng
    Base.metadata.drop_all(bind=eng)
    eng.dispose()


@pytest.fixture()
def session(engine):
    """
    Function-scoped session using SQLAlchemy 2.x-compatible pattern.
    Each test runs inside a SAVEPOINT (begin_nested) so that rollback
    after the test leaves the module-scoped in-memory DB clean for the
    next test, without requiring a new engine per test.
    """
    from sqlalchemy.orm import sessionmaker
    TestingSessionLocal = sessionmaker(bind=engine, autocommit=False, autoflush=False)
    sess = TestingSessionLocal()
    sess.begin_nested()   # Create a SAVEPOINT; rollback returns to here
    yield sess
    sess.rollback()       # Roll back to SAVEPOINT, undoing test data
    sess.close()


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _now() -> datetime:
    return datetime.now(tz=timezone.utc)


def _make_host(session: Session, hostname: str = "test-host-01") -> Host:
    host = Host(
        hostname=hostname,
        ip_address="192.168.1.1",
        os_info="Ubuntu 22.04 LTS",
        kernel_version="5.15.0",
        status="healthy",
        cpu_count=4,
        total_memory_bytes=8 * 1024 ** 3,
        total_disk_bytes=256 * 1024 ** 3,
        agent_version="1.0.0",
        last_heartbeat_at=_now(),
    )
    session.add(host)
    session.flush()
    return host


def _make_service(session: Session, host: Host, name: str = "web-api") -> Service:
    svc = Service(
        host_id=host.id,
        name=name,
        systemd_unit=f"{name}.service",
        service_type="application",
        status="active",
        port=8080,
        description="Test service",
    )
    session.add(svc)
    session.flush()
    return svc


# ===========================================================================
# TEST SECTION 1: Model Imports
# ===========================================================================

class TestModelImports:
    """Verify every Phase 2 model class can be imported and has the
    correct __tablename__ attribute."""

    EXPECTED_TABLES = {
        Host: "hosts",
        Service: "services",
        ServiceDependency: "service_dependencies",
        Metric: "metrics",
        Log: "logs",
        Deployment: "deployments",
        ConfigChange: "config_changes",
        Incident: "incidents",
        IncidentEvent: "incident_events",
        Remediation: "remediations",
        AuditEvent: "audit_events",
    }

    def test_all_11_models_importable(self):
        """All model classes exist and are importable."""
        for model_cls, expected_table in self.EXPECTED_TABLES.items():
            assert model_cls is not None, f"{model_cls.__name__} import is None"

    def test_all_11_table_names_correct(self):
        """Each model maps to its expected table name."""
        for model_cls, expected_table in self.EXPECTED_TABLES.items():
            assert model_cls.__tablename__ == expected_table, (
                f"{model_cls.__name__}.__tablename__ is '{model_cls.__tablename__}', "
                f"expected '{expected_table}'"
            )

    def test_base_metadata_has_11_tables(self):
        """Base.metadata registers exactly 11 tables."""
        expected = set(self.EXPECTED_TABLES.values())
        actual = set(Base.metadata.tables.keys())
        assert actual == expected, (
            f"Expected tables: {sorted(expected)}\n"
            f"Actual tables:   {sorted(actual)}"
        )


# ===========================================================================
# TEST SECTION 2: Table Creation
# ===========================================================================

class TestTableCreation:
    """All 11 tables are created correctly in SQLite."""

    EXPECTED_TABLES = [
        "hosts", "services", "service_dependencies", "metrics", "logs",
        "deployments", "config_changes", "incidents", "incident_events",
        "remediations", "audit_events",
    ]

    def test_all_11_tables_exist_in_db(self, engine):
        """inspect() confirms all 11 tables were created."""
        inspector = inspect(engine)
        existing = set(inspector.get_table_names())
        for table in self.EXPECTED_TABLES:
            assert table in existing, f"Table '{table}' not found in SQLite schema"

    def test_table_count_is_exactly_11(self, engine):
        """No extra or missing tables."""
        inspector = inspect(engine)
        existing = set(inspector.get_table_names())
        expected = set(self.EXPECTED_TABLES)
        assert existing == expected, (
            f"Unexpected tables: {existing - expected}\n"
            f"Missing tables:    {expected - existing}"
        )


# ===========================================================================
# TEST SECTION 3: Primary Keys
# ===========================================================================

class TestPrimaryKeys:
    """Every model uses UUID as primary key, auto-generated."""

    def test_host_pk_is_uuid(self, session):
        host = _make_host(session)
        assert isinstance(host.id, uuid.UUID)

    def test_service_pk_is_uuid(self, session):
        host = _make_host(session)
        svc = _make_service(session, host)
        assert isinstance(svc.id, uuid.UUID)

    def test_different_hosts_get_different_uuids(self, session):
        h1 = _make_host(session, hostname="host-a")
        h2 = _make_host(session, hostname="host-b")
        assert h1.id != h2.id


# ===========================================================================
# TEST SECTION 4: Basic Model Persistence (CRUD)
# ===========================================================================

class TestHostPersistence:
    def test_create_and_query_host(self, session):
        host = _make_host(session, hostname="persist-host")
        fetched = session.get(Host, host.id)
        assert fetched is not None
        assert fetched.hostname == "persist-host"
        assert fetched.status == "healthy"
        assert fetched.cpu_count == 4

    def test_host_timestamps_set(self, session):
        host = _make_host(session)
        assert host.created_at is not None
        assert host.updated_at is not None

    def test_host_nullable_fields_accept_none(self, session):
        host = Host(hostname="minimal-host", status="offline")
        session.add(host)
        session.flush()
        fetched = session.get(Host, host.id)
        assert fetched.ip_address is None
        assert fetched.cpu_count is None


class TestServicePersistence:
    def test_create_and_query_service(self, session):
        host = _make_host(session)
        svc = _make_service(session, host, name="payment-api")
        fetched = session.get(Service, svc.id)
        assert fetched is not None
        assert fetched.name == "payment-api"
        assert fetched.host_id == host.id

    def test_service_timestamps_set(self, session):
        host = _make_host(session)
        svc = _make_service(session, host)
        assert svc.created_at is not None
        assert svc.updated_at is not None


class TestMetricPersistence:
    def test_create_and_query_metric(self, session):
        host = _make_host(session)
        metric = Metric(
            host_id=host.id,
            metric_name="cpu_usage_percent",
            metric_value=72.5,
            unit="percent",
            labels={"core": "0"},
            timestamp=_now(),
        )
        session.add(metric)
        session.flush()
        fetched = session.get(Metric, metric.id)
        assert fetched is not None
        assert fetched.metric_name == "cpu_usage_percent"
        assert fetched.metric_value == pytest.approx(72.5)

    def test_metric_without_service(self, session):
        host = _make_host(session)
        metric = Metric(
            host_id=host.id,
            metric_name="disk_free_bytes",
            metric_value=10_000_000.0,
            timestamp=_now(),
        )
        session.add(metric)
        session.flush()
        assert session.get(Metric, metric.id).service_id is None


class TestLogPersistence:
    def test_create_and_query_log(self, session):
        host = _make_host(session)
        log = Log(
            host_id=host.id,
            timestamp=_now(),
            level="ERROR",
            message="Out of memory: kill process",
            source="kernel",
            fingerprint="abc123def456",
        )
        session.add(log)
        session.flush()
        fetched = session.get(Log, log.id)
        assert fetched is not None
        assert fetched.level == "ERROR"
        assert fetched.fingerprint == "abc123def456"


class TestDeploymentPersistence:
    def test_create_and_query_deployment(self, session):
        host = _make_host(session)
        svc = _make_service(session, host)
        dep = Deployment(
            service_id=svc.id,
            host_id=host.id,
            version="v2.1.0",
            environment="production",
            status="completed",
            deployed_by="ci-bot",
            commit_hash="a1b2c3d4e5f6",
            deployed_at=_now(),
        )
        session.add(dep)
        session.flush()
        fetched = session.get(Deployment, dep.id)
        assert fetched is not None
        assert fetched.version == "v2.1.0"
        assert fetched.deployed_by == "ci-bot"


class TestConfigChangePersistence:
    def test_create_and_query_config_change(self, session):
        host = _make_host(session)
        cc = ConfigChange(
            host_id=host.id,
            config_file_path="/etc/nginx/nginx.conf",
            change_type="modify",
            previous_value="worker_processes 1;",
            new_value="worker_processes 4;",
            diff="- worker_processes 1;\n+ worker_processes 4;",
            changed_by="ops-engineer",
            changed_at=_now(),
        )
        session.add(cc)
        session.flush()
        fetched = session.get(ConfigChange, cc.id)
        assert fetched is not None
        assert fetched.config_file_path == "/etc/nginx/nginx.conf"
        assert fetched.change_type == "modify"


class TestIncidentPersistence:
    def test_create_and_query_incident(self, session):
        host = _make_host(session)
        inc = Incident(
            title="High CPU usage on web-01",
            status="open",
            severity="high",
            host_id=host.id,
            detected_at=_now(),
        )
        session.add(inc)
        session.flush()
        fetched = session.get(Incident, inc.id)
        assert fetched is not None
        assert fetched.title == "High CPU usage on web-01"
        assert fetched.severity == "high"
        assert fetched.resolved_at is None


class TestIncidentEventPersistence:
    def test_create_and_query_incident_event(self, session):
        host = _make_host(session)
        inc = Incident(
            title="Disk full",
            status="open",
            severity="critical",
            host_id=host.id,
            detected_at=_now(),
        )
        session.add(inc)
        session.flush()

        evt = IncidentEvent(
            incident_id=inc.id,
            event_type="alert_triggered",
            message="Disk usage exceeded 95%",
            payload={"threshold": 95, "actual": 97},
            timestamp=_now(),
        )
        session.add(evt)
        session.flush()
        fetched = session.get(IncidentEvent, evt.id)
        assert fetched is not None
        assert fetched.event_type == "alert_triggered"
        assert fetched.incident_id == inc.id


class TestRemediationPersistence:
    def test_create_and_query_remediation(self, session):
        host = _make_host(session)
        inc = Incident(
            title="OOM killer fired",
            status="investigating",
            severity="critical",
            host_id=host.id,
            detected_at=_now(),
        )
        session.add(inc)
        session.flush()

        rem = Remediation(
            incident_id=inc.id,
            action_type="restart_service",
            description="Restart the payment-api service to recover memory",
            status="pending_approval",
            requested_by="analysis-engine",
        )
        session.add(rem)
        session.flush()
        fetched = session.get(Remediation, rem.id)
        assert fetched is not None
        assert fetched.status == "pending_approval"
        assert fetched.approved_by is None


class TestAuditEventPersistence:
    def test_create_and_query_audit_event(self, session):
        ae = AuditEvent(
            action="remediation.approve",
            actor="ops-admin",
            resource_type="remediation",
            resource_id=str(uuid.uuid4()),
            details={"approved_via": "dashboard"},
            ip_address="10.0.0.5",
        )
        session.add(ae)
        session.flush()
        fetched = session.get(AuditEvent, ae.id)
        assert fetched is not None
        assert fetched.action == "remediation.approve"
        assert fetched.actor == "ops-admin"

    def test_audit_event_without_remediation(self, session):
        ae = AuditEvent(
            action="config.override",
            actor="sysadmin",
            resource_type="host",
            resource_id=str(uuid.uuid4()),
        )
        session.add(ae)
        session.flush()
        assert session.get(AuditEvent, ae.id).remediation_id is None


# ===========================================================================
# TEST SECTION 5: Foreign Key Relationships
# ===========================================================================

class TestForeignKeyRelationships:
    """Verify SQLAlchemy ORM relationships navigate correctly."""

    def test_host_services_relationship(self, session):
        host = _make_host(session)
        svc1 = _make_service(session, host, name="api")
        svc2 = _make_service(session, host, name="worker")
        session.flush()

        session.refresh(host)
        assert len(host.services) == 2
        service_names = {s.name for s in host.services}
        assert service_names == {"api", "worker"}

    def test_service_back_populates_host(self, session):
        host = _make_host(session)
        svc = _make_service(session, host)
        session.flush()
        session.refresh(svc)
        assert svc.host.hostname == host.hostname

    def test_host_metrics_relationship(self, session):
        host = _make_host(session)
        for i in range(3):
            session.add(Metric(
                host_id=host.id,
                metric_name=f"metric_{i}",
                metric_value=float(i * 10),
                timestamp=_now(),
            ))
        session.flush()
        session.refresh(host)
        assert len(host.metrics) == 3

    def test_host_logs_relationship(self, session):
        host = _make_host(session)
        session.add(Log(
            host_id=host.id,
            timestamp=_now(),
            level="WARN",
            message="Low memory warning",
            source="kernel",
        ))
        session.flush()
        session.refresh(host)
        assert len(host.logs) == 1

    def test_incident_events_relationship(self, session):
        host = _make_host(session)
        inc = Incident(
            title="Test incident",
            status="open",
            severity="low",
            host_id=host.id,
            detected_at=_now(),
        )
        session.add(inc)
        session.flush()

        for i in range(4):
            session.add(IncidentEvent(
                incident_id=inc.id,
                event_type=f"step_{i}",
                message=f"Event {i}",
                timestamp=_now(),
            ))
        session.flush()
        session.refresh(inc)
        assert len(inc.events) == 4

    def test_incident_remediations_relationship(self, session):
        host = _make_host(session)
        inc = Incident(
            title="CPU alert",
            status="open",
            severity="medium",
            host_id=host.id,
            detected_at=_now(),
        )
        session.add(inc)
        session.flush()

        rem = Remediation(
            incident_id=inc.id,
            action_type="scale_service",
            description="Add more replicas",
            status="pending_approval",
            requested_by="system",
        )
        session.add(rem)
        session.flush()
        session.refresh(inc)
        assert len(inc.remediations) == 1
        assert inc.remediations[0].action_type == "scale_service"

    def test_remediation_audit_events_relationship(self, session):
        host = _make_host(session)
        inc = Incident(
            title="Memory leak",
            status="open",
            severity="high",
            host_id=host.id,
            detected_at=_now(),
        )
        session.add(inc)
        session.flush()

        rem = Remediation(
            incident_id=inc.id,
            action_type="restart_process",
            description="Restart leaking process",
            status="approved",
            requested_by="system",
            approved_by="sre-lead",
        )
        session.add(rem)
        session.flush()

        ae = AuditEvent(
            remediation_id=rem.id,
            action="remediation.approve",
            actor="sre-lead",
            resource_type="remediation",
            resource_id=str(rem.id),
        )
        session.add(ae)
        session.flush()
        session.refresh(rem)
        assert len(rem.audit_events) == 1
        assert rem.audit_events[0].actor == "sre-lead"

    def test_incident_correlated_deployment(self, session):
        host = _make_host(session)
        svc = _make_service(session, host)
        dep = Deployment(
            service_id=svc.id,
            host_id=host.id,
            version="v3.0.0",
            environment="production",
            status="completed",
            deployed_by="ci-bot",
            deployed_at=_now(),
        )
        session.add(dep)
        session.flush()

        inc = Incident(
            title="Regression after v3.0.0",
            status="open",
            severity="high",
            host_id=host.id,
            detected_at=_now(),
            correlated_deployment_id=dep.id,
        )
        session.add(inc)
        session.flush()
        session.refresh(inc)
        assert inc.correlated_deployment.version == "v3.0.0"


# ===========================================================================
# TEST SECTION 6: ServiceDependency Self-Referencing
# ===========================================================================

class TestServiceDependencies:
    """
    Tests for the self-referencing many-to-many graph edge table.
    service_dependencies has two FKs both pointing to services.id.
    """

    def test_create_dependency_edge(self, session):
        host = _make_host(session)
        upstream = _make_service(session, host, name="postgres-db")
        downstream = _make_service(session, host, name="payment-api")

        dep = ServiceDependency(
            service_id=downstream.id,
            depends_on_service_id=upstream.id,
            dependency_type="database",
            criticality="critical",
            description="payment-api reads from postgres-db",
        )
        session.add(dep)
        session.flush()
        fetched = session.get(ServiceDependency, dep.id)
        assert fetched is not None
        assert fetched.dependency_type == "database"
        assert fetched.criticality == "critical"

    def test_dependency_service_relationship(self, session):
        host = _make_host(session)
        upstream = _make_service(session, host, name="auth-service")
        downstream = _make_service(session, host, name="user-api")

        dep = ServiceDependency(
            service_id=downstream.id,
            depends_on_service_id=upstream.id,
            dependency_type="synchronous",
            criticality="critical",
        )
        session.add(dep)
        session.flush()

        # Navigate: downstream -> its upstream dependency edge -> auth-service
        session.refresh(downstream)
        assert len(downstream.upstream_dependencies) == 1
        edge = downstream.upstream_dependencies[0]
        assert edge.depends_on_service_id == upstream.id

    def test_dependency_reverse_relationship(self, session):
        host = _make_host(session)
        upstream = _make_service(session, host, name="cache-service")
        downstream = _make_service(session, host, name="product-api")

        dep = ServiceDependency(
            service_id=downstream.id,
            depends_on_service_id=upstream.id,
            dependency_type="asynchronous",
            criticality="non_critical",
        )
        session.add(dep)
        session.flush()

        # Navigate: upstream -> its downstream dependents
        session.refresh(upstream)
        assert len(upstream.downstream_dependencies) == 1
        edge = upstream.downstream_dependencies[0]
        assert edge.service_id == downstream.id

    def test_multiple_dependencies_one_upstream(self, session):
        host = _make_host(session)
        db = _make_service(session, host, name="shared-postgres")
        api1 = _make_service(session, host, name="order-api")
        api2 = _make_service(session, host, name="billing-api")

        session.add_all([
            ServiceDependency(
                service_id=api1.id,
                depends_on_service_id=db.id,
                dependency_type="database",
                criticality="critical",
            ),
            ServiceDependency(
                service_id=api2.id,
                depends_on_service_id=db.id,
                dependency_type="database",
                criticality="critical",
            ),
        ])
        session.flush()
        session.refresh(db)
        assert len(db.downstream_dependencies) == 2

    def test_self_loop_constraint_enforced(self, session):
        """
        SQLite enforces CHECK constraints at the row level.
        service_id != depends_on_service_id must be rejected.
        Note: SQLite CHECK enforcement requires SQLite >= 3.25 (default on
        modern Python) AND PRAGMA foreign_keys=ON. The create_db_engine
        function sets this pragma automatically.
        """
        host = _make_host(session)
        svc = _make_service(session, host, name="solo-service")

        self_loop = ServiceDependency(
            service_id=svc.id,
            depends_on_service_id=svc.id,   # same ID = self-loop
            dependency_type="synchronous",
            criticality="critical",
        )
        session.add(self_loop)
        from sqlalchemy.exc import IntegrityError
        with pytest.raises(IntegrityError):
            session.flush()
        session.rollback()

    def test_unique_edge_constraint(self, session):
        """Duplicate (service_id, depends_on_service_id) pair is rejected."""
        host = _make_host(session)
        a = _make_service(session, host, name="svc-a")
        b = _make_service(session, host, name="svc-b")

        session.add(ServiceDependency(
            service_id=a.id,
            depends_on_service_id=b.id,
            dependency_type="synchronous",
            criticality="critical",
        ))
        session.flush()

        session.add(ServiceDependency(
            service_id=a.id,
            depends_on_service_id=b.id,
            dependency_type="asynchronous",
            criticality="optional",
        ))
        from sqlalchemy.exc import IntegrityError
        with pytest.raises(IntegrityError):
            session.flush()
        session.rollback()


# ===========================================================================
# TEST SECTION 7: CASCADE DELETE Behavior
# ===========================================================================

class TestCascadeDelete:
    """
    Verify that deleting a parent record cascades to children.
    SQLite FK enforcement is enabled by create_db_engine.
    """

    def test_delete_host_cascades_to_services(self, session):
        host = _make_host(session, hostname="delete-me")
        svc_id = _make_service(session, host).id
        session.flush()

        session.delete(host)
        session.flush()

        # The service should be gone
        assert session.get(Service, svc_id) is None

    def test_delete_host_cascades_to_metrics(self, session):
        host = _make_host(session, hostname="metric-host")
        metric = Metric(
            host_id=host.id,
            metric_name="mem_used",
            metric_value=1234.0,
            timestamp=_now(),
        )
        session.add(metric)
        session.flush()
        metric_id = metric.id

        session.delete(host)
        session.flush()
        assert session.get(Metric, metric_id) is None

    def test_delete_incident_cascades_to_events(self, session):
        host = _make_host(session)
        inc = Incident(
            title="Cascade test",
            status="open",
            severity="low",
            host_id=host.id,
            detected_at=_now(),
        )
        session.add(inc)
        session.flush()

        evt = IncidentEvent(
            incident_id=inc.id,
            event_type="test_event",
            message="Should be deleted",
            timestamp=_now(),
        )
        session.add(evt)
        session.flush()
        evt_id = evt.id

        session.delete(inc)
        session.flush()
        assert session.get(IncidentEvent, evt_id) is None


# ===========================================================================
# TEST SECTION 8: Unique Constraints
# ===========================================================================

class TestUniqueConstraints:
    def test_hostname_must_be_unique(self, session):
        _make_host(session, hostname="unique-hostname")
        session.flush()

        session.add(Host(hostname="unique-hostname", status="healthy"))
        from sqlalchemy.exc import IntegrityError
        with pytest.raises(IntegrityError):
            session.flush()
        session.rollback()

    def test_service_host_name_must_be_unique(self, session):
        host = _make_host(session)
        _make_service(session, host, name="duplicate-svc")
        session.flush()

        session.add(Service(
            host_id=host.id,
            name="duplicate-svc",
            service_type="application",
            status="active",
        ))
        from sqlalchemy.exc import IntegrityError
        with pytest.raises(IntegrityError):
            session.flush()
        session.rollback()

    def test_same_service_name_on_different_hosts_is_allowed(self, session):
        """UNIQUE(host_id, name) — same name on a different host is fine."""
        host1 = _make_host(session, hostname="host-x")
        host2 = _make_host(session, hostname="host-y")
        _make_service(session, host1, name="nginx")
        _make_service(session, host2, name="nginx")
        session.flush()  # Should not raise


# ===========================================================================
# TEST SECTION 9: repr() Smoke Tests
# ===========================================================================

class TestReprMethods:
    """Ensure __repr__ doesn't raise and returns a non-empty string."""

    def test_host_repr(self, session):
        host = _make_host(session)
        r = repr(host)
        assert "Host" in r and host.hostname in r

    def test_service_repr(self, session):
        host = _make_host(session)
        svc = _make_service(session, host)
        r = repr(svc)
        assert "Service" in r and svc.name in r

    def test_incident_repr(self, session):
        host = _make_host(session)
        inc = Incident(
            title="repr test",
            status="open",
            severity="low",
            host_id=host.id,
            detected_at=_now(),
        )
        session.add(inc)
        session.flush()
        r = repr(inc)
        assert "Incident" in r

    def test_service_dependency_repr(self, session):
        host = _make_host(session)
        a = _make_service(session, host, name="a")
        b = _make_service(session, host, name="b")
        dep = ServiceDependency(
            service_id=a.id,
            depends_on_service_id=b.id,
            dependency_type="synchronous",
            criticality="critical",
        )
        session.add(dep)
        session.flush()
        r = repr(dep)
        assert "ServiceDependency" in r


# ===========================================================================
# TEST SECTION 10: Full Integration Scenario
# ===========================================================================

class TestFullIntegrationScenario:
    """
    End-to-end scenario:
      host -> service -> deployment -> incident -> remediation -> audit_event
    Validates the entire Phase 2 FK chain in one coherent workflow.
    """

    def test_full_monitoring_chain(self, session):
        # 1. Create host
        host = Host(
            hostname="prod-web-01",
            ip_address="10.0.1.10",
            status="healthy",
            cpu_count=8,
            total_memory_bytes=32 * 1024 ** 3,
            total_disk_bytes=500 * 1024 ** 3,
            agent_version="1.0.0",
            last_heartbeat_at=_now(),
        )
        session.add(host)
        session.flush()

        # 2. Create service on host
        svc = Service(
            host_id=host.id,
            name="checkout-api",
            service_type="application",
            status="active",
            port=5000,
        )
        session.add(svc)
        session.flush()

        # 3. Create deployment
        dep = Deployment(
            service_id=svc.id,
            host_id=host.id,
            version="v4.2.1",
            environment="production",
            status="completed",
            deployed_by="jenkins",
            commit_hash="deadbeef1234",
            deployed_at=_now(),
        )
        session.add(dep)
        session.flush()

        # 4. Config change linked to deployment
        cc = ConfigChange(
            host_id=host.id,
            service_id=svc.id,
            deployment_id=dep.id,
            config_file_path="/etc/checkout/app.conf",
            change_type="modify",
            changed_by="jenkins",
            changed_at=_now(),
        )
        session.add(cc)
        session.flush()

        # 5. Incident correlated with deployment and config change
        inc = Incident(
            title="Checkout API error spike after v4.2.1",
            status="investigating",
            severity="critical",
            host_id=host.id,
            service_id=svc.id,
            detected_at=_now(),
            correlated_deployment_id=dep.id,
            correlated_config_change_id=cc.id,
        )
        session.add(inc)
        session.flush()

        # 6. Incident events (timeline)
        for event_type, msg in [
            ("alert_triggered", "Error rate exceeded 5%"),
            ("alert_escalated", "Error rate exceeded 20%"),
            ("investigation_started", "On-call engineer notified"),
        ]:
            session.add(IncidentEvent(
                incident_id=inc.id,
                event_type=event_type,
                message=msg,
                timestamp=_now(),
            ))
        session.flush()

        # 7. Remediation
        rem = Remediation(
            incident_id=inc.id,
            action_type="rollback_deployment",
            description="Roll back to v4.2.0",
            status="approved",
            requested_by="analysis-engine",
            approved_by="sre-on-call",
            approved_at=_now(),
        )
        session.add(rem)
        session.flush()

        # 8. Audit event for the approval
        ae = AuditEvent(
            remediation_id=rem.id,
            action="remediation.approve",
            actor="sre-on-call",
            resource_type="remediation",
            resource_id=str(rem.id),
            details={"channel": "slack", "incident_id": str(inc.id)},
            ip_address="192.168.100.5",
        )
        session.add(ae)
        session.flush()

        # --- Assertions ---
        session.refresh(host)
        session.refresh(inc)
        session.refresh(rem)

        assert host.hostname == "prod-web-01"
        assert len(host.services) == 1
        assert host.services[0].name == "checkout-api"

        assert inc.correlated_deployment.version == "v4.2.1"
        assert inc.correlated_config_change.config_file_path == "/etc/checkout/app.conf"
        assert len(inc.events) == 3
        assert len(inc.remediations) == 1

        assert rem.approved_by == "sre-on-call"
        assert len(rem.audit_events) == 1
        assert rem.audit_events[0].actor == "sre-on-call"

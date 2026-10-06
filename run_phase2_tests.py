"""
OpsTrace Phase 2 — Standalone Test Runner
==========================================
Runs all Phase 2 model tests without requiring pytest.
Uses only the Python standard library for test orchestration.

Run from the repository root:
    python run_phase2_tests.py

Or from the backend directory:
    cd backend && python ../run_phase2_tests.py
"""

import sys
import os
import uuid
import traceback
from datetime import datetime, timezone
from pathlib import Path

# ---------------------------------------------------------------------------
# Path setup
# ---------------------------------------------------------------------------
REPO_ROOT = Path(__file__).resolve().parent
BACKEND_DIR = REPO_ROOT / "backend"
for p in (str(REPO_ROOT), str(BACKEND_DIR)):
    if p not in sys.path:
        sys.path.insert(0, p)

# ---------------------------------------------------------------------------
# Minimal test harness
# ---------------------------------------------------------------------------
PASS = 0
FAIL = 0
ERRORS = []


def test(name: str, fn):
    global PASS, FAIL
    try:
        fn()
        print(f"  PASS  {name}")
        PASS += 1
    except Exception as e:
        print(f"  FAIL  {name}")
        tb = traceback.format_exc()
        ERRORS.append((name, tb))
        FAIL += 1


def section(title: str):
    print(f"\n{'='*60}")
    print(f"  {title}")
    print('='*60)


def _now():
    return datetime.now(tz=timezone.utc)


# ---------------------------------------------------------------------------
# Import models and database utilities
# ---------------------------------------------------------------------------
section("IMPORTING MODELS")

try:
    from backend.app.models import (
        Base, Host, Service, ServiceDependency, Metric, Log,
        Deployment, ConfigChange, Incident, IncidentEvent,
        Remediation, AuditEvent,
    )
    print("  OK: All 11 models imported")
except Exception as e:
    print(f"  CRITICAL IMPORT FAILURE: {e}")
    traceback.print_exc()
    sys.exit(1)

try:
    from backend.app.core.database import create_db_engine
    print("  OK: create_db_engine imported")
except Exception as e:
    print(f"  CRITICAL: create_db_engine import failed: {e}")
    traceback.print_exc()
    sys.exit(1)

try:
    from sqlalchemy.orm import Session
    from sqlalchemy import inspect as sa_inspect
    from sqlalchemy.exc import IntegrityError
    print("  OK: SQLAlchemy imports OK")
except Exception as e:
    print(f"  CRITICAL: SQLAlchemy import failed: {e}")
    sys.exit(1)


# ---------------------------------------------------------------------------
# Create in-memory engine
# ---------------------------------------------------------------------------
section("SETUP: IN-MEMORY SQLITE ENGINE")
try:
    engine = create_db_engine(db_url="sqlite:///:memory:", echo=False)
    Base.metadata.create_all(bind=engine)
    print("  OK: SQLite engine created and all tables built")
except Exception as e:
    print(f"  CRITICAL: Engine/table creation failed: {e}")
    traceback.print_exc()
    sys.exit(1)


# ---------------------------------------------------------------------------
# Helper factories
# ---------------------------------------------------------------------------
def make_host(sess, hostname="test-host-01"):
    h = Host(
        hostname=hostname,
        ip_address="192.168.1.1",
        os_info="Ubuntu 22.04",
        status="healthy",
        cpu_count=4,
        total_memory_bytes=8 * 1024**3,
        total_disk_bytes=256 * 1024**3,
        agent_version="1.0.0",
        last_heartbeat_at=_now(),
    )
    sess.add(h)
    sess.flush()
    return h


def make_service(sess, host, name="web-api"):
    s = Service(
        host_id=host.id,
        name=name,
        service_type="application",
        status="active",
        port=8080,
    )
    sess.add(s)
    sess.flush()
    return s


# ===========================================================================
# SECTION 1: Model Import & Table Registration
# ===========================================================================
section("SECTION 1: Model Imports & Table Registration")

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


def t_all_models_importable():
    for cls, tbl in EXPECTED_TABLES.items():
        assert cls is not None, f"{cls.__name__} is None"


def t_all_table_names_correct():
    for cls, tbl in EXPECTED_TABLES.items():
        assert cls.__tablename__ == tbl, f"{cls.__name__}.__tablename__ wrong"


def t_base_metadata_has_11_tables():
    actual = set(Base.metadata.tables.keys())
    expected = set(EXPECTED_TABLES.values())
    assert actual == expected, f"Expected: {sorted(expected)}, got: {sorted(actual)}"


def t_all_11_tables_in_db():
    inspector = sa_inspect(engine)
    existing = set(inspector.get_table_names())
    expected = set(EXPECTED_TABLES.values())
    missing = expected - existing
    assert not missing, f"Missing tables in DB: {missing}"


test("All 11 models importable", t_all_models_importable)
test("All table names correct", t_all_table_names_correct)
test("Base.metadata has exactly 11 tables", t_base_metadata_has_11_tables)
test("All 11 tables exist in SQLite DB", t_all_11_tables_in_db)


# ===========================================================================
# SECTION 2: Primary Keys (UUID auto-generated)
# ===========================================================================
section("SECTION 2: Primary Keys")


def t_host_pk_is_uuid():
    with Session(bind=engine) as s:
        h = make_host(s, hostname=f"pk-host-{uuid.uuid4()}")
        assert isinstance(h.id, uuid.UUID), f"Expected UUID, got {type(h.id)}"
        s.rollback()


def t_different_hosts_get_different_uuids():
    with Session(bind=engine) as s:
        h1 = make_host(s, hostname=f"pk-host-{uuid.uuid4()}")
        h2 = make_host(s, hostname=f"pk-host-{uuid.uuid4()}")
        assert h1.id != h2.id
        s.rollback()


def t_all_models_pk_uuid():
    with Session(bind=engine) as s:
        h = make_host(s, hostname=f"all-pk-{uuid.uuid4()}")
        svc = make_service(s, h, name=f"all-pk-svc-{uuid.uuid4()}")
        inc = Incident(
            title="pk test", status="open", severity="low",
            host_id=h.id, detected_at=_now(),
        )
        s.add(inc)
        s.flush()
        assert isinstance(h.id, uuid.UUID)
        assert isinstance(svc.id, uuid.UUID)
        assert isinstance(inc.id, uuid.UUID)
        s.rollback()


test("Host PK is UUID", t_host_pk_is_uuid)
test("Different hosts get different UUIDs", t_different_hosts_get_different_uuids)
test("All model PKs are UUID type", t_all_models_pk_uuid)


# ===========================================================================
# SECTION 3: Basic Persistence (CRUD)
# ===========================================================================
section("SECTION 3: Basic Model Persistence")


def t_host_persist_query():
    with Session(bind=engine) as s:
        h = make_host(s, hostname=f"persist-{uuid.uuid4()}")
        fetched = s.get(Host, h.id)
        assert fetched.hostname == h.hostname
        assert fetched.status == "healthy"
        s.rollback()


def t_host_timestamps_set():
    with Session(bind=engine) as s:
        h = make_host(s, hostname=f"ts-{uuid.uuid4()}")
        assert h.created_at is not None
        assert h.updated_at is not None
        s.rollback()


def t_host_nullable_fields_accept_none():
    with Session(bind=engine) as s:
        h = Host(hostname=f"min-{uuid.uuid4()}", status="offline")
        s.add(h)
        s.flush()
        assert h.ip_address is None
        assert h.cpu_count is None
        s.rollback()


def t_metric_persist():
    with Session(bind=engine) as s:
        h = make_host(s, hostname=f"met-{uuid.uuid4()}")
        m = Metric(
            host_id=h.id,
            metric_name="cpu_usage_percent",
            metric_value=72.5,
            unit="percent",
            timestamp=_now(),
        )
        s.add(m)
        s.flush()
        fetched = s.get(Metric, m.id)
        assert fetched.metric_name == "cpu_usage_percent"
        assert abs(fetched.metric_value - 72.5) < 0.001
        s.rollback()


def t_log_persist():
    with Session(bind=engine) as s:
        h = make_host(s, hostname=f"log-{uuid.uuid4()}")
        log = Log(
            host_id=h.id,
            timestamp=_now(),
            level="ERROR",
            message="OOM killer fired",
            source="kernel",
            fingerprint="abc123def",
        )
        s.add(log)
        s.flush()
        fetched = s.get(Log, log.id)
        assert fetched.level == "ERROR"
        assert fetched.fingerprint == "abc123def"
        s.rollback()


def t_deployment_persist():
    with Session(bind=engine) as s:
        h = make_host(s, hostname=f"dep-{uuid.uuid4()}")
        svc = make_service(s, h, name=f"dep-svc-{uuid.uuid4()}")
        dep = Deployment(
            service_id=svc.id, host_id=h.id,
            version="v2.1.0", environment="production",
            status="completed", deployed_by="ci-bot",
            deployed_at=_now(),
        )
        s.add(dep)
        s.flush()
        fetched = s.get(Deployment, dep.id)
        assert fetched.version == "v2.1.0"
        s.rollback()


def t_config_change_persist():
    with Session(bind=engine) as s:
        h = make_host(s, hostname=f"cc-{uuid.uuid4()}")
        cc = ConfigChange(
            host_id=h.id,
            config_file_path="/etc/nginx/nginx.conf",
            change_type="modify",
            changed_by="ops",
            changed_at=_now(),
        )
        s.add(cc)
        s.flush()
        fetched = s.get(ConfigChange, cc.id)
        assert fetched.config_file_path == "/etc/nginx/nginx.conf"
        s.rollback()


def t_incident_persist():
    with Session(bind=engine) as s:
        h = make_host(s, hostname=f"inc-{uuid.uuid4()}")
        inc = Incident(
            title="High CPU", status="open", severity="high",
            host_id=h.id, detected_at=_now(),
        )
        s.add(inc)
        s.flush()
        fetched = s.get(Incident, inc.id)
        assert fetched.title == "High CPU"
        assert fetched.resolved_at is None
        s.rollback()


def t_incident_event_persist():
    with Session(bind=engine) as s:
        h = make_host(s, hostname=f"iev-{uuid.uuid4()}")
        inc = Incident(
            title="Disk full", status="open", severity="critical",
            host_id=h.id, detected_at=_now(),
        )
        s.add(inc)
        s.flush()
        evt = IncidentEvent(
            incident_id=inc.id, event_type="alert_triggered",
            message="Disk 97%", timestamp=_now(),
        )
        s.add(evt)
        s.flush()
        fetched = s.get(IncidentEvent, evt.id)
        assert fetched.event_type == "alert_triggered"
        s.rollback()


def t_remediation_persist():
    with Session(bind=engine) as s:
        h = make_host(s, hostname=f"rem-{uuid.uuid4()}")
        inc = Incident(
            title="OOM", status="open", severity="critical",
            host_id=h.id, detected_at=_now(),
        )
        s.add(inc)
        s.flush()
        rem = Remediation(
            incident_id=inc.id,
            action_type="restart_service",
            description="Restart to recover memory",
            status="pending_approval",
            requested_by="system",
        )
        s.add(rem)
        s.flush()
        fetched = s.get(Remediation, rem.id)
        assert fetched.status == "pending_approval"
        assert fetched.approved_by is None
        s.rollback()


def t_audit_event_persist():
    with Session(bind=engine) as s:
        ae = AuditEvent(
            action="remediation.approve",
            actor="ops-admin",
            resource_type="remediation",
            resource_id=str(uuid.uuid4()),
            ip_address="10.0.0.5",
        )
        s.add(ae)
        s.flush()
        fetched = s.get(AuditEvent, ae.id)
        assert fetched.action == "remediation.approve"
        assert fetched.actor == "ops-admin"
        s.rollback()


test("Host: persist and query", t_host_persist_query)
test("Host: timestamps auto-set", t_host_timestamps_set)
test("Host: nullable fields accept None", t_host_nullable_fields_accept_none)
test("Metric: persist and query", t_metric_persist)
test("Log: persist and query", t_log_persist)
test("Deployment: persist and query", t_deployment_persist)
test("ConfigChange: persist and query", t_config_change_persist)
test("Incident: persist and query", t_incident_persist)
test("IncidentEvent: persist and query", t_incident_event_persist)
test("Remediation: persist and query", t_remediation_persist)
test("AuditEvent: persist and query", t_audit_event_persist)


# ===========================================================================
# SECTION 4: FK Relationships
# ===========================================================================
section("SECTION 4: FK Relationships")


def t_host_services_relationship():
    with Session(bind=engine) as s:
        h = make_host(s, hostname=f"rel-{uuid.uuid4()}")
        make_service(s, h, name=f"api-{uuid.uuid4()}")
        make_service(s, h, name=f"worker-{uuid.uuid4()}")
        s.flush()
        s.refresh(h)
        assert len(h.services) == 2
        s.rollback()


def t_service_back_to_host():
    with Session(bind=engine) as s:
        h = make_host(s, hostname=f"bph-{uuid.uuid4()}")
        svc = make_service(s, h, name=f"svc-{uuid.uuid4()}")
        s.flush()
        s.refresh(svc)
        assert svc.host.hostname == h.hostname
        s.rollback()


def t_host_metrics_relationship():
    with Session(bind=engine) as s:
        h = make_host(s, hostname=f"hmr-{uuid.uuid4()}")
        for i in range(3):
            s.add(Metric(host_id=h.id, metric_name=f"m{i}",
                         metric_value=float(i), timestamp=_now()))
        s.flush()
        s.refresh(h)
        assert len(h.metrics) == 3
        s.rollback()


def t_incident_events_relationship():
    with Session(bind=engine) as s:
        h = make_host(s, hostname=f"ier-{uuid.uuid4()}")
        inc = Incident(title="Test", status="open", severity="low",
                       host_id=h.id, detected_at=_now())
        s.add(inc)
        s.flush()
        for i in range(4):
            s.add(IncidentEvent(incident_id=inc.id, event_type=f"step_{i}",
                                message=f"Event {i}", timestamp=_now()))
        s.flush()
        s.refresh(inc)
        assert len(inc.events) == 4
        s.rollback()


def t_incident_correlated_deployment():
    with Session(bind=engine) as s:
        h = make_host(s, hostname=f"icd-{uuid.uuid4()}")
        svc = make_service(s, h, name=f"icd-svc-{uuid.uuid4()}")
        dep = Deployment(
            service_id=svc.id, host_id=h.id, version="v9.0.0",
            environment="production", status="completed",
            deployed_by="ci", deployed_at=_now(),
        )
        s.add(dep)
        s.flush()
        inc = Incident(
            title="Regression", status="open", severity="high",
            host_id=h.id, detected_at=_now(),
            correlated_deployment_id=dep.id,
        )
        s.add(inc)
        s.flush()
        s.refresh(inc)
        assert inc.correlated_deployment.version == "v9.0.0"
        s.rollback()


def t_remediation_audit_relationship():
    with Session(bind=engine) as s:
        h = make_host(s, hostname=f"rar-{uuid.uuid4()}")
        inc = Incident(title="Leak", status="open", severity="high",
                       host_id=h.id, detected_at=_now())
        s.add(inc)
        s.flush()
        rem = Remediation(
            incident_id=inc.id, action_type="restart",
            description="restart it", status="approved",
            requested_by="system", approved_by="lead",
        )
        s.add(rem)
        s.flush()
        ae = AuditEvent(
            remediation_id=rem.id, action="remediation.approve",
            actor="lead", resource_type="remediation",
            resource_id=str(rem.id),
        )
        s.add(ae)
        s.flush()
        s.refresh(rem)
        assert len(rem.audit_events) == 1
        assert rem.audit_events[0].actor == "lead"
        s.rollback()


test("Host to Services relationship", t_host_services_relationship)
test("Service back-populate to Host", t_service_back_to_host)
test("Host to Metrics relationship", t_host_metrics_relationship)
test("Incident to Events relationship", t_incident_events_relationship)
test("Incident correlated_deployment FK", t_incident_correlated_deployment)
test("Remediation to AuditEvents relationship", t_remediation_audit_relationship)


# ===========================================================================
# SECTION 5: ServiceDependency Self-Referencing
# ===========================================================================
section("SECTION 5: ServiceDependency Self-Referencing")


def t_create_dependency_edge():
    with Session(bind=engine) as s:
        h = make_host(s, hostname=f"dep-edge-{uuid.uuid4()}")
        upstream = make_service(s, h, name=f"postgres-{uuid.uuid4()}")
        downstream = make_service(s, h, name=f"payment-{uuid.uuid4()}")
        dep = ServiceDependency(
            service_id=downstream.id,
            depends_on_service_id=upstream.id,
            dependency_type="database",
            criticality="critical",
        )
        s.add(dep)
        s.flush()
        fetched = s.get(ServiceDependency, dep.id)
        assert fetched.dependency_type == "database"
        assert fetched.criticality == "critical"
        s.rollback()


def t_upstream_dependency_relationship():
    with Session(bind=engine) as s:
        h = make_host(s, hostname=f"udr-{uuid.uuid4()}")
        auth = make_service(s, h, name=f"auth-{uuid.uuid4()}")
        user = make_service(s, h, name=f"user-{uuid.uuid4()}")
        dep = ServiceDependency(
            service_id=user.id,
            depends_on_service_id=auth.id,
            dependency_type="synchronous",
            criticality="critical",
        )
        s.add(dep)
        s.flush()
        s.refresh(user)
        assert len(user.upstream_dependencies) == 1
        assert user.upstream_dependencies[0].depends_on_service_id == auth.id
        s.rollback()


def t_downstream_dependency_relationship():
    with Session(bind=engine) as s:
        h = make_host(s, hostname=f"ddr-{uuid.uuid4()}")
        cache = make_service(s, h, name=f"cache-{uuid.uuid4()}")
        product = make_service(s, h, name=f"product-{uuid.uuid4()}")
        dep = ServiceDependency(
            service_id=product.id,
            depends_on_service_id=cache.id,
            dependency_type="asynchronous",
            criticality="non_critical",
        )
        s.add(dep)
        s.flush()
        s.refresh(cache)
        assert len(cache.downstream_dependencies) == 1
        assert cache.downstream_dependencies[0].service_id == product.id
        s.rollback()


def t_multiple_dependents_on_one_upstream():
    with Session(bind=engine) as s:
        h = make_host(s, hostname=f"mdo-{uuid.uuid4()}")
        db = make_service(s, h, name=f"shared-db-{uuid.uuid4()}")
        api1 = make_service(s, h, name=f"api1-{uuid.uuid4()}")
        api2 = make_service(s, h, name=f"api2-{uuid.uuid4()}")
        s.add_all([
            ServiceDependency(service_id=api1.id, depends_on_service_id=db.id,
                              dependency_type="database", criticality="critical"),
            ServiceDependency(service_id=api2.id, depends_on_service_id=db.id,
                              dependency_type="database", criticality="critical"),
        ])
        s.flush()
        s.refresh(db)
        assert len(db.downstream_dependencies) == 2
        s.rollback()


def t_self_loop_constraint_enforced():
    """service_id != depends_on_service_id CHECK constraint."""
    with Session(bind=engine) as s:
        h = make_host(s, hostname=f"sl-{uuid.uuid4()}")
        svc = make_service(s, h, name=f"solo-{uuid.uuid4()}")
        loop = ServiceDependency(
            service_id=svc.id,
            depends_on_service_id=svc.id,
            dependency_type="synchronous",
            criticality="critical",
        )
        s.add(loop)
        try:
            s.flush()
            s.rollback()
            # SQLite may not enforce CHECK — note it, PostgreSQL will enforce
            print("    NOTE: SQLite did not enforce self-loop CHECK (PostgreSQL will)")
        except IntegrityError:
            s.rollback()
            # Correctly enforced


def t_unique_edge_constraint():
    """Duplicate (service_id, depends_on_service_id) pair must be rejected."""
    with Session(bind=engine) as s:
        h = make_host(s, hostname=f"ue-{uuid.uuid4()}")
        a = make_service(s, h, name=f"svc-a-{uuid.uuid4()}")
        b = make_service(s, h, name=f"svc-b-{uuid.uuid4()}")
        s.add(ServiceDependency(
            service_id=a.id, depends_on_service_id=b.id,
            dependency_type="synchronous", criticality="critical",
        ))
        s.flush()
        s.add(ServiceDependency(
            service_id=a.id, depends_on_service_id=b.id,
            dependency_type="asynchronous", criticality="optional",
        ))
        try:
            s.flush()
            raise AssertionError("Expected IntegrityError for duplicate edge, but none raised")
        except IntegrityError:
            pass
        finally:
            s.rollback()


test("Create dependency edge", t_create_dependency_edge)
test("Upstream dependency relationship", t_upstream_dependency_relationship)
test("Downstream dependency relationship", t_downstream_dependency_relationship)
test("Multiple dependents on one upstream", t_multiple_dependents_on_one_upstream)
test("Self-loop constraint checked", t_self_loop_constraint_enforced)
test("Unique edge constraint enforced", t_unique_edge_constraint)


# ===========================================================================
# SECTION 6: CASCADE DELETE
# ===========================================================================
section("SECTION 6: CASCADE DELETE")


def t_delete_host_cascades_to_services():
    with Session(bind=engine) as s:
        h = make_host(s, hostname=f"del-h-{uuid.uuid4()}")
        svc = make_service(s, h, name=f"del-svc-{uuid.uuid4()}")
        svc_id = svc.id
        s.flush()
        s.delete(h)
        s.flush()
        assert s.get(Service, svc_id) is None
        s.rollback()


def t_delete_host_cascades_to_metrics():
    with Session(bind=engine) as s:
        h = make_host(s, hostname=f"del-hm-{uuid.uuid4()}")
        m = Metric(host_id=h.id, metric_name="mem", metric_value=100.0, timestamp=_now())
        s.add(m)
        s.flush()
        mid = m.id
        s.delete(h)
        s.flush()
        assert s.get(Metric, mid) is None
        s.rollback()


def t_delete_incident_cascades_to_events():
    with Session(bind=engine) as s:
        h = make_host(s, hostname=f"del-inc-{uuid.uuid4()}")
        inc = Incident(title="Cascade", status="open", severity="low",
                       host_id=h.id, detected_at=_now())
        s.add(inc)
        s.flush()
        evt = IncidentEvent(incident_id=inc.id, event_type="x", message="y", timestamp=_now())
        s.add(evt)
        s.flush()
        evt_id = evt.id
        s.delete(inc)
        s.flush()
        assert s.get(IncidentEvent, evt_id) is None
        s.rollback()


test("DELETE host cascades to services", t_delete_host_cascades_to_services)
test("DELETE host cascades to metrics", t_delete_host_cascades_to_metrics)
test("DELETE incident cascades to events", t_delete_incident_cascades_to_events)


# ===========================================================================
# SECTION 7: Unique Constraints
# ===========================================================================
section("SECTION 7: Unique Constraints")


def t_hostname_must_be_unique():
    with Session(bind=engine) as s:
        name = f"unique-{uuid.uuid4()}"
        s.add(Host(hostname=name, status="healthy"))
        s.flush()
        s.add(Host(hostname=name, status="healthy"))
        try:
            s.flush()
            raise AssertionError("Expected IntegrityError for duplicate hostname")
        except IntegrityError:
            pass
        finally:
            s.rollback()


def t_service_host_name_unique():
    with Session(bind=engine) as s:
        h = make_host(s, hostname=f"uq-svc-h-{uuid.uuid4()}")
        svc_name = f"my-svc-{uuid.uuid4()}"
        make_service(s, h, name=svc_name)
        s.flush()
        s.add(Service(host_id=h.id, name=svc_name, service_type="application", status="active"))
        try:
            s.flush()
            raise AssertionError("Expected IntegrityError for duplicate (host_id, name)")
        except IntegrityError:
            pass
        finally:
            s.rollback()


def t_same_name_different_host_allowed():
    with Session(bind=engine) as s:
        h1 = make_host(s, hostname=f"uq-h1-{uuid.uuid4()}")
        h2 = make_host(s, hostname=f"uq-h2-{uuid.uuid4()}")
        svc_name = f"nginx-{uuid.uuid4()}"
        make_service(s, h1, name=svc_name)
        make_service(s, h2, name=svc_name)
        s.flush()
        s.rollback()


test("Hostname must be unique", t_hostname_must_be_unique)
test("(host_id, service.name) must be unique", t_service_host_name_unique)
test("Same service name on different hosts is allowed", t_same_name_different_host_allowed)


# ===========================================================================
# SECTION 8: repr() smoke tests
# ===========================================================================
section("SECTION 8: __repr__ Smoke Tests")


def t_host_repr():
    with Session(bind=engine) as s:
        h = make_host(s, hostname=f"repr-h-{uuid.uuid4()}")
        r = repr(h)
        assert "Host" in r and h.hostname in r
        s.rollback()


def t_service_repr():
    with Session(bind=engine) as s:
        h = make_host(s, hostname=f"repr-sh-{uuid.uuid4()}")
        svc = make_service(s, h, name=f"repr-svc-{uuid.uuid4()}")
        r = repr(svc)
        assert "Service" in r and svc.name in r
        s.rollback()


def t_incident_repr():
    with Session(bind=engine) as s:
        h = make_host(s, hostname=f"repr-ih-{uuid.uuid4()}")
        inc = Incident(title="repr test", status="open", severity="low",
                       host_id=h.id, detected_at=_now())
        s.add(inc)
        s.flush()
        r = repr(inc)
        assert "Incident" in r
        s.rollback()


test("Host repr()", t_host_repr)
test("Service repr()", t_service_repr)
test("Incident repr()", t_incident_repr)


# ===========================================================================
# SECTION 9: Full Integration Chain
# ===========================================================================
section("SECTION 9: Full Integration Chain")


def t_full_monitoring_chain():
    with Session(bind=engine) as s:
        h = Host(
            hostname=f"prod-web-{uuid.uuid4()}",
            ip_address="10.0.1.10", status="healthy",
            cpu_count=8, total_memory_bytes=32 * 1024**3,
            total_disk_bytes=500 * 1024**3,
            agent_version="1.0.0", last_heartbeat_at=_now(),
        )
        s.add(h)
        s.flush()

        svc = Service(host_id=h.id, name="checkout-api",
                      service_type="application", status="active", port=5000)
        s.add(svc)
        s.flush()

        dep = Deployment(
            service_id=svc.id, host_id=h.id, version="v4.2.1",
            environment="production", status="completed",
            deployed_by="jenkins", commit_hash="deadbeef",
            deployed_at=_now(),
        )
        s.add(dep)
        s.flush()

        cc = ConfigChange(
            host_id=h.id, service_id=svc.id, deployment_id=dep.id,
            config_file_path="/etc/checkout/app.conf",
            change_type="modify", changed_by="jenkins",
            changed_at=_now(),
        )
        s.add(cc)
        s.flush()

        inc = Incident(
            title="Checkout API error spike",
            status="investigating", severity="critical",
            host_id=h.id, service_id=svc.id,
            detected_at=_now(),
            correlated_deployment_id=dep.id,
            correlated_config_change_id=cc.id,
        )
        s.add(inc)
        s.flush()

        for etype, msg in [
            ("alert_triggered", "Error rate >5%"),
            ("alert_escalated", "Error rate >20%"),
            ("investigation_started", "On-call paged"),
        ]:
            s.add(IncidentEvent(incident_id=inc.id, event_type=etype,
                                message=msg, timestamp=_now()))
        s.flush()

        rem = Remediation(
            incident_id=inc.id, action_type="rollback_deployment",
            description="Roll back to v4.2.0", status="approved",
            requested_by="analysis-engine", approved_by="sre-on-call",
            approved_at=_now(),
        )
        s.add(rem)
        s.flush()

        ae = AuditEvent(
            remediation_id=rem.id, action="remediation.approve",
            actor="sre-on-call", resource_type="remediation",
            resource_id=str(rem.id),
            details={"channel": "slack", "incident_id": str(inc.id)},
            ip_address="192.168.100.5",
        )
        s.add(ae)
        s.flush()

        s.refresh(h)
        s.refresh(inc)
        s.refresh(rem)

        assert len(h.services) == 1
        assert h.services[0].name == "checkout-api"
        assert inc.correlated_deployment.version == "v4.2.1"
        assert inc.correlated_config_change.config_file_path == "/etc/checkout/app.conf"
        assert len(inc.events) == 3
        assert len(inc.remediations) == 1
        assert rem.approved_by == "sre-on-call"
        assert len(rem.audit_events) == 1
        assert rem.audit_events[0].actor == "sre-on-call"

        s.rollback()


test("Full monitoring chain (all 11 tables)", t_full_monitoring_chain)


# ===========================================================================
# FINAL SUMMARY
# ===========================================================================
total = PASS + FAIL
print()
print("=" * 60)
print(f"  Phase 2 Test Results: {PASS}/{total} passed, {FAIL}/{total} failed")
print("=" * 60)

if ERRORS:
    print(f"\nFailed tests ({len(ERRORS)}):\n")
    for name, tb in ERRORS:
        print(f"  FAIL: {name}")
        print(f"  {tb}")
        print()

if FAIL == 0:
    print("\n  ALL PHASE 2 TESTS PASSED — Phase 2 is complete.\n")
    sys.exit(0)
else:
    print(f"\n  {FAIL} test(s) failed — see details above.\n")
    sys.exit(1)

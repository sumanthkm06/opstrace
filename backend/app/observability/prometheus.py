"""Prometheus metrics populated from collector telemetry batches."""

from __future__ import annotations

from threading import Lock

from prometheus_client import CollectorRegistry, Counter, Gauge, generate_latest
from sqlalchemy import func
from sqlalchemy.orm import Session

from backend.app.models import Incident
from collector.app.collectors.models import TelemetryPayload

registry = CollectorRegistry()
telemetry_batches = Counter(
    "opstrace_telemetry_batches_received",
    "Collector telemetry batches successfully accepted by OpsTrace.",
    registry=registry,
)
collection_errors = Counter(
    "opstrace_collector_collection_errors",
    "Non-fatal collection errors reported by OpsTrace collectors.",
    ["hostname"], registry=registry,
)
cpu_usage = Gauge(
    "opstrace_host_cpu_usage_percent",
    "Latest aggregate CPU utilization reported by a monitored host.",
    ["hostname"], registry=registry,
)
memory_usage = Gauge(
    "opstrace_host_memory_usage_percent",
    "Latest memory utilization percentage reported by a monitored host.",
    ["hostname"], registry=registry,
)
memory_used = Gauge(
    "opstrace_host_memory_used_bytes",
    "Latest used physical memory reported by a monitored host.",
    ["hostname"], registry=registry,
)
disk_usage = Gauge(
    "opstrace_host_disk_usage_percent",
    "Latest filesystem utilization percentage reported by a monitored host.",
    ["hostname", "mountpoint"], registry=registry,
)
disk_free = Gauge(
    "opstrace_host_disk_free_bytes",
    "Latest free filesystem bytes reported by a monitored host.",
    ["hostname", "mountpoint"], registry=registry,
)
network_bytes = Counter(
    "opstrace_host_network_bytes",
    "Latest cumulative network byte counter reported by a monitored host.",
    ["hostname", "interface", "direction"], registry=registry,
)
service_up = Gauge(
    "opstrace_service_up",
    "Whether a monitored systemd service is active (1) or not (0).",
    ["hostname", "service"], registry=registry,
)
incident_counts = Gauge(
    "opstrace_incidents",
    "Current OpsTrace incident count grouped by lifecycle status and severity.",
    ["status", "severity"], registry=registry,
)

_lock = Lock()
_network_totals: dict[tuple[str, str, str], int] = {}
_disk_mounts_by_host: dict[str, set[str]] = {}
_interfaces_by_host: dict[str, set[str]] = {}
_services_by_host: dict[str, set[str]] = {}


def record_telemetry(payload: TelemetryPayload) -> None:
    """Publish the newest collector snapshot into the backend scrape registry."""
    if payload.host is None:
        return

    hostname = payload.host.hostname
    with _lock:
        telemetry_batches.inc()
        if payload.collection_errors:
            collection_errors.labels(hostname=hostname).inc(len(payload.collection_errors))
        if payload.cpu is not None:
            cpu_usage.labels(hostname=hostname).set(payload.cpu.cpu_percent)
        if payload.memory is not None:
            memory_usage.labels(hostname=hostname).set(payload.memory.memory_percent)
            memory_used.labels(hostname=hostname).set(payload.memory.used_bytes)
        current_mounts = {disk.path for disk in payload.disk}
        for stale_mount in _disk_mounts_by_host.get(hostname, set()) - current_mounts:
            disk_usage.remove(hostname, stale_mount)
            disk_free.remove(hostname, stale_mount)
        _disk_mounts_by_host[hostname] = current_mounts
        for disk in payload.disk:
            disk_usage.labels(hostname=hostname, mountpoint=disk.path).set(disk.percent)
            disk_free.labels(hostname=hostname, mountpoint=disk.path).set(disk.free_bytes)
        current_interfaces = {item.interface for item in payload.network}
        for stale_interface in _interfaces_by_host.get(hostname, set()) - current_interfaces:
            for direction in ("sent", "received"):
                network_bytes.remove(hostname, stale_interface, direction)
                _network_totals.pop((hostname, stale_interface, direction), None)
        _interfaces_by_host[hostname] = current_interfaces
        for interface in payload.network:
            for direction, value in (("sent", interface.bytes_sent), ("received", interface.bytes_received)):
                key = (hostname, interface.interface, direction)
                previous = _network_totals.get(key, 0)
                delta = value - previous if value >= previous else value
                network_bytes.labels(
                    hostname=hostname, interface=interface.interface, direction=direction
                ).inc(delta)
                _network_totals[key] = value
        current_services = {item.name for item in payload.services}
        for stale_service in _services_by_host.get(hostname, set()) - current_services:
            service_up.remove(hostname, stale_service)
        _services_by_host[hostname] = current_services
        for service in payload.services:
            service_up.labels(hostname=hostname, service=service.name).set(
                1 if service.active_state == "active" else 0
            )


def prometheus_payload() -> bytes:
    """Serialize the current registry using Prometheus text exposition."""
    return generate_latest(registry)


def refresh_incident_counts(db: Session) -> None:
    """Refresh incident count series from the existing incident table."""
    rows = (
        db.query(Incident.status, Incident.severity, func.count(Incident.id))
        .group_by(Incident.status, Incident.severity)
        .all()
    )
    with _lock:
        incident_counts.clear()
        for status, severity, count in rows:
            incident_counts.labels(status=status, severity=severity).set(count)

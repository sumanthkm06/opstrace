"""Persist collector snapshots using the existing host, service, and metric models."""

from __future__ import annotations

from sqlalchemy.orm import Session

from backend.app.models import Host, Metric, Service
from collector.app.collectors.models import TelemetryPayload


def _append_metric(rows, *, host_id, metric_name, value, unit, timestamp, labels=None, service_id=None):
    rows.append(Metric(
        host_id=host_id,
        service_id=service_id,
        metric_name=metric_name,
        metric_value=float(value),
        unit=unit,
        timestamp=timestamp,
        labels=labels or None,
    ))


def ingest_telemetry(db: Session, payload: TelemetryPayload) -> tuple[Host, int, int]:
    """Upsert host/service state and append numeric samples from one collection cycle."""
    if payload.host is None:
        raise ValueError("Collector telemetry must include host identification.")

    data = payload.host
    host = db.query(Host).filter(Host.hostname == data.hostname).first()
    if host is None:
        host = Host(hostname=data.hostname)
        db.add(host)
        db.flush()

    host.ip_address = data.primary_ip
    host.os_info = " ".join(part for part in (data.os_name, data.os_version) if part)[:255] or None
    host.kernel_version = data.os_release
    host.cpu_count = data.cpu_count_logical
    host.total_memory_bytes = data.total_memory_bytes
    host.agent_version = data.collector_version
    host.last_heartbeat_at = payload.collected_at
    host.status = "degraded" if payload.collection_errors else "healthy"

    rows: list[Metric] = []
    if payload.cpu is not None:
        _append_metric(rows, host_id=host.id, metric_name="cpu_usage_percent", value=payload.cpu.cpu_percent,
                       unit="percent", timestamp=payload.collected_at)
    if payload.memory is not None:
        for name, value, unit in (
            ("memory_usage_percent", payload.memory.memory_percent, "percent"),
            ("memory_total_bytes", payload.memory.total_bytes, "bytes"),
            ("memory_available_bytes", payload.memory.available_bytes, "bytes"),
            ("memory_used_bytes", payload.memory.used_bytes, "bytes"),
        ):
            _append_metric(rows, host_id=host.id, metric_name=name, value=value,
                           unit=unit, timestamp=payload.collected_at)
    for disk in payload.disk:
        labels = {"mountpoint": disk.path}
        for name, value, unit in (
            ("disk_usage_percent", disk.percent, "percent"),
            ("disk_total_bytes", disk.total_bytes, "bytes"),
            ("disk_used_bytes", disk.used_bytes, "bytes"),
            ("disk_free_bytes", disk.free_bytes, "bytes"),
        ):
            _append_metric(rows, host_id=host.id, metric_name=name, value=value,
                           unit=unit, timestamp=payload.collected_at, labels=labels)
    for interface in payload.network:
        labels = {"interface": interface.interface}
        for name, value, unit in (
            ("network_bytes_sent_total", interface.bytes_sent, "bytes"),
            ("network_bytes_received_total", interface.bytes_received, "bytes"),
            ("network_packets_sent_total", interface.packets_sent, "packets"),
            ("network_packets_received_total", interface.packets_received, "packets"),
            ("network_errors_in_total", interface.errors_in, "errors"),
            ("network_errors_out_total", interface.errors_out, "errors"),
            ("network_drops_in_total", interface.drop_in, "packets"),
            ("network_drops_out_total", interface.drop_out, "packets"),
        ):
            _append_metric(rows, host_id=host.id, metric_name=name, value=value,
                           unit=unit, timestamp=payload.collected_at, labels=labels)

    services_updated = 0
    for service_data in payload.services:
        service = db.query(Service).filter(
            Service.host_id == host.id, Service.name == service_data.name
        ).first()
        if service is None:
            service = Service(host_id=host.id, name=service_data.name,
                              service_type="system", systemd_unit=service_data.name)
            db.add(service)
            db.flush()
        state = (service_data.active_state or "").lower()
        service.status = (
            "active" if state == "active" else "failed" if state == "failed"
            else "inactive" if state == "inactive" else "degraded"
        )
        services_updated += 1
        _append_metric(rows, host_id=host.id, service_id=service.id,
                       metric_name="service_up", value=state == "active", unit="boolean",
                       timestamp=payload.collected_at, labels={"service": service_data.name})

    db.add_all(rows)
    db.commit()
    return host, len(rows), services_updated

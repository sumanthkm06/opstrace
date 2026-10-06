"""
OpsTrace Collector — Telemetry Data Models
Phase 4: Linux Monitoring Collector

Typed Pydantic models representing the structured telemetry payload
assembled after each collection cycle.

These models serve as the canonical internal data contract between
the individual collectors and the backend client. They are serialised
to JSON before transmission.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import List, Optional

from pydantic import BaseModel, Field


# ---------------------------------------------------------------------------
# Individual metric models
# ---------------------------------------------------------------------------


class CpuTelemetry(BaseModel):
    """CPU utilisation snapshot."""

    cpu_percent: float = Field(
        description="Aggregate CPU utilisation across all logical cores (0.0–100.0)."
    )
    logical_cpu_count: Optional[int] = Field(
        default=None,
        description="Number of logical (hyper-threaded) CPUs visible to the OS.",
    )
    physical_cpu_count: Optional[int] = Field(
        default=None,
        description="Number of physical CPU cores.",
    )
    load_avg_1m: Optional[float] = Field(
        default=None,
        description="1-minute load average (Linux/macOS only; None on Windows).",
    )
    load_avg_5m: Optional[float] = Field(
        default=None,
        description="5-minute load average.",
    )
    load_avg_15m: Optional[float] = Field(
        default=None,
        description="15-minute load average.",
    )


class MemoryTelemetry(BaseModel):
    """System RAM snapshot."""

    total_bytes: int = Field(description="Total installed physical memory in bytes.")
    available_bytes: int = Field(
        description="Memory available to new processes without swapping."
    )
    used_bytes: int = Field(description="Memory actively in use (total − available).")
    memory_percent: float = Field(
        description="Percentage of memory in use (0.0–100.0)."
    )


class DiskTelemetry(BaseModel):
    """Single filesystem/mount-point usage snapshot."""

    path: str = Field(description="Mount point path, e.g. '/' or '/home'.")
    total_bytes: int = Field(description="Total size of the filesystem in bytes.")
    used_bytes: int = Field(description="Used space in bytes.")
    free_bytes: int = Field(description="Free space in bytes.")
    percent: float = Field(
        description="Percentage of disk space used (0.0–100.0)."
    )
    fstype: Optional[str] = Field(
        default=None,
        description="Filesystem type, e.g. 'ext4', 'xfs', 'tmpfs'.",
    )


class NetworkInterfaceTelemetry(BaseModel):
    """Per-network-interface I/O counters."""

    interface: str = Field(description="Network interface name, e.g. 'eth0'.")
    bytes_sent: int = Field(description="Cumulative bytes transmitted.")
    bytes_received: int = Field(description="Cumulative bytes received.")
    packets_sent: int = Field(description="Cumulative packets transmitted.")
    packets_received: int = Field(description="Cumulative packets received.")
    errors_in: int = Field(default=0, description="Total receive errors.")
    errors_out: int = Field(default=0, description="Total transmit errors.")
    drop_in: int = Field(default=0, description="Incoming packets dropped.")
    drop_out: int = Field(default=0, description="Outgoing packets dropped.")


class HostTelemetry(BaseModel):
    """Static host identification data."""

    hostname: str = Field(description="Fully-qualified or short hostname.")
    fqdn: Optional[str] = Field(
        default=None, description="Fully-qualified domain name if resolvable."
    )
    os_name: Optional[str] = Field(
        default=None, description="Operating system name, e.g. 'Linux'."
    )
    os_version: Optional[str] = Field(
        default=None, description="OS version string."
    )
    os_release: Optional[str] = Field(
        default=None,
        description="Kernel or OS release string, e.g. '5.15.0-91-generic'.",
    )
    architecture: Optional[str] = Field(
        default=None, description="CPU architecture, e.g. 'x86_64'."
    )
    cpu_count_logical: Optional[int] = Field(
        default=None, description="Logical CPU count."
    )
    cpu_count_physical: Optional[int] = Field(
        default=None, description="Physical CPU core count."
    )
    total_memory_bytes: Optional[int] = Field(
        default=None, description="Total installed RAM in bytes."
    )
    primary_ip: Optional[str] = Field(
        default=None,
        description="Primary non-loopback IPv4 address (best-effort).",
    )
    collector_version: str = Field(
        default="0.4.0", description="Collector daemon version."
    )


class ServiceTelemetry(BaseModel):
    """Systemd unit status snapshot."""

    name: str = Field(description="Systemd unit name, e.g. 'nginx.service'.")
    load_state: Optional[str] = Field(
        default=None,
        description="Systemd load state: 'loaded', 'not-found', etc.",
    )
    active_state: Optional[str] = Field(
        default=None,
        description="Systemd active state: 'active', 'inactive', 'failed', etc.",
    )
    sub_state: Optional[str] = Field(
        default=None,
        description="Systemd sub-state: 'running', 'dead', 'exited', etc.",
    )


# ---------------------------------------------------------------------------
# Composite telemetry payload
# ---------------------------------------------------------------------------


class TelemetryPayload(BaseModel):
    """
    Full telemetry snapshot sent to the OpsTrace backend in a single request.

    All sub-fields are Optional so that partial snapshots can be sent if
    an individual collector fails without blocking the rest.
    """

    collected_at: datetime = Field(
        default_factory=lambda: datetime.now(tz=timezone.utc),
        description="UTC timestamp when this collection cycle completed.",
    )
    host: Optional[HostTelemetry] = Field(
        default=None,
        description="Host identification and static metadata.",
    )
    cpu: Optional[CpuTelemetry] = Field(
        default=None,
        description="CPU utilisation snapshot.",
    )
    memory: Optional[MemoryTelemetry] = Field(
        default=None,
        description="System memory snapshot.",
    )
    disk: List[DiskTelemetry] = Field(
        default_factory=list,
        description="Per-mount-point disk usage snapshots.",
    )
    network: List[NetworkInterfaceTelemetry] = Field(
        default_factory=list,
        description="Per-interface network I/O counters.",
    )
    services: List[ServiceTelemetry] = Field(
        default_factory=list,
        description="Systemd service status snapshots.",
    )
    collection_errors: List[str] = Field(
        default_factory=list,
        description=(
            "Non-fatal errors encountered during collection. "
            "Allows the backend to know that some data may be missing."
        ),
    )

"""
OpsTrace Collector — Host Information Telemetry
Phase 4: Linux Monitoring Collector

Collects static host identification data: hostname, OS, architecture,
CPU topology, total memory, and primary IP address.

This data is intended to populate or update the backend `hosts` table.
It is included in every telemetry payload so the backend can identify
which host is reporting.

No passwords, private keys, or sensitive credentials are collected.
"""

import logging
import platform
import socket
from typing import Optional

import psutil

from collector.app.collectors.models import HostTelemetry

logger = logging.getLogger(__name__)

# Collector version — kept here as a constant rather than duplicating
# across every call site.  Updated alongside the package version.
COLLECTOR_VERSION = "0.4.0"


def _get_primary_ip() -> Optional[str]:
    """
    Attempt to determine the primary non-loopback IPv4 address.

    Connects a UDP socket to a well-known external address (Google DNS)
    without actually sending any data — this causes the OS to choose the
    appropriate source interface and we read the resulting local IP.

    Returns None if the operation fails (e.g. no network connectivity).
    """
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            # Connecting to an external host selects the correct interface.
            # No data is transmitted because UDP connect does not send packets.
            sock.connect(("8.8.8.8", 80))
            return sock.getsockname()[0]
    except OSError:
        return None


def _get_fqdn() -> Optional[str]:
    """Return the FQDN of this host, or None if unresolvable."""
    try:
        fqdn = socket.getfqdn()
        # getfqdn() may return the hostname itself when DNS is not configured
        return fqdn if fqdn else None
    except OSError:
        return None


def collect_host(collector_version: str = COLLECTOR_VERSION) -> HostTelemetry:
    """
    Collect static host identification and topology information.

    Information collected:
        - hostname (from socket.gethostname)
        - FQDN (best-effort DNS lookup)
        - OS name, version, and kernel release (from platform module)
        - CPU architecture
        - Logical and physical CPU counts (from psutil)
        - Total installed RAM in bytes (from psutil)
        - Primary IPv4 address (UDP socket trick — no data sent)
        - Collector daemon version

    Returns:
        HostTelemetry: Typed model with host metadata.
    """
    logger.debug("Collecting host telemetry")

    hostname = socket.gethostname()
    fqdn = _get_fqdn()
    primary_ip = _get_primary_ip()

    os_name = platform.system()          # e.g. 'Linux', 'Darwin', 'Windows'
    os_version = platform.version()      # detailed version string
    os_release = platform.release()      # kernel release, e.g. '5.15.0-91-generic'
    architecture = platform.machine()    # e.g. 'x86_64', 'aarch64'

    logical_cpus = psutil.cpu_count(logical=True)
    physical_cpus = psutil.cpu_count(logical=False)

    try:
        vm = psutil.virtual_memory()
        total_memory_bytes: Optional[int] = vm.total
    except Exception:
        total_memory_bytes = None

    telemetry = HostTelemetry(
        hostname=hostname,
        fqdn=fqdn,
        os_name=os_name,
        os_version=os_version,
        os_release=os_release,
        architecture=architecture,
        cpu_count_logical=logical_cpus,
        cpu_count_physical=physical_cpus,
        total_memory_bytes=total_memory_bytes,
        primary_ip=primary_ip,
        collector_version=collector_version,
    )

    logger.debug(
        "Host telemetry collected: hostname=%s os=%s arch=%s cpus_logical=%s",
        telemetry.hostname,
        telemetry.os_name,
        telemetry.architecture,
        telemetry.cpu_count_logical,
    )
    return telemetry

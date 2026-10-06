"""
OpsTrace Collector — Network Telemetry
Phase 4: Linux Monitoring Collector

Collects per-interface network I/O counters using psutil.
These are cumulative kernel counters; rate calculation (bytes/s) is
performed by the backend from successive snapshots.

No packet sniffing or deep-packet inspection is performed.
The collector is strictly read-only with respect to network configuration.
"""

import logging
from typing import List

import psutil

from collector.app.collectors.models import NetworkInterfaceTelemetry

logger = logging.getLogger(__name__)

# Interfaces to skip — loopback produces little useful operational information.
_SKIP_INTERFACES = {"lo"}


def collect_network() -> List[NetworkInterfaceTelemetry]:
    """
    Collect per-interface network I/O counters.

    Uses psutil.net_io_counters(pernic=True) to obtain per-interface counters.
    The loopback interface ('lo') is excluded by default.

    If no per-interface data is available (e.g. in some container environments),
    an empty list is returned.

    Returns:
        List[NetworkInterfaceTelemetry]: One entry per network interface.

    Raises:
        RuntimeError: If psutil is unable to read any network counter data.
    """
    logger.debug("Collecting network telemetry")

    try:
        counters = psutil.net_io_counters(pernic=True)
    except Exception as exc:
        raise RuntimeError(f"Failed to read network I/O counters: {exc}") from exc

    if not counters:
        logger.warning("No network interfaces found — returning empty list")
        return []

    results: List[NetworkInterfaceTelemetry] = []

    for interface, stats in counters.items():
        if interface in _SKIP_INTERFACES:
            logger.debug("Skipping loopback interface: %s", interface)
            continue

        results.append(
            NetworkInterfaceTelemetry(
                interface=interface,
                bytes_sent=stats.bytes_sent,
                bytes_received=stats.bytes_recv,
                packets_sent=stats.packets_sent,
                packets_received=stats.packets_recv,
                errors_in=stats.errin,
                errors_out=stats.errout,
                drop_in=stats.dropin,
                drop_out=stats.dropout,
            )
        )
        logger.debug(
            "Interface %s: bytes_sent=%d bytes_recv=%d packets_sent=%d packets_recv=%d",
            interface,
            stats.bytes_sent,
            stats.bytes_recv,
            stats.packets_sent,
            stats.packets_recv,
        )

    logger.debug("Network telemetry collected: %d interfaces", len(results))
    return results

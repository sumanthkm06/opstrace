"""
OpsTrace Collector — Memory Telemetry
Phase 4: Linux Monitoring Collector

Collects system RAM usage metrics using psutil.virtual_memory().
This module reports raw byte values only; percentage thresholds and
alerting are handled by the backend.
"""

import logging

import psutil

from collector.app.collectors.models import MemoryTelemetry

logger = logging.getLogger(__name__)


def collect_memory() -> MemoryTelemetry:
    """
    Collect a system memory snapshot.

    Uses psutil.virtual_memory() which queries /proc/meminfo on Linux
    and the equivalent platform APIs on other systems.

    Fields collected:
        - total:     Total installed physical RAM.
        - available: Memory available to new processes without swapping.
                     This is NOT the same as 'free'; it includes reclaimable
                     cache and buffer memory (Linux-specific semantics).
        - used:      Memory actively in use.  Computed as total − available
                     so that it is consistent across platforms.
        - percent:   (total − available) / total * 100.

    Returns:
        MemoryTelemetry: Typed model with memory usage metrics.

    Raises:
        RuntimeError: If psutil is unable to read memory statistics.
    """
    logger.debug("Collecting memory telemetry")

    try:
        vm = psutil.virtual_memory()
    except Exception as exc:
        raise RuntimeError(f"Failed to read virtual memory stats: {exc}") from exc

    telemetry = MemoryTelemetry(
        total_bytes=vm.total,
        available_bytes=vm.available,
        used_bytes=vm.used,
        memory_percent=vm.percent,
    )

    logger.debug(
        "Memory telemetry collected: total=%d available=%d percent=%.1f",
        telemetry.total_bytes,
        telemetry.available_bytes,
        telemetry.memory_percent,
    )
    return telemetry

"""
OpsTrace Collector — CPU Telemetry
Phase 4: Linux Monitoring Collector

Collects CPU utilisation metrics using psutil.
This module is deliberately minimal: it reports raw values only.
Threshold evaluation and alerting are handled by the backend.
"""

import logging
import os
from typing import Optional, Tuple

import psutil

from collector.app.collectors.models import CpuTelemetry

logger = logging.getLogger(__name__)


def _get_load_averages() -> Tuple[Optional[float], Optional[float], Optional[float]]:
    """
    Return (1m, 5m, 15m) load averages.

    getloadavg() is available on Linux and macOS but raises AttributeError
    on Windows.  We handle this gracefully so the collector can run on the
    development machine.
    """
    try:
        load1, load5, load15 = os.getloadavg()
        return load1, load5, load15
    except (AttributeError, OSError):
        # Windows or systems without /proc/loadavg
        return None, None, None


def collect_cpu() -> CpuTelemetry:
    """
    Collect a CPU utilisation snapshot.

    psutil.cpu_percent() is called with interval=1 to obtain a meaningful
    blocking measurement (as opposed to the immediately-returning 0.0 that
    would result from interval=None on the first call).

    Returns:
        CpuTelemetry: Typed model with CPU usage metrics.

    Raises:
        RuntimeError: If psutil is unable to read CPU statistics.
    """
    logger.debug("Collecting CPU telemetry")

    try:
        cpu_percent = psutil.cpu_percent(interval=1)
    except Exception as exc:
        raise RuntimeError(f"Failed to read CPU percent: {exc}") from exc

    logical = psutil.cpu_count(logical=True)
    physical = psutil.cpu_count(logical=False)

    load1, load5, load15 = _get_load_averages()

    telemetry = CpuTelemetry(
        cpu_percent=cpu_percent,
        logical_cpu_count=logical,
        physical_cpu_count=physical,
        load_avg_1m=load1,
        load_avg_5m=load5,
        load_avg_15m=load15,
    )

    logger.debug(
        "CPU telemetry collected: cpu_percent=%.1f logical=%s physical=%s",
        telemetry.cpu_percent,
        telemetry.logical_cpu_count,
        telemetry.physical_cpu_count,
    )
    return telemetry

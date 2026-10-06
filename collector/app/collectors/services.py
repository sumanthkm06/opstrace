"""
OpsTrace Collector — Linux Systemd Service Status Telemetry
Phase 4: Linux Monitoring Collector

Reads systemd unit status in a strictly READ-ONLY manner.
The collector NEVER starts, stops, restarts, or modifies any service.
It does NOT execute arbitrary shell commands received from the backend.

Systemd availability is checked before attempting queries.
If systemd is not available (container environments, non-Linux platforms,
environments without dbus), this collector returns an empty list without
raising an exception.

Two collection strategies are attempted in order:
  1. dbus / pydbus  — preferred; queries systemd Manager D-Bus interface.
  2. subprocess systemctl show — fallback using the CLI tool.

Only strategy 2 is implemented here (minimal dependency footprint).
"""

import logging
import shutil
import subprocess
from typing import List, Optional

from collector.app.collectors.models import ServiceTelemetry

logger = logging.getLogger(__name__)

# -------------------------------------------------------------------
# Configurable list of unit names to monitor.
# This is intentionally conservative: we only report on units that
# are actually present on the host.  The backend can be extended in
# future phases to allow per-host configuration of which units to watch.
# -------------------------------------------------------------------
DEFAULT_UNITS = [
    "nginx.service",
    "apache2.service",
    "postgresql.service",
    "mysql.service",
    "mariadb.service",
    "docker.service",
    "redis.service",
    "mongodb.service",
    "elasticsearch.service",
    "ssh.service",
    "sshd.service",
    "cron.service",
    "crond.service",
    "firewalld.service",
    "ufw.service",
    "fail2ban.service",
    "rsyslog.service",
    "journald.service",
    "systemd-journald.service",
    "NetworkManager.service",
    "systemd-networkd.service",
    "chronyd.service",
    "ntpd.service",
]


def _systemctl_available() -> bool:
    """
    Check whether the systemctl binary is on PATH.

    Returns False on non-Linux platforms and inside containers that do not
    have systemd installed.
    """
    return shutil.which("systemctl") is not None


def _query_unit(unit_name: str) -> Optional[ServiceTelemetry]:
    """
    Query a single systemd unit using 'systemctl show'.

    Uses 'systemctl show --no-pager --property=...' which is safe and
    read-only — it interrogates the D-Bus systemd manager interface
    through the CLI and never modifies service state.

    Returns None if the unit is not installed (LoadState = not-found).
    """
    properties = ["LoadState", "ActiveState", "SubState"]
    cmd = [
        "systemctl",
        "show",
        "--no-pager",
        f"--property={','.join(properties)}",
        unit_name,
    ]

    try:
        result = subprocess.run(  # noqa: S603
            cmd,
            capture_output=True,
            text=True,
            timeout=5,
            check=False,  # We inspect returncode ourselves
        )
    except FileNotFoundError:
        # systemctl disappeared between _systemctl_available() and here
        logger.debug("systemctl not found while querying unit %s", unit_name)
        return None
    except subprocess.TimeoutExpired:
        logger.warning("Timed out querying systemd unit %s — skipping", unit_name)
        return None
    except OSError as exc:
        logger.warning("OSError querying unit %s: %s — skipping", unit_name, exc)
        return None

    # Parse key=value pairs from stdout
    state: dict = {}
    for line in result.stdout.splitlines():
        if "=" in line:
            key, _, value = line.partition("=")
            state[key.strip()] = value.strip()

    load_state = state.get("LoadState", "")
    active_state = state.get("ActiveState", "")
    sub_state = state.get("SubState", "")

    # Skip units that systemd does not know about at all
    if load_state in ("not-found", "masked", ""):
        logger.debug("Unit %s not found or masked (LoadState=%s)", unit_name, load_state)
        return None

    return ServiceTelemetry(
        name=unit_name,
        load_state=load_state or None,
        active_state=active_state or None,
        sub_state=sub_state or None,
    )


def collect_services(unit_names: Optional[List[str]] = None) -> List[ServiceTelemetry]:
    """
    Collect systemd service status for the specified unit names.

    This function is strictly read-only.  It NEVER modifies service state.

    If systemctl is not available (non-Linux platform, minimal container,
    etc.), an empty list is returned without raising an exception.

    Args:
        unit_names: List of unit names to query.  Defaults to DEFAULT_UNITS.

    Returns:
        List[ServiceTelemetry]: Status for each unit that is installed and
        known to systemd.  Not-found/masked units are omitted.
    """
    if unit_names is None:
        unit_names = DEFAULT_UNITS

    if not _systemctl_available():
        logger.info(
            "systemctl not found — skipping service status collection. "
            "This is expected on Windows and in containers without systemd."
        )
        return []

    logger.debug("Collecting service telemetry for %d units", len(unit_names))

    results: List[ServiceTelemetry] = []

    for unit_name in unit_names:
        service = _query_unit(unit_name)
        if service is not None:
            results.append(service)
            logger.debug(
                "Service %s: active_state=%s sub_state=%s",
                service.name,
                service.active_state,
                service.sub_state,
            )

    logger.debug(
        "Service telemetry collected: %d units found of %d queried",
        len(results),
        len(unit_names),
    )
    return results

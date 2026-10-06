"""
OpsTrace Collector — Disk Telemetry
Phase 4: Linux Monitoring Collector

Collects disk usage statistics for real, mounted filesystems using psutil.
Virtual/pseudo-filesystems (tmpfs, devtmpfs, sysfs, proc, etc.) are
filtered out by default to avoid cluttering the telemetry payload.
"""

import logging
from typing import List, Set

import psutil

from collector.app.collectors.models import DiskTelemetry

logger = logging.getLogger(__name__)

# Filesystem types to skip — these are virtual or kernel pseudo-filesystems
# that do not represent persistent storage.
_VIRTUAL_FSTYPES: Set[str] = {
    "tmpfs",
    "devtmpfs",
    "devfs",
    "sysfs",
    "proc",
    "cgroup",
    "cgroup2",
    "pstore",
    "debugfs",
    "securityfs",
    "overlay",
    "squashfs",
    "fuse.gvfsd-fuse",
    "fuse.sshfs",
    "fusectl",
    "hugetlbfs",
    "mqueue",
    "bpf",
    "tracefs",
    "configfs",
    "efivarfs",
    "autofs",
    "binfmt_misc",
    "rpc_pipefs",
}


def _is_real_filesystem(partition: psutil.disk_partitions) -> bool:  # type: ignore[name-defined]
    """
    Return True if the partition represents persistent (non-virtual) storage.

    Filters out:
    - Known virtual filesystem types.
    - Duplicate /dev/loop* snap mounts (squashfs overlays on Ubuntu).
    """
    if partition.fstype.lower() in _VIRTUAL_FSTYPES:
        return False
    # Skip loop devices (snap packages on Ubuntu create many squashfs loop mounts)
    if partition.device.startswith("/dev/loop"):
        return False
    return True


def collect_disk() -> List[DiskTelemetry]:
    """
    Collect disk usage for all real, mounted filesystems.

    Iterates over psutil.disk_partitions() and queries disk_usage() for
    each partition that passes the virtual-filesystem filter.

    Errors on individual mount points are caught and logged so that a single
    unreadable mount (e.g. an unmounted NFS share) does not abort the entire
    collection cycle.

    Returns:
        List[DiskTelemetry]: One entry per real filesystem/mount point.
    """
    logger.debug("Collecting disk telemetry")

    results: List[DiskTelemetry] = []

    try:
        partitions = psutil.disk_partitions(all=False)
    except Exception as exc:
        raise RuntimeError(f"Failed to list disk partitions: {exc}") from exc

    for partition in partitions:
        if not _is_real_filesystem(partition):
            logger.debug(
                "Skipping virtual filesystem: device=%s fstype=%s mountpoint=%s",
                partition.device,
                partition.fstype,
                partition.mountpoint,
            )
            continue

        try:
            usage = psutil.disk_usage(partition.mountpoint)
        except PermissionError:
            logger.warning(
                "Permission denied reading disk usage for %s — skipping",
                partition.mountpoint,
            )
            continue
        except OSError as exc:
            logger.warning(
                "OSError reading disk usage for %s: %s — skipping",
                partition.mountpoint,
                exc,
            )
            continue

        results.append(
            DiskTelemetry(
                path=partition.mountpoint,
                total_bytes=usage.total,
                used_bytes=usage.used,
                free_bytes=usage.free,
                percent=usage.percent,
                fstype=partition.fstype or None,
            )
        )
        logger.debug(
            "Disk %s: total=%d used=%d free=%d percent=%.1f",
            partition.mountpoint,
            usage.total,
            usage.used,
            usage.free,
            usage.percent,
        )

    logger.debug("Disk telemetry collected: %d mount points", len(results))
    return results

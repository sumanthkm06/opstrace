"""
OpsTrace Linux Monitoring Collector
Phase 4: Linux Monitoring Collector

Entry point for the OpsTrace collector daemon.

The collector:
  1. Reads configuration from environment variables.
  2. Runs a controlled collection loop at the configured interval.
  3. On each cycle, collects CPU, memory, disk, network, host, and service
     telemetry using modular sub-collectors.
  4. Assembles a typed TelemetryPayload and sends it to the backend.
  5. Handles individual collection failures gracefully without crashing.
  6. Supports clean shutdown via SIGINT / SIGTERM.

Security:
  - Read-only with respect to the monitored system.
  - Never executes commands received from the backend.
  - Never logs the COLLECTOR_API_KEY.

Running:
    # From the repository root:
    python -m collector.main

    # Or directly:
    python collector/main.py

    # With custom settings:
    BACKEND_URL=http://192.168.1.10:8000 \\
    COLLECTOR_API_KEY=<token> \\
    COLLECTION_INTERVAL=30 \\
    python -m collector.main
"""

import logging
import signal
import sys
import time
from pathlib import Path
from typing import List, Optional

# ---------------------------------------------------------------------------
# Ensure the repository root is on sys.path when run directly.
# ---------------------------------------------------------------------------
_REPO_ROOT = Path(__file__).resolve().parent.parent
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from collector.app.clients.backend import BackendClient, build_client_from_settings
from collector.app.collectors.cpu import collect_cpu
from collector.app.collectors.disk import collect_disk
from collector.app.collectors.host import collect_host
from collector.app.collectors.memory import collect_memory
from collector.app.collectors.models import TelemetryPayload
from collector.app.collectors.network import collect_network
from collector.app.collectors.services import collect_services
from collector.app.config.settings import get_collector_settings

# Phase 5 log imports
from collector.app.collectors.log_batcher import LogBatcher
from collector.app.collectors.log_file import build_file_collectors, collect_from_files
from collector.app.collectors.log_journal import collect_journal

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Shutdown flag — set by signal handlers to break the collection loop cleanly.
# ---------------------------------------------------------------------------
_running: bool = True


def _handle_shutdown_signal(signum: int, frame: object) -> None:  # noqa: ARG001
    """Handle SIGINT and SIGTERM for graceful shutdown."""
    global _running
    logger.info(
        "Received signal %d — initiating graceful shutdown", signum
    )
    _running = False


def _setup_signal_handlers() -> None:
    """Register SIGINT and SIGTERM handlers for graceful shutdown."""
    signal.signal(signal.SIGINT, _handle_shutdown_signal)
    signal.signal(signal.SIGTERM, _handle_shutdown_signal)


def _setup_logging(log_level: str) -> None:
    """Configure structured console logging."""
    numeric_level = getattr(logging, log_level.upper(), logging.INFO)
    logging.basicConfig(
        level=numeric_level,
        format="%(asctime)s %(levelname)-8s %(name)s — %(message)s",
        datefmt="%Y-%m-%dT%H:%M:%S",
        stream=sys.stdout,
    )


def run_collection_cycle(
    client: Optional[BackendClient],
    collect_svc: bool = True,
) -> TelemetryPayload:
    """
    Execute one full telemetry collection cycle.

    Each sub-collector is wrapped in its own try/except so that a failure
    in one area does not prevent the others from running.  Non-fatal errors
    are accumulated in payload.collection_errors so the backend is aware
    that some data may be absent.

    Args:
        client:       BackendClient instance, or None if not configured.
        collect_svc:  Whether to attempt service status collection.

    Returns:
        TelemetryPayload assembled from successful sub-collectors.
    """
    errors: List[str] = []

    # ---- Host ----------------------------------------------------------
    host_telemetry = None
    try:
        host_telemetry = collect_host()
    except Exception as exc:
        msg = f"host collection failed: {exc}"
        logger.error("Collection error — %s", msg)
        errors.append(msg)

    # ---- CPU -----------------------------------------------------------
    cpu_telemetry = None
    try:
        cpu_telemetry = collect_cpu()
    except Exception as exc:
        msg = f"cpu collection failed: {exc}"
        logger.error("Collection error — %s", msg)
        errors.append(msg)

    # ---- Memory --------------------------------------------------------
    memory_telemetry = None
    try:
        memory_telemetry = collect_memory()
    except Exception as exc:
        msg = f"memory collection failed: {exc}"
        logger.error("Collection error — %s", msg)
        errors.append(msg)

    # ---- Disk ----------------------------------------------------------
    disk_telemetry = []
    try:
        disk_telemetry = collect_disk()
    except Exception as exc:
        msg = f"disk collection failed: {exc}"
        logger.error("Collection error — %s", msg)
        errors.append(msg)

    # ---- Network -------------------------------------------------------
    network_telemetry = []
    try:
        network_telemetry = collect_network()
    except Exception as exc:
        msg = f"network collection failed: {exc}"
        logger.error("Collection error — %s", msg)
        errors.append(msg)

    # ---- Services ------------------------------------------------------
    service_telemetry = []
    if collect_svc:
        try:
            service_telemetry = collect_services()
        except Exception as exc:
            msg = f"service collection failed: {exc}"
            logger.error("Collection error — %s", msg)
            errors.append(msg)

    payload = TelemetryPayload(
        host=host_telemetry,
        cpu=cpu_telemetry,
        memory=memory_telemetry,
        disk=disk_telemetry,
        network=network_telemetry,
        services=service_telemetry,
        collection_errors=errors,
    )

    logger.info(
        "Collection cycle complete — cpu=%.1f%% mem=%.1f%% disks=%d "
        "interfaces=%d services=%d errors=%d",
        payload.cpu.cpu_percent if payload.cpu else -1,
        payload.memory.memory_percent if payload.memory else -1,
        len(payload.disk),
        len(payload.network),
        len(payload.services),
        len(payload.collection_errors),
    )

    if client is not None:
        sent = client.send_telemetry(payload)
        if sent:
            logger.info("Telemetry delivered to backend successfully")
        else:
            logger.warning(
                "Telemetry delivery failed — data will be lost for this cycle"
            )
    else:
        logger.debug("No backend client configured — telemetry not sent")

    return payload


def main() -> None:
    """
    Entry point for the OpsTrace collector daemon.

    Reads configuration, starts the collection loop, and runs until
    a SIGINT or SIGTERM signal is received.
    """
    global _running

    settings = get_collector_settings()
    _setup_logging(settings.LOG_LEVEL)
    _setup_signal_handlers()

    logger.info(
        "OpsTrace Collector starting — version=%s env=%s backend=%s interval=%ds",
        settings.COLLECTOR_VERSION,
        settings.ENVIRONMENT,
        settings.BACKEND_URL,
        settings.COLLECTION_INTERVAL,
        # NOTE: COLLECTOR_API_KEY is intentionally NOT logged here.
    )

    client = build_client_from_settings()

    # Phase 5: Log Collector Initialisation
    log_batcher = None
    file_collectors = []
    journal_cursor = None
    first_cycle = True

    if settings.COLLECT_LOGS:
        log_batcher = LogBatcher(
            backend_client=client,
            batch_size=settings.LOG_BATCH_SIZE,
        )
        file_collectors = build_file_collectors(settings.get_log_file_paths())
        logger.info(
            "Log collection enabled: %d file(s) configured, journal=%s",
            len(file_collectors),
            settings.COLLECT_JOURNAL,
        )

    try:
        while _running:
            logger.info("Starting collection cycle")
            
            # 1. Telemetry Collection
            try:
                run_collection_cycle(
                    client=client,
                    collect_svc=settings.COLLECT_SERVICES,
                )
            except Exception as exc:
                # Catch any unexpected top-level error to keep the daemon alive.
                logger.exception(
                    "Unexpected error in telemetry collection cycle: %s — continuing", exc
                )

            # 2. Log Collection
            if settings.COLLECT_LOGS and log_batcher is not None:
                try:
                    # File logs
                    file_events, file_errors = collect_from_files(file_collectors)
                    if file_events:
                        log_batcher.add_events(file_events, collection_errors=file_errors)
                        
                    # Journal logs
                    if settings.COLLECT_JOURNAL:
                        journal_events, next_cursor = collect_journal(
                            lines=settings.JOURNAL_LINES if first_cycle else 200,
                            since_cursor=journal_cursor,
                        )
                        if next_cursor:
                            journal_cursor = next_cursor
                        if journal_events:
                            log_batcher.add_events(journal_events)
                            
                    # Always flush at the end of the collection cycle
                    flushed = log_batcher.flush(collection_errors=file_errors)
                    if flushed > 0:
                        logger.info("Flushed %d log events at end of cycle", flushed)
                        
                except Exception as exc:
                    logger.exception(
                        "Unexpected error in log collection cycle: %s — continuing", exc
                    )
            
            first_cycle = False

            # Interruptible sleep: check _running flag every second so that
            # SIGINT/SIGTERM are acted upon within 1 second rather than waiting
            # for the full interval.
            elapsed = 0
            while _running and elapsed < settings.COLLECTION_INTERVAL:
                time.sleep(1)
                elapsed += 1
    finally:
        if log_batcher is not None:
            # Attempt a final flush on clean shutdown
            try:
                log_batcher.flush()
            except Exception as exc:
                logger.error("Error flushing logs on shutdown: %s", exc)
                
        if client is not None:
            client.close()
        logger.info("OpsTrace Collector shut down cleanly")


if __name__ == "__main__":
    main()

"""
OpsTrace Collector — Log Batcher and Backend Sender
Phase 5: Log Collection and Ingestion

Accumulates collected log events into fixed-size batches and sends
each batch to the backend in a single HTTP POST.

Batching behaviour:
  - Events are buffered until the configured batch size is reached OR
    the collection cycle ends (flush remainder).
  - The batch size is configurable via ``LOG_BATCH_SIZE``.
  - A batch containing zero events is never sent.
  - Connection failures are logged; no events are silently lost
    (a warning is always emitted).

Security:
  - Uses the same ``BackendClient`` (and its Authorization header)
    as the Phase 4 telemetry sender.
  - The API key is never logged or included in exception messages.
"""

from __future__ import annotations

import logging
import socket
from datetime import datetime, timezone
from typing import List, Optional

from collector.app.collectors.log_models import CollectedLogEvent, LogBatch

logger = logging.getLogger(__name__)

# Path on the OpsTrace backend that accepts log batches.
_LOG_INGEST_ENDPOINT = "/api/v1/logs/ingest"

# Conservative timeouts (seconds) — independent of the telemetry client.
_CONNECT_TIMEOUT = 5
_READ_TIMEOUT = 20


class LogBatcher:
    """
    Accumulates log events and flushes them to the backend in batches.

    Usage::

        batcher = LogBatcher(backend_client=client, batch_size=100)
        batcher.add_events(events)
        batcher.flush()   # send any remaining buffered events
        batcher.reset()   # clear the buffer (called automatically on flush)

    Args:
        backend_client: A ``BackendClient``-compatible object with a
                        ``_session`` attribute and ``backend_url`` property.
                        Pass None to operate in dry-run mode (events are
                        counted but not sent).
        batch_size:     Number of events to accumulate before auto-flushing.
                        Defaults to 100.
        hostname:       Hostname to embed in each batch payload.
    """

    def __init__(
        self,
        backend_client,  # BackendClient | None — avoid circular import
        batch_size: int = 100,
        hostname: Optional[str] = None,
    ) -> None:
        self._client = backend_client
        self._batch_size = max(1, batch_size)
        self._hostname = hostname or _get_local_hostname()
        self._buffer: List[CollectedLogEvent] = []
        self._batches_sent: int = 0
        self._events_sent: int = 0

    # ------------------------------------------------------------------
    # Public interface
    # ------------------------------------------------------------------

    @property
    def buffered_count(self) -> int:
        """Number of events currently waiting in the buffer."""
        return len(self._buffer)

    @property
    def batches_sent(self) -> int:
        """Total number of HTTP batches sent in this batcher's lifetime."""
        return self._batches_sent

    def add_events(
        self,
        events: List[CollectedLogEvent],
        collection_errors: Optional[List[str]] = None,
    ) -> int:
        """
        Add a list of events to the buffer and auto-flush when full.

        Returns the number of events flushed (may be 0 if buffer is not full).
        """
        self._buffer.extend(events)
        flushed = 0

        while len(self._buffer) >= self._batch_size:
            batch_events = self._buffer[: self._batch_size]
            self._buffer = self._buffer[self._batch_size :]
            flushed += self._send_batch(batch_events, collection_errors or [])

        return flushed

    def flush(self, collection_errors: Optional[List[str]] = None) -> int:
        """
        Send all remaining buffered events regardless of batch size.

        This should be called at the end of each collection cycle to ensure
        no events are left buffered.

        Returns the number of events sent.
        """
        if not self._buffer:
            return 0
        events = self._buffer[:]
        self._buffer = []
        return self._send_batch(events, collection_errors or [])

    def reset(self) -> None:
        """Discard all buffered events without sending."""
        self._buffer = []

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _send_batch(
        self,
        events: List[CollectedLogEvent],
        collection_errors: List[str],
    ) -> int:
        """
        Serialise ``events`` into a ``LogBatch`` and POST to the backend.

        Returns the number of events in the batch (for accounting).
        """
        if not events:
            return 0

        batch = LogBatch(
            collected_at=datetime.now(tz=timezone.utc),
            hostname=self._hostname,
            events=events,
            collection_errors=collection_errors,
        )

        if self._client is None:
            logger.debug(
                "No backend client configured — log batch of %d events not sent.",
                len(events),
            )
            return len(events)

        url = f"{self._client.backend_url}{_LOG_INGEST_ENDPOINT}"

        try:
            body = batch.model_dump_json()
        except Exception as exc:
            logger.error("Failed to serialise log batch: %s", exc)
            return 0

        logger.debug(
            "Sending log batch: %d events to %s", len(events), url
        )

        try:
            from requests.exceptions import ConnectionError, RequestException, Timeout

            response = self._client._session.post(
                url,
                data=body,
                timeout=(_CONNECT_TIMEOUT, _READ_TIMEOUT),
            )
        except ConnectionError as exc:
            logger.warning(
                "Cannot reach backend at %s for log ingestion: %s",
                self._client.backend_url,
                exc,
            )
            return 0
        except Timeout:
            logger.warning(
                "Log ingestion request timed out (connect=%ds read=%ds)",
                _CONNECT_TIMEOUT,
                _READ_TIMEOUT,
            )
            return 0
        except Exception as exc:
            logger.error("Unexpected error sending log batch: %s", exc)
            return 0

        if response.ok:
            self._batches_sent += 1
            self._events_sent += len(events)
            logger.debug(
                "Log batch accepted: status=%d events=%d",
                response.status_code,
                len(events),
            )
            return len(events)

        logger.warning(
            "Backend rejected log batch: status=%d body=%.200s",
            response.status_code,
            response.text,
        )
        return 0


def _get_local_hostname() -> str:
    """Return the local machine hostname; falls back to 'unknown'."""
    try:
        return socket.gethostname()
    except Exception:
        return "unknown"

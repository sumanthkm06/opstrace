"""
OpsTrace Collector — HTTP Backend Client
Phase 4: Linux Monitoring Collector

Responsible for serialising and transmitting the telemetry payload to
the OpsTrace FastAPI backend via HTTP POST.

Security requirements:
  - The COLLECTOR_API_KEY is NEVER logged, printed, or included in
    exception messages.
  - Only the configured BACKEND_URL is used; no other endpoints are called.
  - Connection errors are caught and reported without crashing the daemon.

The client does NOT implement retry logic with exponential back-off in
Phase 4; failed requests are logged and the collection loop continues
on the next interval.  Retry/circuit-breaker patterns are deferred to
a later phase.
"""

import logging
from typing import Optional

import requests
from requests.exceptions import ConnectionError, RequestException, Timeout

from collector.app.collectors.models import TelemetryPayload

logger = logging.getLogger(__name__)

# Endpoint path on the OpsTrace backend
_TELEMETRY_ENDPOINT = "/api/v1/telemetry"

# Conservative timeouts (seconds) for connect and read phases
_CONNECT_TIMEOUT = 5
_READ_TIMEOUT = 15


class BackendClient:
    """
    Lightweight HTTP client for sending telemetry to the OpsTrace backend.

    Usage::

        client = BackendClient(
            backend_url="http://192.168.1.10:8000",
            api_key="<token>",
        )
        ok = client.send_telemetry(payload)
    """

    def __init__(self, backend_url: str, api_key: str) -> None:
        """
        Initialise the client.

        Args:
            backend_url: Base URL of the OpsTrace backend, e.g.
                         'http://192.168.1.10:8000'.  Trailing slash is
                         stripped for consistent URL construction.
            api_key:     Bearer token for the Authorization header.
                         This value is NEVER logged.
        """
        self._backend_url = backend_url.rstrip("/")
        # Store the key privately; never expose it outside this instance.
        self.__api_key = api_key

        # Build a reusable session so HTTP keep-alive is used across requests.
        self._session = requests.Session()
        self._session.headers.update(
            {
                "Content-Type": "application/json",
                "Accept": "application/json",
                # The Authorization header is added here once at construction
                # time so it never appears in log statements.
                "Authorization": f"Bearer {self.__api_key}",
            }
        )

    @property
    def backend_url(self) -> str:
        """Public URL of the configured backend (safe to log)."""
        return self._backend_url

    def send_telemetry(self, payload: TelemetryPayload) -> bool:
        """
        Serialise and POST a telemetry payload to the backend.

        Args:
            payload: TelemetryPayload instance containing the current
                     collection cycle results.

        Returns:
            True if the backend returned a 2xx status code.
            False if a connection error, timeout, or non-2xx response occurs.

        The API key is NOT included in any log or exception message.
        """
        url = f"{self._backend_url}{_TELEMETRY_ENDPOINT}"

        try:
            body = payload.model_dump_json()
        except Exception as exc:
            logger.error("Failed to serialise telemetry payload: %s", exc)
            return False

        logger.debug(
            "Sending telemetry to %s (collected_at=%s)",
            url,
            payload.collected_at.isoformat(),
        )

        try:
            response = self._session.post(
                url,
                data=body,
                timeout=(_CONNECT_TIMEOUT, _READ_TIMEOUT),
            )
        except ConnectionError as exc:
            logger.warning(
                "Cannot reach backend at %s — connection refused or network error: %s",
                self._backend_url,
                exc,
            )
            return False
        except Timeout:
            logger.warning(
                "Backend at %s timed out (connect=%ds read=%ds)",
                self._backend_url,
                _CONNECT_TIMEOUT,
                _READ_TIMEOUT,
            )
            return False
        except RequestException as exc:
            logger.error(
                "Unexpected HTTP error sending telemetry to %s: %s",
                self._backend_url,
                exc,
            )
            return False

        if response.ok:
            logger.debug(
                "Telemetry accepted by backend: status=%d",
                response.status_code,
            )
            return True

        logger.warning(
            "Backend rejected telemetry: status=%d url=%s",
            response.status_code,
            url,
        )
        return False

    def close(self) -> None:
        """Close the underlying HTTP session and release connections."""
        self._session.close()
        logger.debug("BackendClient session closed")


def build_client_from_settings() -> Optional[BackendClient]:
    """
    Construct a BackendClient from the collector settings.

    Returns None if the COLLECTOR_API_KEY is not configured, to prevent
    accidental unauthenticated requests.  A warning is logged in this case.
    """
    from collector.app.config.settings import get_collector_settings

    settings = get_collector_settings()

    if not settings.COLLECTOR_API_KEY:
        logger.warning(
            "COLLECTOR_API_KEY is not set — telemetry will NOT be sent. "
            "Set COLLECTOR_API_KEY in the environment or .env file."
        )
        return None

    return BackendClient(
        backend_url=settings.BACKEND_URL,
        api_key=settings.COLLECTOR_API_KEY,
    )

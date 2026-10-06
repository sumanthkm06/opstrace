import logging
from unittest.mock import MagicMock, patch

from collector.app.clients.backend import BackendClient
from collector.app.collectors.models import TelemetryPayload


def test_backend_error_response_body_is_not_logged(caplog):
    response = MagicMock(ok=False, status_code=500, text="secret-diagnostic-value")
    client = BackendClient("http://localhost:8000", "not-a-real-key")
    with patch("requests.Session.post", return_value=response):
        with caplog.at_level(logging.WARNING, logger="collector"):
            assert client.send_telemetry(TelemetryPayload()) is False
    assert "secret-diagnostic-value" not in caplog.text
    client.close()

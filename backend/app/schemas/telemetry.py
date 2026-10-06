"""Response schema for collector telemetry ingestion."""

from datetime import datetime
from pydantic import BaseModel


class TelemetryIngestResponse(BaseModel):
    accepted: bool
    host_id: str
    metrics_recorded: int
    services_updated: int
    collected_at: datetime

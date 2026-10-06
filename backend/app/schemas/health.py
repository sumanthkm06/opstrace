"""
OpsTrace Health Check Schemas
Phase 3: FastAPI Backend Foundation

Pydantic response models for health check endpoints.
No business logic — pure data shapes for API responses.
"""

from datetime import datetime, timezone
from typing import Literal, Optional

from pydantic import BaseModel, Field


class HealthResponse(BaseModel):
    """
    Basic application health response.
    Returned by GET /health.
    """

    status: Literal["ok", "degraded", "error"] = Field(
        description="Overall health status of the service",
    )
    service: str = Field(
        default="opstrace-backend",
        description="Canonical service name",
    )
    version: str = Field(
        description="Application version string",
    )
    environment: str = Field(
        description="Runtime environment (development, production, testing)",
    )
    timestamp: datetime = Field(
        description="UTC timestamp when the health response was generated",
    )

    model_config = {"json_encoders": {datetime: lambda v: v.isoformat()}}


class DatabaseHealthStatus(BaseModel):
    """
    Database connectivity status embedded in the API health response.
    """

    connected: bool = Field(description="Whether the database is reachable")
    message: str = Field(description="Human-readable status message")


class APIHealthResponse(BaseModel):
    """
    Extended API health response including database status.
    Returned by GET /api/v1/health.
    """

    status: Literal["ok", "degraded", "error"] = Field(
        description="Overall API health status",
    )
    service: str = Field(
        default="opstrace-backend",
        description="Canonical service name",
    )
    version: str = Field(
        description="Application version string",
    )
    environment: str = Field(
        description="Runtime environment",
    )
    api_version: str = Field(
        default="v1",
        description="API version prefix",
    )
    database: DatabaseHealthStatus = Field(
        description="Database connectivity status",
    )
    timestamp: datetime = Field(
        description="UTC timestamp when the health response was generated",
    )

    model_config = {"json_encoders": {datetime: lambda v: v.isoformat()}}

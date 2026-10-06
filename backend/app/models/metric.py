"""
OpsTrace Metric Entity Model
Phase 2: PostgreSQL Database Design and Implementation
"""

import uuid
from datetime import datetime
from typing import TYPE_CHECKING, Any, Dict, Optional
from sqlalchemy import DateTime, Float, ForeignKey, Index, String, Uuid, func
from sqlalchemy.orm import Mapped, mapped_column, relationship

from backend.app.models.base import Base, JSONType

if TYPE_CHECKING:
    from backend.app.models.host import Host
    from backend.app.models.service import Service


class Metric(Base):
    """
    Time-series metric data point ingested from host or service probes.
    Indexed for high-throughput range scans by host/service and timestamp.
    """
    __tablename__ = "metrics"
    __table_args__ = (
        Index("ix_metrics_host_name_ts", "host_id", "metric_name", "timestamp"),
        Index("ix_metrics_service_name_ts", "service_id", "metric_name", "timestamp"),
    )

    id: Mapped[uuid.UUID] = mapped_column(
        Uuid,
        primary_key=True,
        default=uuid.uuid4,
    )
    host_id: Mapped[uuid.UUID] = mapped_column(
        Uuid,
        ForeignKey("hosts.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    service_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        Uuid,
        ForeignKey("services.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )
    metric_name: Mapped[str] = mapped_column(
        String(100),
        nullable=False,
        index=True,
    )
    metric_value: Mapped[float] = mapped_column(
        Float,
        nullable=False,
    )
    unit: Mapped[Optional[str]] = mapped_column(
        String(50),
        nullable=True,
    )
    labels: Mapped[Optional[Dict[str, Any]]] = mapped_column(
        JSONType,
        nullable=True,
    )
    timestamp: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        index=True,
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
    )

    # Relationships
    host: Mapped["Host"] = relationship(
        back_populates="metrics",
    )
    service: Mapped[Optional["Service"]] = relationship(
        back_populates="metrics",
    )

    def __repr__(self) -> str:
        return (
            f"<Metric(id={self.id}, name='{self.metric_name}', value={self.metric_value}, "
            f"timestamp={self.timestamp})>"
        )

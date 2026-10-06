"""
OpsTrace Incident Event Model (Timeline/Replay)
Phase 2: PostgreSQL Database Design and Implementation
"""

import uuid
from datetime import datetime
from typing import TYPE_CHECKING, Any, Dict, Optional
from sqlalchemy import DateTime, ForeignKey, Index, String, Text, Uuid, func
from sqlalchemy.orm import Mapped, mapped_column, relationship

from backend.app.models.base import Base, JSONType

if TYPE_CHECKING:
    from backend.app.models.incident import Incident


class IncidentEvent(Base):
    """
    Chronological event log within an incident lifecycle.
    Powers incident timeline construction and deterministic incident replay.
    """
    __tablename__ = "incident_events"
    __table_args__ = (
        Index("ix_incident_events_incident_ts", "incident_id", "timestamp"),
    )

    id: Mapped[uuid.UUID] = mapped_column(
        Uuid,
        primary_key=True,
        default=uuid.uuid4,
    )
    incident_id: Mapped[uuid.UUID] = mapped_column(
        Uuid,
        ForeignKey("incidents.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    event_type: Mapped[str] = mapped_column(
        String(100),
        nullable=False,
        index=True,
    )
    message: Mapped[str] = mapped_column(
        Text,
        nullable=False,
    )
    payload: Mapped[Optional[Dict[str, Any]]] = mapped_column(
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
    incident: Mapped["Incident"] = relationship(
        back_populates="events",
    )

    def __repr__(self) -> str:
        return (
            f"<IncidentEvent(id={self.id}, incident_id={self.incident_id}, type='{self.event_type}', "
            f"timestamp={self.timestamp})>"
        )

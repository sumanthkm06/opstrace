"""
OpsTrace Incident Entity Model
Phase 2: PostgreSQL Database Design and Implementation
"""

import uuid
from datetime import datetime
from typing import TYPE_CHECKING, Any, Dict, List, Optional
from sqlalchemy import CheckConstraint, DateTime, ForeignKey, Index, String, Text, Uuid
from sqlalchemy.orm import Mapped, mapped_column, relationship

from backend.app.models.base import Base, JSONType, TimestampMixin

if TYPE_CHECKING:
    from backend.app.models.host import Host
    from backend.app.models.service import Service
    from backend.app.models.deployment import Deployment
    from backend.app.models.config_change import ConfigChange
    from backend.app.models.incident_event import IncidentEvent
    from backend.app.models.remediation import Remediation


class Incident(Base, TimestampMixin):
    """
    Represents an operational incident evaluated by health thresholds or anomaly algorithms.
    Maintains correlation references to suspect deployments and configuration alterations.
    """
    __tablename__ = "incidents"
    __table_args__ = (
        CheckConstraint(
            "status IN ('open', 'investigating', 'mitigated', 'resolved', 'closed')",
            name="ck_incidents_status",
        ),
        CheckConstraint(
            "severity IN ('critical', 'high', 'medium', 'low')",
            name="ck_incidents_severity",
        ),
        Index("ix_incidents_status_severity", "status", "severity"),
        Index("ix_incidents_host_detected_at", "host_id", "detected_at"),
    )

    id: Mapped[uuid.UUID] = mapped_column(
        Uuid,
        primary_key=True,
        default=uuid.uuid4,
    )
    title: Mapped[str] = mapped_column(
        String(255),
        nullable=False,
    )
    description: Mapped[Optional[str]] = mapped_column(
        Text,
        nullable=True,
    )
    status: Mapped[str] = mapped_column(
        String(50),
        nullable=False,
        default="open",
        index=True,
    )
    severity: Mapped[str] = mapped_column(
        String(50),
        nullable=False,
        default="medium",
        index=True,
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
    detected_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        index=True,
    )
    resolved_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )
    root_cause_analysis: Mapped[Optional[str]] = mapped_column(
        Text,
        nullable=True,
    )
    correlated_deployment_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        Uuid,
        ForeignKey("deployments.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )
    correlated_config_change_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        Uuid,
        ForeignKey("config_changes.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )
    metadata_json: Mapped[Optional[Dict[str, Any]]] = mapped_column(
        JSONType,
        nullable=True,
    )

    # Relationships
    host: Mapped["Host"] = relationship(
        back_populates="incidents",
    )
    service: Mapped[Optional["Service"]] = relationship(
        back_populates="incidents",
    )
    correlated_deployment: Mapped[Optional["Deployment"]] = relationship(
        back_populates="correlated_incidents",
    )
    correlated_config_change: Mapped[Optional["ConfigChange"]] = relationship(
        back_populates="correlated_incidents",
    )
    events: Mapped[List["IncidentEvent"]] = relationship(
        back_populates="incident",
        cascade="all, delete-orphan",
        order_by="IncidentEvent.timestamp",
    )
    remediations: Mapped[List["Remediation"]] = relationship(
        back_populates="incident",
        cascade="all, delete-orphan",
    )

    def __repr__(self) -> str:
        return (
            f"<Incident(id={self.id}, title='{self.title}', status='{self.status}', "
            f"severity='{self.severity}')>"
        )

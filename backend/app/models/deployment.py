"""
OpsTrace Deployment Entity Model
Phase 2: PostgreSQL Database Design and Implementation
"""

import uuid
from datetime import datetime
from typing import TYPE_CHECKING, Any, Dict, List, Optional
from sqlalchemy import CheckConstraint, DateTime, ForeignKey, Index, String, Text, Uuid, func
from sqlalchemy.orm import Mapped, mapped_column, relationship

from backend.app.models.base import Base, JSONType

if TYPE_CHECKING:
    from backend.app.models.host import Host
    from backend.app.models.service import Service
    from backend.app.models.config_change import ConfigChange
    from backend.app.models.incident import Incident


class Deployment(Base):
    """
    Tracks software deployments, package releases, and container updates.
    Crucial for change-aware correlation and candidate cause analysis.
    """
    __tablename__ = "deployments"
    __table_args__ = (
        CheckConstraint(
            "status IN ('started', 'completed', 'failed', 'rolled_back')",
            name="ck_deployments_status",
        ),
        Index("ix_deployments_service_deployed_at", "service_id", "deployed_at"),
    )

    id: Mapped[uuid.UUID] = mapped_column(
        Uuid,
        primary_key=True,
        default=uuid.uuid4,
    )
    service_id: Mapped[uuid.UUID] = mapped_column(
        Uuid,
        ForeignKey("services.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    host_id: Mapped[uuid.UUID] = mapped_column(
        Uuid,
        ForeignKey("hosts.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    version: Mapped[str] = mapped_column(
        String(100),
        nullable=False,
    )
    environment: Mapped[str] = mapped_column(
        String(50),
        nullable=False,
        default="production",
    )
    status: Mapped[str] = mapped_column(
        String(50),
        nullable=False,
        default="completed",
        index=True,
    )
    deployed_by: Mapped[str] = mapped_column(
        String(100),
        nullable=False,
    )
    commit_hash: Mapped[Optional[str]] = mapped_column(
        String(64),
        nullable=True,
    )
    release_notes: Mapped[Optional[str]] = mapped_column(
        Text,
        nullable=True,
    )
    metadata_json: Mapped[Optional[Dict[str, Any]]] = mapped_column(
        JSONType,
        nullable=True,
    )
    deployed_at: Mapped[datetime] = mapped_column(
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
    service: Mapped["Service"] = relationship(
        back_populates="deployments",
    )
    host: Mapped["Host"] = relationship(
        back_populates="deployments",
    )
    config_changes: Mapped[List["ConfigChange"]] = relationship(
        back_populates="deployment",
    )
    correlated_incidents: Mapped[List["Incident"]] = relationship(
        back_populates="correlated_deployment",
    )

    def __repr__(self) -> str:
        return (
            f"<Deployment(id={self.id}, service_id={self.service_id}, version='{self.version}', "
            f"deployed_at={self.deployed_at})>"
        )

"""
OpsTrace Host Entity Model
Phase 2: PostgreSQL Database Design and Implementation
"""

import uuid
from datetime import datetime
from typing import TYPE_CHECKING, List, Optional
from sqlalchemy import BigInteger, CheckConstraint, DateTime, Integer, String, Uuid
from sqlalchemy.orm import Mapped, mapped_column, relationship

from backend.app.models.base import Base, TimestampMixin

if TYPE_CHECKING:
    from backend.app.models.service import Service
    from backend.app.models.metric import Metric
    from backend.app.models.log import Log
    from backend.app.models.deployment import Deployment
    from backend.app.models.config_change import ConfigChange
    from backend.app.models.incident import Incident


class Host(Base, TimestampMixin):
    """
    Represents a monitored Linux host machine emitting system metrics and logs.
    """
    __tablename__ = "hosts"
    __table_args__ = (
        CheckConstraint(
            "status IN ('healthy', 'degraded', 'critical', 'offline')",
            name="ck_hosts_status",
        ),
    )

    id: Mapped[uuid.UUID] = mapped_column(
        Uuid,
        primary_key=True,
        default=uuid.uuid4,
    )
    hostname: Mapped[str] = mapped_column(
        String(255),
        unique=True,
        nullable=False,
        index=True,
    )
    ip_address: Mapped[Optional[str]] = mapped_column(
        String(45),
        nullable=True,
    )
    os_info: Mapped[Optional[str]] = mapped_column(
        String(255),
        nullable=True,
    )
    kernel_version: Mapped[Optional[str]] = mapped_column(
        String(255),
        nullable=True,
    )
    status: Mapped[str] = mapped_column(
        String(50),
        nullable=False,
        default="healthy",
        index=True,
    )
    cpu_count: Mapped[Optional[int]] = mapped_column(
        Integer,
        nullable=True,
    )
    total_memory_bytes: Mapped[Optional[int]] = mapped_column(
        BigInteger,
        nullable=True,
    )
    total_disk_bytes: Mapped[Optional[int]] = mapped_column(
        BigInteger,
        nullable=True,
    )
    agent_version: Mapped[Optional[str]] = mapped_column(
        String(50),
        nullable=True,
    )
    last_heartbeat_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
        index=True,
    )

    # Relationships
    services: Mapped[List["Service"]] = relationship(
        back_populates="host",
        cascade="all, delete-orphan",
    )
    metrics: Mapped[List["Metric"]] = relationship(
        back_populates="host",
        cascade="all, delete-orphan",
    )
    logs: Mapped[List["Log"]] = relationship(
        back_populates="host",
        cascade="all, delete-orphan",
    )
    deployments: Mapped[List["Deployment"]] = relationship(
        back_populates="host",
        cascade="all, delete-orphan",
    )
    config_changes: Mapped[List["ConfigChange"]] = relationship(
        back_populates="host",
        cascade="all, delete-orphan",
    )
    incidents: Mapped[List["Incident"]] = relationship(
        back_populates="host",
        cascade="all, delete-orphan",
    )

    def __repr__(self) -> str:
        return f"<Host(id={self.id}, hostname='{self.hostname}', status='{self.status}')>"

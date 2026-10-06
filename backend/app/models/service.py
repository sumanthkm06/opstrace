"""
OpsTrace Service Entity Model
Phase 2: PostgreSQL Database Design and Implementation
"""

import uuid
from typing import TYPE_CHECKING, List, Optional
from sqlalchemy import CheckConstraint, ForeignKey, Integer, String, Text, UniqueConstraint, Uuid
from sqlalchemy.orm import Mapped, mapped_column, relationship

from backend.app.models.base import Base, TimestampMixin

if TYPE_CHECKING:
    from backend.app.models.host import Host
    from backend.app.models.service_dependency import ServiceDependency
    from backend.app.models.metric import Metric
    from backend.app.models.log import Log
    from backend.app.models.deployment import Deployment
    from backend.app.models.config_change import ConfigChange
    from backend.app.models.incident import Incident


class Service(Base, TimestampMixin):
    """
    Represents an application, database, or systemd daemon managed on a host.
    """
    __tablename__ = "services"
    __table_args__ = (
        UniqueConstraint("host_id", "name", name="uq_services_host_name"),
        CheckConstraint(
            "status IN ('active', 'inactive', 'failed', 'degraded')",
            name="ck_services_status",
        ),
        CheckConstraint(
            "port IS NULL OR (port > 0 AND port <= 65535)",
            name="ck_services_port",
        ),
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
    name: Mapped[str] = mapped_column(
        String(100),
        nullable=False,
        index=True,
    )
    systemd_unit: Mapped[Optional[str]] = mapped_column(
        String(100),
        nullable=True,
    )
    service_type: Mapped[str] = mapped_column(
        String(50),
        nullable=False,
        default="application",
    )
    status: Mapped[str] = mapped_column(
        String(50),
        nullable=False,
        default="active",
        index=True,
    )
    port: Mapped[Optional[int]] = mapped_column(
        Integer,
        nullable=True,
    )
    description: Mapped[Optional[str]] = mapped_column(
        Text,
        nullable=True,
    )

    # Relationships
    host: Mapped["Host"] = relationship(
        back_populates="services",
    )
    metrics: Mapped[List["Metric"]] = relationship(
        back_populates="service",
    )
    logs: Mapped[List["Log"]] = relationship(
        back_populates="service",
    )
    deployments: Mapped[List["Deployment"]] = relationship(
        back_populates="service",
        cascade="all, delete-orphan",
    )
    config_changes: Mapped[List["ConfigChange"]] = relationship(
        back_populates="service",
    )
    incidents: Mapped[List["Incident"]] = relationship(
        back_populates="service",
    )

    # Self-referencing service dependencies
    upstream_dependencies: Mapped[List["ServiceDependency"]] = relationship(
        "ServiceDependency",
        foreign_keys="ServiceDependency.service_id",
        back_populates="service",
        cascade="all, delete-orphan",
    )
    downstream_dependencies: Mapped[List["ServiceDependency"]] = relationship(
        "ServiceDependency",
        foreign_keys="ServiceDependency.depends_on_service_id",
        back_populates="depends_on_service",
        cascade="all, delete-orphan",
    )

    def __repr__(self) -> str:
        return f"<Service(id={self.id}, name='{self.name}', host_id={self.host_id}, status='{self.status}')>"

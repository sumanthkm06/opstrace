"""
OpsTrace Configuration Change Entity Model
Phase 2: PostgreSQL Database Design and Implementation
"""

import uuid
from datetime import datetime
from typing import TYPE_CHECKING, List, Optional
from sqlalchemy import CheckConstraint, DateTime, ForeignKey, Index, String, Text, Uuid, func
from sqlalchemy.orm import Mapped, mapped_column, relationship

from backend.app.models.base import Base

if TYPE_CHECKING:
    from backend.app.models.host import Host
    from backend.app.models.service import Service
    from backend.app.models.deployment import Deployment
    from backend.app.models.incident import Incident


class ConfigChange(Base):
    """
    Records configuration file alterations, sysctl adjustments, or environment variables.
    Provides precise change diffs used by the correlation engine.
    """
    __tablename__ = "config_changes"
    __table_args__ = (
        CheckConstraint(
            "change_type IN ('modify', 'add', 'delete', 'env_var_update')",
            name="ck_config_changes_type",
        ),
        Index("ix_config_changes_host_changed_at", "host_id", "changed_at"),
        Index("ix_config_changes_service_changed_at", "service_id", "changed_at"),
    )

    id: Mapped[uuid.UUID] = mapped_column(
        Uuid,
        primary_key=True,
        default=uuid.uuid4,
    )
    service_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        Uuid,
        ForeignKey("services.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )
    host_id: Mapped[uuid.UUID] = mapped_column(
        Uuid,
        ForeignKey("hosts.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    deployment_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        Uuid,
        ForeignKey("deployments.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )
    config_file_path: Mapped[str] = mapped_column(
        String(500),
        nullable=False,
        index=True,
    )
    change_type: Mapped[str] = mapped_column(
        String(50),
        nullable=False,
        default="modify",
    )
    previous_value: Mapped[Optional[str]] = mapped_column(
        Text,
        nullable=True,
    )
    new_value: Mapped[Optional[str]] = mapped_column(
        Text,
        nullable=True,
    )
    diff: Mapped[Optional[str]] = mapped_column(
        Text,
        nullable=True,
    )
    changed_by: Mapped[str] = mapped_column(
        String(100),
        nullable=False,
    )
    changed_at: Mapped[datetime] = mapped_column(
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
    service: Mapped[Optional["Service"]] = relationship(
        back_populates="config_changes",
    )
    host: Mapped["Host"] = relationship(
        back_populates="config_changes",
    )
    deployment: Mapped[Optional["Deployment"]] = relationship(
        back_populates="config_changes",
    )
    correlated_incidents: Mapped[List["Incident"]] = relationship(
        back_populates="correlated_config_change",
    )

    def __repr__(self) -> str:
        return (
            f"<ConfigChange(id={self.id}, path='{self.config_file_path}', type='{self.change_type}', "
            f"changed_at={self.changed_at})>"
        )

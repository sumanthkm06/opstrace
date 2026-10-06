"""
OpsTrace Service Dependency Model (Self-Referencing Graph Edge)
Phase 2: PostgreSQL Database Design and Implementation
"""

import uuid
from datetime import datetime
from typing import TYPE_CHECKING, Optional
from sqlalchemy import CheckConstraint, DateTime, ForeignKey, String, Text, UniqueConstraint, Uuid, func
from sqlalchemy.orm import Mapped, mapped_column, relationship

from backend.app.models.base import Base

if TYPE_CHECKING:
    from backend.app.models.service import Service


class ServiceDependency(Base):
    """
    Directed dependency edge between two services.
    Captures downstream caller -> upstream provider for blast radius and impact analysis.
    """
    __tablename__ = "service_dependencies"
    __table_args__ = (
        UniqueConstraint(
            "service_id",
            "depends_on_service_id",
            name="uq_service_dependencies_edge",
        ),
        CheckConstraint(
            "service_id != depends_on_service_id",
            name="ck_service_dependencies_no_self_loop",
        ),
        CheckConstraint(
            "dependency_type IN ('synchronous', 'asynchronous', 'database', 'internal_call')",
            name="ck_service_dependencies_type",
        ),
        CheckConstraint(
            "criticality IN ('critical', 'non_critical', 'optional')",
            name="ck_service_dependencies_criticality",
        ),
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
    depends_on_service_id: Mapped[uuid.UUID] = mapped_column(
        Uuid,
        ForeignKey("services.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    dependency_type: Mapped[str] = mapped_column(
        String(50),
        nullable=False,
        default="synchronous",
    )
    criticality: Mapped[str] = mapped_column(
        String(50),
        nullable=False,
        default="critical",
    )
    description: Mapped[Optional[str]] = mapped_column(
        Text,
        nullable=True,
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
    )

    # Relationships
    service: Mapped["Service"] = relationship(
        "Service",
        foreign_keys=[service_id],
        back_populates="upstream_dependencies",
    )
    depends_on_service: Mapped["Service"] = relationship(
        "Service",
        foreign_keys=[depends_on_service_id],
        back_populates="downstream_dependencies",
    )

    def __repr__(self) -> str:
        return (
            f"<ServiceDependency(id={self.id}, service_id={self.service_id} -> "
            f"depends_on={self.depends_on_service_id}, type='{self.dependency_type}')>"
        )

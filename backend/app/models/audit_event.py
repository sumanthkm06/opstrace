"""
OpsTrace Immutable Audit Event Entity Model
Phase 2: PostgreSQL Database Design and Implementation
"""

import uuid
from datetime import datetime
from typing import TYPE_CHECKING, Any, Dict, Optional
from sqlalchemy import DateTime, ForeignKey, Index, String, Uuid, func
from sqlalchemy.orm import Mapped, mapped_column, relationship

from backend.app.models.base import Base, JSONType

if TYPE_CHECKING:
    from backend.app.models.remediation import Remediation


class AuditEvent(Base):
    """
    Append-only immutable audit log tracking administrative commands,
    remediation approvals, configuration overrides, and security-relevant actions.
    """
    __tablename__ = "audit_events"
    __table_args__ = (
        Index("ix_audit_events_actor_ts", "actor", "created_at"),
        Index("ix_audit_events_action_ts", "action", "created_at"),
    )

    id: Mapped[uuid.UUID] = mapped_column(
        Uuid,
        primary_key=True,
        default=uuid.uuid4,
    )
    remediation_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        Uuid,
        ForeignKey("remediations.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )
    action: Mapped[str] = mapped_column(
        String(100),
        nullable=False,
        index=True,
    )
    actor: Mapped[str] = mapped_column(
        String(100),
        nullable=False,
        index=True,
    )
    resource_type: Mapped[str] = mapped_column(
        String(50),
        nullable=False,
    )
    resource_id: Mapped[str] = mapped_column(
        String(100),
        nullable=False,
    )
    details: Mapped[Optional[Dict[str, Any]]] = mapped_column(
        JSONType,
        nullable=True,
    )
    ip_address: Mapped[Optional[str]] = mapped_column(
        String(45),
        nullable=True,
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
        index=True,
    )

    # Relationships
    remediation: Mapped[Optional["Remediation"]] = relationship(
        back_populates="audit_events",
    )

    def __repr__(self) -> str:
        return (
            f"<AuditEvent(id={self.id}, action='{self.action}', actor='{self.actor}', "
            f"resource={self.resource_type}:{self.resource_id})>"
        )

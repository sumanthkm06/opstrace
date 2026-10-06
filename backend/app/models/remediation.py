"""
OpsTrace Remediation Entity Model (Controlled Human Approval Workflow)
Phase 2: PostgreSQL Database Design and Implementation
"""

import uuid
from datetime import datetime
from typing import TYPE_CHECKING, Any, Dict, List, Optional
from sqlalchemy import CheckConstraint, DateTime, ForeignKey, String, Text, Uuid
from sqlalchemy.orm import Mapped, mapped_column, relationship

from backend.app.models.base import Base, JSONType, TimestampMixin

if TYPE_CHECKING:
    from backend.app.models.incident import Incident
    from backend.app.models.audit_event import AuditEvent


class Remediation(Base, TimestampMixin):
    """
    Suggested remediation action for an incident.
    Enforces human operator review/approval gate; strictly auditable.
    """
    __tablename__ = "remediations"
    __table_args__ = (
        CheckConstraint(
            "status IN ('pending_approval', 'approved', 'rejected', 'executed', 'failed')",
            name="ck_remediations_status",
        ),
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
    action_type: Mapped[str] = mapped_column(
        String(100),
        nullable=False,
    )
    description: Mapped[str] = mapped_column(
        Text,
        nullable=False,
    )
    status: Mapped[str] = mapped_column(
        String(50),
        nullable=False,
        default="pending_approval",
        index=True,
    )
    parameters: Mapped[Optional[Dict[str, Any]]] = mapped_column(
        JSONType,
        nullable=True,
    )
    rationale: Mapped[Optional[str]] = mapped_column(
        Text,
        nullable=True,
    )
    requested_by: Mapped[str] = mapped_column(
        String(100),
        nullable=False,
        default="system",
    )
    approved_by: Mapped[Optional[str]] = mapped_column(
        String(100),
        nullable=True,
    )
    approved_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )
    executed_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )
    execution_output: Mapped[Optional[str]] = mapped_column(
        Text,
        nullable=True,
    )

    # Relationships
    incident: Mapped["Incident"] = relationship(
        back_populates="remediations",
    )
    audit_events: Mapped[List["AuditEvent"]] = relationship(
        back_populates="remediation",
    )

    def __repr__(self) -> str:
        return (
            f"<Remediation(id={self.id}, incident_id={self.incident_id}, action='{self.action_type}', "
            f"status='{self.status}')>"
        )

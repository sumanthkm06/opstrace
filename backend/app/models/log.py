"""
OpsTrace Log Entity Model
Phase 2: PostgreSQL Database Design and Implementation
"""

import uuid
from datetime import datetime
from typing import TYPE_CHECKING, Any, Dict, Optional
from sqlalchemy import CheckConstraint, DateTime, ForeignKey, Index, String, Text, Uuid, func
from sqlalchemy.orm import Mapped, mapped_column, relationship

from backend.app.models.base import Base, JSONType

if TYPE_CHECKING:
    from backend.app.models.host import Host
    from backend.app.models.service import Service


class Log(Base):
    """
    Ingested Linux systemd, syslog, or application log entry.
    Features fingerprinting for error clustering and indexes for log search and anomaly detection.
    """
    __tablename__ = "logs"
    __table_args__ = (
        CheckConstraint(
            "level IN ('DEBUG', 'INFO', 'WARN', 'WARNING', 'ERROR', 'CRITICAL', 'FATAL')",
            name="ck_logs_level",
        ),
        Index("ix_logs_host_level_ts", "host_id", "level", "timestamp"),
        Index("ix_logs_service_level_ts", "service_id", "level", "timestamp"),
        Index("ix_logs_fingerprint_ts", "fingerprint", "timestamp"),
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
    timestamp: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        index=True,
    )
    level: Mapped[str] = mapped_column(
        String(20),
        nullable=False,
        default="INFO",
        index=True,
    )
    message: Mapped[str] = mapped_column(
        Text,
        nullable=False,
    )
    source: Mapped[str] = mapped_column(
        String(100),
        nullable=False,
        default="syslog",
    )
    fingerprint: Mapped[Optional[str]] = mapped_column(
        String(64),
        nullable=True,
        index=True,
    )
    attributes: Mapped[Optional[Dict[str, Any]]] = mapped_column(
        JSONType,
        nullable=True,
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
    )

    # Relationships
    host: Mapped["Host"] = relationship(
        back_populates="logs",
    )
    service: Mapped[Optional["Service"]] = relationship(
        back_populates="logs",
    )

    def __repr__(self) -> str:
        return f"<Log(id={self.id}, level='{self.level}', source='{self.source}', timestamp={self.timestamp})>"

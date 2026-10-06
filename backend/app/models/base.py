"""
OpsTrace SQLAlchemy Base Model and Declarative Types
Phase 2: PostgreSQL Database Design and Implementation
"""

import uuid
from datetime import datetime
from sqlalchemy import DateTime, func, Uuid, JSON
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column

# PostgreSQL JSONB with SQLite JSON fallback for testing
JSONType = JSONB().with_variant(JSON(), "sqlite")


class Base(DeclarativeBase):
    """
    Root declarative base for all OpsTrace relational models.
    """
    pass


class TimestampMixin:
    """
    Reusable timestamp mixin enforcing UTC timezone-aware created_at and updated_at.
    """
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
        onupdate=func.now(),
    )

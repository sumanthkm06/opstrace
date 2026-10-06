"""
OpsTrace Database Engine and Session Management
Phase 2: PostgreSQL Database Design and Implementation
"""

import logging
from typing import Generator, Optional
from sqlalchemy import Engine, create_engine, event, text
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

from backend.app.core.config import get_settings

logger = logging.getLogger(__name__)


def create_db_engine(db_url: Optional[str] = None, echo: bool = False) -> Engine:
    """
    Factory function to initialize a SQLAlchemy Engine based on environment settings.
    Configures pool pre-ping, connection recycling, and cross-database safeguards.
    """
    settings = get_settings()
    url = db_url or settings.sqlalchemy_database_uri

    if url.startswith("sqlite"):
        # SQLite configuration for local unit/integration tests
        connect_args = {"check_same_thread": False}
        if ":memory:" in url or "mode=memory" in url:
            engine = create_engine(
                url,
                connect_args=connect_args,
                poolclass=StaticPool,
                echo=echo,
            )
        else:
            engine = create_engine(
                url,
                connect_args=connect_args,
                echo=echo,
            )

        # Enforce foreign key constraints in SQLite
        @event.listens_for(engine, "connect")
        def set_sqlite_pragma(dbapi_connection, connection_record):
            cursor = dbapi_connection.cursor()
            cursor.execute("PRAGMA foreign_keys=ON")
            cursor.close()

        return engine

    # Standard PostgreSQL Engine Configuration
    return create_engine(
        url,
        pool_size=settings.POSTGRES_POOL_SIZE,
        max_overflow=settings.POSTGRES_MAX_OVERFLOW,
        pool_timeout=settings.POSTGRES_POOL_TIMEOUT,
        pool_recycle=settings.POSTGRES_POOL_RECYCLE,
        pool_pre_ping=True,
        echo=echo,
    )


# Default application-wide engine and sessionmaker
engine = create_db_engine()
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


def get_db() -> Generator[Session, None, None]:
    """
    Dependency generator for obtaining an isolated SQLAlchemy session per operation/request.
    Guarantees session cleanup upon completion or failure.
    """
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def check_database_connection(target_engine: Optional[Engine] = None) -> bool:
    """
    Executes a lightweight ping query ('SELECT 1') to verify database connectivity.
    """
    eng = target_engine or engine
    try:
        with eng.connect() as conn:
            conn.execute(text("SELECT 1"))
        return True
    except Exception as e:
        logger.error("Database health check failed (%s).", type(e).__name__)
        return False

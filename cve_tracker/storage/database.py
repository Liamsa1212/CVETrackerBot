"""Database engine creation, session management, and schema initialization."""

from pathlib import Path
from typing import AsyncGenerator
from loguru import logger
from sqlalchemy import event
from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)
from cve_tracker.storage.models import Base


def create_db_engine(database_url: str) -> AsyncEngine:
    """Create and configure asynchronous SQLAlchemy database engine."""
    # Ensure data directory exists if local sqlite
    connect_args = {}
    if "sqlite" in database_url:
        connect_args["timeout"] = 30.0
        if "///" in database_url:
            db_path = database_url.split("///")[-1]
            parent_dir = Path(db_path).parent
            if parent_dir and not parent_dir.exists():
                parent_dir.mkdir(parents=True, exist_ok=True)

    engine = create_async_engine(
        database_url,
        echo=False,
        future=True,
        connect_args=connect_args,
    )

    if "sqlite" in database_url:
        @event.listens_for(engine.sync_engine, "connect")
        def set_sqlite_pragma(dbapi_connection, connection_record):
            cursor = dbapi_connection.cursor()
            try:
                cursor.execute("PRAGMA journal_mode=WAL")
                cursor.execute("PRAGMA synchronous=NORMAL")
            except Exception:
                pass
            finally:
                cursor.close()

    return engine


def create_session_factory(engine: AsyncEngine) -> async_sessionmaker[AsyncSession]:
    """Create async session factory."""
    return async_sessionmaker(
        bind=engine,
        class_=AsyncSession,
        expire_on_commit=False,
        autoflush=False,
    )


async def init_db(engine: AsyncEngine) -> None:
    """Initialize database tables and run lightweight automatic column migrations."""
    logger.info("Initializing database schema...")
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
        # Migrate schema additions gracefully on existing databases
        for col, col_type in (("epss_score", "FLOAT"), ("epss_percentile", "FLOAT")):
            try:
                await conn.exec_driver_sql(f"ALTER TABLE cves ADD COLUMN {col} {col_type}")
                logger.info(f"Migrated column {col} into cves table.")
            except Exception:
                # Column already exists
                pass
    logger.info("Database schema initialized successfully.")

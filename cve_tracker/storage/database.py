"""Database engine creation, session management, and schema initialization."""

from pathlib import Path
from typing import AsyncGenerator
from loguru import logger
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
    if "sqlite" in database_url and "///" in database_url:
        db_path = database_url.split("///")[-1]
        parent_dir = Path(db_path).parent
        if parent_dir and not parent_dir.exists():
            parent_dir.mkdir(parents=True, exist_ok=True)

    engine = create_async_engine(
        database_url,
        echo=False,
        future=True,
    )
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
    """Initialize database tables."""
    logger.info("Initializing database schema...")
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    logger.info("Database schema initialized successfully.")

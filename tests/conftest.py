"""Pytest fixtures and test configuration."""

import asyncio
from datetime import datetime, timezone
import pytest
import pytest_asyncio
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from cve_tracker.core.config import Settings
from cve_tracker.models.cve import (
    CVEItem,
    CVSSData,
    Reference,
    Severity,
    SourceType,
)
from cve_tracker.models.filter import SubscriptionFilter
from cve_tracker.models.subscriber import ChannelType
from cve_tracker.storage.models import Base
from cve_tracker.storage.repository import CVERepository


@pytest.fixture(scope="session")
def event_loop():
    """Create event loop for test suite."""
    policy = asyncio.get_event_loop_policy()
    loop = policy.new_event_loop()
    yield loop
    loop.close()


@pytest.fixture
def test_settings() -> Settings:
    """Settings configured for test environment."""
    return Settings(
        telegram_bot_token="123456:TEST_TOKEN",
        database_url="sqlite+aiosqlite:///:memory:",
        poll_interval_seconds=60,
        default_min_cvss=7.0,
        request_timeout_seconds=5.0,
        max_retries=2,
    )


@pytest_asyncio.fixture
async def async_engine():
    """Create in-memory SQLite engine for tests."""
    engine = create_async_engine("sqlite+aiosqlite:///:memory:", echo=False)
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    yield engine
    await engine.dispose()


@pytest_asyncio.fixture
async def session_factory(async_engine):
    """Create sessionmaker for test database."""
    return async_sessionmaker(bind=async_engine, class_=AsyncSession, expire_on_commit=False)


@pytest_asyncio.fixture
async def repository(session_factory) -> CVERepository:
    """Create repository backed by in-memory SQLite."""
    return CVERepository(session_factory)


@pytest.fixture
def sample_cve() -> CVEItem:
    """Sample critical CVE Item."""
    return CVEItem(
        id="CVE-2024-9999",
        source=SourceType.NVD,
        title="Test Critical Remote Code Execution Vulnerability",
        description="A remote code execution flaw exists in Example Service due to improper buffer validation.",
        cvss=CVSSData(
            version="3.1",
            score=9.8,
            vector_string="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            severity=Severity.CRITICAL,
        ),
        cwes=["CWE-120"],
        affected_vendors=["microsoft"],
        affected_products=["windows_server"],
        references=[
            Reference(url="https://github.com/example/poc", tags=["exploit"]),
            Reference(url="https://example.com/advisory", tags=["vendor-advisory"]),
        ],
        published_at=datetime.now(timezone.utc),
    )


@pytest.fixture
def sample_cisa_cve() -> CVEItem:
    """Sample CISA KEV actively exploited CVE."""
    return CVEItem(
        id="CVE-2024-1111",
        source=SourceType.CISA_KEV,
        title="Actively Exploited Zero-Day Flaw",
        description="Known exploited zero-day vulnerability in Gateway Router.",
        cvss=CVSSData(
            version="3.1",
            score=9.0,
            severity=Severity.CRITICAL,
        ),
        cwes=["CWE-78"],
        affected_vendors=["cisco"],
        affected_products=["ios_xe"],
        is_cisa_kev=True,
    )

"""Abstract Base Class for external vulnerability data fetchers."""

from abc import ABC, abstractmethod
from datetime import datetime
from typing import List, Optional
import httpx
from cve_tracker.core.config import Settings
from cve_tracker.core.rate_limiter import AsyncRateLimiter
from cve_tracker.models.cve import CVEItem, SourceType


class BaseCVEFetcher(ABC):
    """Abstract base class for all vulnerability sources."""

    def __init__(
        self,
        settings: Settings,
        client: Optional[httpx.AsyncClient] = None,
        rate_limiter: Optional[AsyncRateLimiter] = None,
    ):
        self.settings = settings
        self._external_client = client
        self._client: Optional[httpx.AsyncClient] = None
        self.rate_limiter = rate_limiter or AsyncRateLimiter(rate=2.0, capacity=5.0)

    @property
    @abstractmethod
    def source(self) -> SourceType:
        """The source identifier enum."""

    async def get_client(self) -> httpx.AsyncClient:
        """Get or create the HTTP client instance."""
        if self._external_client:
            return self._external_client
        if self._client is None or self._client.is_closed:
            self._client = httpx.AsyncClient(
                timeout=httpx.Timeout(self.settings.request_timeout_seconds),
                headers={"User-Agent": "CVETrackerBot/2.0 (Security Intelligence)"},
                http2=True,
                follow_redirects=True,
            )
        return self._client

    async def close(self) -> None:
        """Close the internal HTTP client if owned."""
        if self._client and not self._client.is_closed:
            await self._client.aclose()

    @abstractmethod
    async def fetch_latest(
        self,
        since: Optional[datetime] = None,
        limit: int = 20,
    ) -> List[CVEItem]:
        """Fetch latest vulnerabilities published or updated since given datetime."""

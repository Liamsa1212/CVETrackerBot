"""Fetcher manager coordinating concurrent multi-source vulnerability ingestion."""

import asyncio
from datetime import datetime, timedelta, timezone
from typing import List, Optional, Tuple
from loguru import logger

from cve_tracker.core.config import Settings
from cve_tracker.fetchers.base import BaseCVEFetcher
from cve_tracker.fetchers.cisa_kev import CISAKEVFetcher
from cve_tracker.fetchers.github import GitHubAdvisoryFetcher
from cve_tracker.fetchers.nvd import NVDFetcher
from cve_tracker.models.cve import CVEItem
from cve_tracker.storage.repository import CVERepository


class FetcherManager:
    """Coordinates fetching from all enabled CVE and advisory sources."""

    def __init__(
        self,
        settings: Settings,
        repository: CVERepository,
        fetchers: Optional[List[BaseCVEFetcher]] = None,
    ):
        self.settings = settings
        self.repository = repository
        if fetchers is not None:
            self.fetchers = fetchers
        else:
            self.fetchers = [
                CISAKEVFetcher(settings),
                NVDFetcher(settings),
                GitHubAdvisoryFetcher(settings),
            ]

    async def poll_and_ingest(
        self,
        since: Optional[datetime] = None,
        limit_per_source: int = 50,
    ) -> List[CVEItem]:
        """
        Poll all sources concurrently, deduplicate, persist to database,
        and return only the newly discovered or meaningfully updated CVE items.
        """
        if since is None:
            since = datetime.now(timezone.utc) - timedelta(
                seconds=self.settings.poll_interval_seconds * 2
            )

        logger.info(f"Starting vulnerability poll across {len(self.fetchers)} sources...")

        async def _fetch_source(f: BaseCVEFetcher) -> List[CVEItem]:
            try:
                return await f.fetch_latest(since=since, limit=limit_per_source)
            except Exception as e:
                logger.error(f"Error fetching from {f.source}: {e}")
                return []

        results = await asyncio.gather(*[_fetch_source(f) for f in self.fetchers], return_exceptions=True)

        all_cves: List[CVEItem] = []
        for res in results:
            if isinstance(res, list):
                all_cves.extend(res)

        logger.info(f"Aggregated {len(all_cves)} CVE items from all sources. Persisting to database...")

        newly_updated_cves: List[CVEItem] = []
        seen_ids = set()

        for cve in all_cves:
            # Deduplicate items in the same batch
            if cve.id in seen_ids:
                continue
            seen_ids.add(cve.id)

            try:
                saved_item, is_new = await self.repository.upsert_cve(cve)
                if is_new:
                    newly_updated_cves.append(saved_item)
            except Exception as e:
                logger.error(f"Failed to upsert CVE {cve.id}: {e}")

        logger.info(
            f"Poll cycle complete. {len(newly_updated_cves)} new/updated CVEs stored."
        )
        return newly_updated_cves

    async def close(self) -> None:
        """Close resources across all fetchers."""
        for f in self.fetchers:
            await f.close()

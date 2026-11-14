"""Fetcher manager coordinating concurrent multi-source vulnerability ingestion."""

import asyncio
from datetime import datetime, timedelta, timezone
from typing import List, Optional, Tuple
from loguru import logger

from cve_tracker.core.config import Settings
from cve_tracker.fetchers.base import BaseCVEFetcher
from cve_tracker.fetchers.cisa_kev import CISAKEVFetcher
from cve_tracker.fetchers.epss import EPSSClient
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
        epss_client: Optional[EPSSClient] = None,
    ):
        self.settings = settings
        self.repository = repository
        self.epss_client = epss_client or EPSSClient(settings)
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

        logger.info(f"Aggregated {len(all_cves)} CVE items from all sources. Querying EPSS scores...")

        # Enrich with EPSS probability
        cve_ids_to_enrich = [c.id for c in all_cves if c.id.startswith("CVE-")]
        if cve_ids_to_enrich:
            try:
                epss_scores = await self.epss_client.get_scores(cve_ids_to_enrich)
                for c in all_cves:
                    if c.id in epss_scores:
                        c.epss_score, c.epss_percentile = epss_scores[c.id]
            except Exception as e:
                logger.warning(f"Failed to enrich batch with EPSS scores: {e}")

        logger.info(f"Persisting {len(all_cves)} enriched CVEs to database...")

        # Merge multiple records for identical CVE ID across feeds (NVD + CISA + GHSA)
        merged_cves: Dict[str, CVEItem] = {}
        for cve in all_cves:
            if cve.id not in merged_cves:
                merged_cves[cve.id] = cve
            else:
                existing = merged_cves[cve.id]
                # Merge KEV flags
                if cve.is_cisa_kev:
                    existing.is_cisa_kev = True
                    if cve.cisa_action_due:
                        existing.cisa_action_due = cve.cisa_action_due
                # Merge CVSS data
                if not existing.cvss and cve.cvss:
                    existing.cvss = cve.cvss
                elif existing.cvss and cve.cvss and (cve.cvss.score or 0) > (existing.cvss.score or 0):
                    existing.cvss = cve.cvss
                # Merge CWEs
                if cve.cwes:
                    existing.cwes = sorted(list(set(existing.cwes + cve.cwes)))
                # Merge vendors and products
                if cve.affected_vendors:
                    existing.affected_vendors = sorted(list(set(existing.affected_vendors + cve.affected_vendors)))
                if cve.affected_products:
                    existing.affected_products = sorted(list(set(existing.affected_products + cve.affected_products)))
                # Merge references
                existing_urls = {r.url for r in existing.references}
                for ref in cve.references:
                    if ref.url not in existing_urls:
                        existing.references.append(ref)
                        existing_urls.add(ref.url)
                # Merge EPSS
                if existing.epss_score is None and cve.epss_score is not None:
                    existing.epss_score = cve.epss_score
                    existing.epss_percentile = cve.epss_percentile

        newly_updated_cves: List[CVEItem] = []
        for cve in merged_cves.values():
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
        """Close resources across all fetchers and clients."""
        await self.epss_client.close()
        for f in self.fetchers:
            await f.close()

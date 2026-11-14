"""CISA Known Exploited Vulnerabilities (KEV) Catalog Fetcher."""

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
import httpx
from loguru import logger

from cve_tracker.core.config import Settings
from cve_tracker.core.rate_limiter import AsyncRateLimiter, execute_with_retry
from cve_tracker.fetchers.base import BaseCVEFetcher
from cve_tracker.models.cve import (
    CVEItem,
    CVSSData,
    Reference,
    Severity,
    SourceType,
)

CISA_KEV_FEED_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"


class CISAKEVFetcher(BaseCVEFetcher):
    """Fetches CISA Known Exploited Vulnerabilities (KEV) catalog."""

    def __init__(
        self,
        settings: Settings,
        client: Optional[httpx.AsyncClient] = None,
    ):
        rate_limiter = AsyncRateLimiter(rate=0.5, capacity=2.0)
        super().__init__(settings, client=client, rate_limiter=rate_limiter)

    @property
    def source(self) -> SourceType:
        return SourceType.CISA_KEV

    async def fetch_latest(
        self,
        since: Optional[datetime] = None,
        limit: int = 50,
    ) -> List[CVEItem]:
        """Fetch and parse vulnerabilities from CISA KEV catalog."""
        client = await self.get_client()

        async def _do_request() -> httpx.Response:
            await self.rate_limiter.acquire()
            resp = await client.get(CISA_KEV_FEED_URL)
            resp.raise_for_status()
            return resp

        try:
            response = await execute_with_retry(
                _do_request,
                max_retries=self.settings.max_retries,
                backoff_factor=self.settings.backoff_factor,
                operation_name="CISA KEV Catalog",
            )
            data = response.json()
        except Exception as e:
            logger.error(f"Failed to fetch CISA KEV catalog: {e}")
            return []

        raw_vulns = data.get("vulnerabilities", [])
        cves: List[CVEItem] = []

        # Sort reverse chronologically by dateAdded
        sorted_vulns = sorted(
            raw_vulns,
            key=lambda x: x.get("dateAdded", ""),
            reverse=True,
        )

        for v in sorted_vulns[:limit]:
            cve_id = v.get("cveID")
            if not cve_id:
                continue

            date_added_str = v.get("dateAdded")
            pub_date = None
            if date_added_str:
                try:
                    pub_date = datetime.strptime(date_added_str, "%Y-%m-%d").replace(tzinfo=timezone.utc)
                except ValueError:
                    pass

            # Filter by 'since' if requested
            if since and pub_date and pub_date < since:
                continue

            due_date_str = v.get("dueDate")
            due_date = None
            if due_date_str:
                try:
                    due_date = datetime.strptime(due_date_str, "%Y-%m-%d").replace(tzinfo=timezone.utc)
                except ValueError:
                    pass

            vendor = v.get("vendorProject")
            product = v.get("product")
            desc = v.get("shortDescription") or v.get("vulnerabilityName") or "Actively exploited in the wild."
            title = v.get("vulnerabilityName")

            notes = v.get("notes", "")
            refs = []
            if notes and ("http://" in notes or "https://" in notes):
                refs.append(Reference(url=notes.strip(), tags=["CISA KEV Note"]))

            # CISA KEV items are by definition exploited in the wild, default severity to HIGH/CRITICAL
            cvss = CVSSData(
                score=9.0,
                severity=Severity.CRITICAL,
                vector_string="CISA-KEV-ACTIVELY-EXPLOITED",
            )

            cve_item = CVEItem(
                id=cve_id,
                source=SourceType.CISA_KEV,
                title=title,
                description=desc,
                cvss=cvss,
                published_at=pub_date,
                affected_vendors=[vendor] if vendor else [],
                affected_products=[product] if product else [],
                references=refs,
                is_cisa_kev=True,
                cisa_action_due=due_date,
            )
            cves.append(cve_item)

        logger.info(f"CISA KEV fetcher returned {len(cves)} active exploited vulnerabilities.")
        return cves

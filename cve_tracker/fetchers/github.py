"""GitHub Security Advisory Database (GHSA) API Fetcher."""

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

GITHUB_ADVISORY_URL = "https://api.github.com/advisories"


class GitHubAdvisoryFetcher(BaseCVEFetcher):
    """Fetches reviewed security advisories from GitHub."""

    def __init__(
        self,
        settings: Settings,
        client: Optional[httpx.AsyncClient] = None,
    ):
        # GitHub allows 60 req/hr unauthenticated, 5000 req/hr authenticated
        rate = 1.0 if settings.github_token else 0.016
        rate_limiter = AsyncRateLimiter(rate=rate, capacity=3.0)
        super().__init__(settings, client=client, rate_limiter=rate_limiter)

    @property
    def source(self) -> SourceType:
        return SourceType.GITHUB

    async def fetch_latest(
        self,
        since: Optional[datetime] = None,
        limit: int = 30,
    ) -> List[CVEItem]:
        client = await self.get_client()
        headers = {
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
        }
        if self.settings.github_token:
            headers["Authorization"] = f"Bearer {self.settings.github_token}"

        params: Dict[str, Any] = {
            "per_page": min(limit, 100),
            "direction": "desc",
            "sort": "published",
            "type": "reviewed",
        }
        if since:
            params["published"] = f">={since.strftime('%Y-%m-%dT%H:%M:%SZ')}"

        async def _do_request() -> httpx.Response:
            await self.rate_limiter.acquire()
            resp = await client.get(GITHUB_ADVISORY_URL, headers=headers, params=params)
            resp.raise_for_status()
            return resp

        try:
            response = await execute_with_retry(
                _do_request,
                max_retries=self.settings.max_retries,
                backoff_factor=self.settings.backoff_factor,
                operation_name="GitHub Advisory API",
            )
            items = response.json()
        except Exception as e:
            logger.error(f"Failed to fetch from GitHub Advisory API: {e}")
            return []

        cves: List[CVEItem] = []
        for adv in items:
            cve_id = adv.get("cve_id") or adv.get("ghsa_id")
            if not cve_id:
                continue

            summary = adv.get("summary")
            description = adv.get("description") or summary or "No description."

            # Parse CVSS
            cvss_raw = adv.get("cvss", {})
            score = cvss_raw.get("score")
            vector = cvss_raw.get("vector_string")
            severity_str = (adv.get("severity") or "").upper()

            severity = (
                Severity(severity_str)
                if severity_str in Severity._value2member_map_
                else Severity.from_score(score)
            )

            cvss = CVSSData(
                score=score,
                vector_string=vector,
                severity=severity,
            )

            # References
            references = []
            for r in adv.get("references", []):
                url = r.get("url") if isinstance(r, dict) else r
                if url:
                    references.append(Reference(url=url))

            # Affected packages
            products = []
            vendors = []
            for vuln in adv.get("vulnerabilities", []):
                pkg = vuln.get("package", {})
                name = pkg.get("name")
                ecosystem = pkg.get("ecosystem")
                if name:
                    products.append(name)
                if ecosystem:
                    vendors.append(ecosystem)

            pub_date = None
            if adv.get("published_at"):
                try:
                    pub_date = datetime.fromisoformat(adv["published_at"].replace("Z", "+00:00"))
                except ValueError:
                    pass

            cves.append(
                CVEItem(
                    id=cve_id,
                    source=SourceType.GITHUB,
                    title=summary,
                    description=description,
                    cvss=cvss,
                    cwes=adv.get("cwe_ids", []),
                    affected_vendors=list(set(vendors)),
                    affected_products=list(set(products)),
                    references=references,
                    published_at=pub_date,
                )
            )

        logger.info(f"GitHub Advisories returned {len(cves)} vulnerabilities.")
        return cves

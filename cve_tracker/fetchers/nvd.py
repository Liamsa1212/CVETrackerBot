"""NIST National Vulnerability Database (NVD) API 2.0 Fetcher."""

from datetime import datetime, timedelta, timezone
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

NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"


class NVDFetcher(BaseCVEFetcher):
    """Fetcher for the NIST NVD API 2.0 with token bucket rate limiting and backoff."""

    def __init__(
        self,
        settings: Settings,
        client: Optional[httpx.AsyncClient] = None,
    ):
        # NVD rate limits: with API key: 50 req / 30s (~1.6 req/s). Without: 5 req / 30s (~0.16 req/s)
        if settings.nvd_api_key:
            rate_limiter = AsyncRateLimiter(rate=1.5, capacity=5.0)
        else:
            rate_limiter = AsyncRateLimiter(rate=0.16, capacity=1.0)

        super().__init__(settings, client=client, rate_limiter=rate_limiter)

    @property
    def source(self) -> SourceType:
        return SourceType.NVD

    def _parse_cvss(self, metrics: Dict[str, Any]) -> Optional[CVSSData]:
        """Safely parse CVSS 4.0, 3.1, 3.0, or 2.0 metrics."""
        for metric_key in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            metric_list = metrics.get(metric_key, [])
            if not isinstance(metric_list, list) or not metric_list:
                continue

            primary_metric = metric_list[0]
            cvss_data = primary_metric.get("cvssData", {})
            score = cvss_data.get("baseScore")
            if score is None:
                continue

            vector = cvss_data.get("vectorString")
            version = cvss_data.get("version")
            raw_severity = cvss_data.get("baseSeverity") or primary_metric.get("baseSeverity")

            severity = (
                Severity(raw_severity.upper())
                if raw_severity and raw_severity.upper() in Severity._value2member_map_
                else Severity.from_score(float(score))
            )

            return CVSSData(
                version=str(version) if version else metric_key.replace("cvssMetricV", ""),
                score=float(score),
                vector_string=vector,
                severity=severity,
            )
        return None

    def _parse_cpe_vendors_and_products(self, configurations: Dict[str, Any]) -> tuple[List[str], List[str]]:
        """Extract vendors and products from CPE strings in configurations."""
        vendors = set()
        products = set()

        nodes = configurations.get("nodes", []) if isinstance(configurations, dict) else []
        for node in nodes:
            cpe_matches = node.get("cpeMatch", [])
            for match in cpe_matches:
                criteria = match.get("criteria", "")
                # CPE format: cpe:2.3:a:vendor:product:...
                parts = criteria.split(":")
                if len(parts) >= 5:
                    v = parts[3].strip()
                    p = parts[4].strip()
                    if v and v != "*":
                        vendors.add(v)
                    if p and p != "*":
                        products.add(p)

        return list(vendors), list(products)

    def _parse_cve_item(self, vuln_data: Dict[str, Any]) -> Optional[CVEItem]:
        """Parse raw NVD JSON vulnerability structure into CVEItem."""
        cve = vuln_data.get("cve", {})
        cve_id = cve.get("id")
        if not cve_id:
            return None

        # Description
        descriptions = cve.get("descriptions", [])
        desc_text = next(
            (d.get("value") for d in descriptions if d.get("lang") == "en" and d.get("value")),
            None,
        )
        if not desc_text and descriptions:
            desc_text = descriptions[0].get("value")

        if not desc_text:
            desc_text = "No description provided."

        # CVSS
        metrics = cve.get("metrics", {})
        cvss = self._parse_cvss(metrics)

        # References
        references: List[Reference] = []
        for ref in cve.get("references", []):
            url = ref.get("url")
            if url:
                tags = ref.get("tags", [])
                references.append(Reference(url=url, tags=tags))

        # CWEs
        cwes = []
        for weakness in cve.get("weaknesses", []):
            for d in weakness.get("description", []):
                val = d.get("value")
                if val and val.startswith("CWE-"):
                    cwes.append(val)

        # Vendors and Products
        vendors, products = self._parse_cpe_vendors_and_products(cve.get("configurations", {}))

        # Timestamps
        pub_date = None
        upd_date = None
        if cve.get("published"):
            try:
                pub_date = datetime.fromisoformat(cve["published"].replace("Z", "+00:00"))
            except ValueError:
                pass
        if cve.get("lastModified"):
            try:
                upd_date = datetime.fromisoformat(cve["lastModified"].replace("Z", "+00:00"))
            except ValueError:
                pass

        return CVEItem(
            id=cve_id,
            source=SourceType.NVD,
            description=desc_text,
            cvss=cvss,
            published_at=pub_date,
            updated_at=upd_date,
            references=references,
            cwes=cwes,
            affected_vendors=vendors,
            affected_products=products,
        )

    async def fetch_latest(
        self,
        since: Optional[datetime] = None,
        limit: int = 20,
    ) -> List[CVEItem]:
        """Query NVD 2.0 API for recent CVEs."""
        client = await self.get_client()
        headers = {}
        if self.settings.nvd_api_key:
            headers["apiKey"] = self.settings.nvd_api_key

        now = datetime.now(timezone.utc)
        if since is None:
            since = now - timedelta(hours=24)

        # Query by last modified date to capture both new CVEs and updated scores/CPEs
        params: Dict[str, Any] = {
            "resultsPerPage": min(limit, 100),
            "startIndex": 0,
            "lastModStartDate": since.strftime("%Y-%m-%dT%H:%M:%S.000"),
            "lastModEndDate": now.strftime("%Y-%m-%dT%H:%M:%S.000"),
        }

        async def _do_request() -> httpx.Response:
            await self.rate_limiter.acquire()
            resp = await client.get(NVD_API_URL, headers=headers, params=params)
            resp.raise_for_status()
            return resp

        try:
            response = await execute_with_retry(
                _do_request,
                max_retries=self.settings.max_retries,
                backoff_factor=self.settings.backoff_factor,
                operation_name="NVD API",
            )
            data = response.json()
        except Exception as e:
            logger.error(f"Failed to fetch from NVD API: {e}")
            return []

        cves: List[CVEItem] = []
        for vuln in data.get("vulnerabilities", []):
            try:
                item = self._parse_cve_item(vuln)
                if item:
                    cves.append(item)
            except Exception as e:
                logger.warning(f"Error parsing NVD vulnerability item: {e}")

        logger.info(f"NVD API returned {len(cves)} vulnerabilities.")
        return cves

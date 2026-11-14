"""FIRST.org Exploit Prediction Scoring System (EPSS) API Client."""

from typing import Dict, List, Optional, Tuple
import httpx
from loguru import logger

from cve_tracker.core.config import Settings
from cve_tracker.core.rate_limiter import AsyncRateLimiter, execute_with_retry

EPSS_API_URL = "https://api.first.org/data/v1/epss"


class EPSSClient:
    """Asynchronous client for querying FIRST.org EPSS probabilities."""

    def __init__(self, settings: Settings, client: Optional[httpx.AsyncClient] = None):
        self.settings = settings
        self._external_client = client
        self._client: Optional[httpx.AsyncClient] = None
        self.rate_limiter = AsyncRateLimiter(rate=5.0, capacity=10.0)

    async def get_client(self) -> httpx.AsyncClient:
        if self._external_client:
            return self._external_client
        if self._client is None or self._client.is_closed:
            self._client = httpx.AsyncClient(timeout=15.0)
        return self._client

    async def close(self) -> None:
        if self._client and not self._client.is_closed:
            await self._client.aclose()

    async def get_scores(self, cve_ids: List[str]) -> Dict[str, Tuple[float, float]]:
        """
        Query EPSS scores for a batch of CVE IDs.
        Returns a dict mapping: {cve_id: (epss_score, epss_percentile)}.
        """
        if not cve_ids:
            return {}

        client = await self.get_client()
        # Clean CVE IDs (only CVEs are supported by EPSS, not GHSA-only IDs)
        valid_cves = [c.upper() for c in cve_ids if c.upper().startswith("CVE-")]
        if not valid_cves:
            return {}

        results: Dict[str, Tuple[float, float]] = {}
        # Batch into chunks of up to 50 CVEs per request
        chunk_size = 50
        for i in range(0, len(valid_cves), chunk_size):
            chunk = valid_cves[i:i + chunk_size]
            cve_param = ",".join(chunk)

            async def _do_req():
                await self.rate_limiter.acquire()
                resp = await client.get(EPSS_API_URL, params={"cve": cve_param})
                resp.raise_for_status()
                return resp

            try:
                response = await execute_with_retry(
                    _do_req,
                    max_retries=self.settings.max_retries,
                    operation_name="EPSS API",
                )
                data = response.json()
                for item in data.get("data", []):
                    cve_id = item.get("cve")
                    score_str = item.get("epss")
                    pct_str = item.get("percentile")
                    if cve_id and score_str is not None:
                        try:
                            score = float(score_str)
                            pct = float(pct_str) if pct_str else 0.0
                            results[cve_id] = (score, pct)
                        except ValueError:
                            pass
            except Exception as e:
                logger.error(f"Failed to fetch EPSS batch for {len(chunk)} CVEs: {e}")

        return results

    async def get_score(self, cve_id: str) -> Optional[Tuple[float, float]]:
        """Query EPSS score for a single CVE ID."""
        scores = await self.get_scores([cve_id])
        return scores.get(cve_id.upper())

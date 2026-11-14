"""Legacy fetcher interface preserved for backward compatibility."""

import asyncio
from typing import Any, Dict, List, Optional
from cve_tracker.core.config import get_settings
from cve_tracker.fetchers.nvd import NVDFetcher
from cve_tracker.models.cve import CVEItem
from cve_tracker.models.filter import SubscriptionFilter


def get_latest_cves(limit: int = 10, min_score: float = 7.0, user_filter: Optional[Dict[str, Any]] = None) -> List[Dict[str, Any]]:
    """Synchronous bridge calling the async NVDFetcher."""
    settings = get_settings()
    fetcher = NVDFetcher(settings)

    async def _fetch():
        items = await fetcher.fetch_latest(limit=limit)
        await fetcher.close()
        return items

    loop = asyncio.new_event_loop()
    try:
        items = loop.run_until_complete(_fetch())
    finally:
        loop.close()

    filter_model = SubscriptionFilter(
        min_cvss=min_score,
        vendors=user_filter.get("vendor", []) if user_filter else [],
        keywords=user_filter.get("keyword", []) if user_filter else [],
        cwes=user_filter.get("cwe", []) if user_filter else [],
    )

    results = []
    for item in items:
        if filter_model.matches(item):
            results.append({
                "id": item.id,
                "summary": item.description,
                "score": item.cvss.score if item.cvss else None,
                "poc": item.poc_urls[0] if item.poc_urls else None,
            })
    return results

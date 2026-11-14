"""Tests for FIRST.org EPSS client and probability scoring."""

import httpx
import pytest
import respx

from cve_tracker.core.config import Settings
from cve_tracker.fetchers.epss import EPSS_API_URL, EPSSClient
from cve_tracker.models.cve import CVEItem, CVSSData, Severity, SourceType
from cve_tracker.models.filter import SubscriptionFilter


@pytest.mark.asyncio
@respx.mock
async def test_epss_client_get_scores(test_settings: Settings):
    mock_epss_response = {
        "status": "OK",
        "status-code": 200,
        "total": 2,
        "data": [
            {
                "cve": "CVE-2024-3400",
                "epss": "0.94231",
                "percentile": "0.9856"
            },
            {
                "cve": "CVE-2024-21413",
                "epss": "0.75120",
                "percentile": "0.9200"
            }
        ]
    }

    respx.get(EPSS_API_URL).mock(return_value=httpx.Response(200, json=mock_epss_response))

    client = EPSSClient(test_settings)
    scores = await client.get_scores(["CVE-2024-3400", "CVE-2024-21413"])
    await client.close()

    assert "CVE-2024-3400" in scores
    score, pct = scores["CVE-2024-3400"]
    assert pytest.approx(score, 0.001) == 0.94231
    assert pytest.approx(pct, 0.001) == 0.9856


def test_subscription_filter_min_epss():
    cve_high_epss = CVEItem(
        id="CVE-2024-1111",
        source=SourceType.NVD,
        description="High exploit probability vulnerability",
        epss_score=0.45,
    )
    cve_low_epss = CVEItem(
        id="CVE-2024-2222",
        source=SourceType.NVD,
        description="Low exploit probability vulnerability",
        epss_score=0.05,
    )

    filt = SubscriptionFilter(min_epss=0.20)
    assert filt.matches(cve_high_epss) is True
    assert filt.matches(cve_low_epss) is False

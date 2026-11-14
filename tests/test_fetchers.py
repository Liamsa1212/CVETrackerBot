"""Tests for external vulnerability fetchers using respx HTTP mocks."""

import httpx
import pytest
import respx

from cve_tracker.core.config import Settings
from cve_tracker.fetchers.cisa_kev import CISA_KEV_FEED_URL, CISAKEVFetcher
from cve_tracker.fetchers.github import GITHUB_ADVISORY_URL, GitHubAdvisoryFetcher
from cve_tracker.fetchers.nvd import NVD_API_URL, NVDFetcher
from cve_tracker.models.cve import Severity, SourceType


@pytest.mark.asyncio
@respx.mock
async def test_nvd_fetcher_success(test_settings: Settings):
    mock_nvd_response = {
        "resultsPerPage": 1,
        "startIndex": 0,
        "totalResults": 1,
        "vulnerabilities": [
            {
                "cve": {
                    "id": "CVE-2024-3000",
                    "descriptions": [{"lang": "en", "value": "A critical vulnerability in TestLib."}],
                    "metrics": {
                        "cvssMetricV31": [
                            {
                                "cvssData": {
                                    "version": "3.1",
                                    "baseScore": 9.1,
                                    "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                                    "baseSeverity": "CRITICAL",
                                }
                            }
                        ]
                    },
                    "references": [
                        {"url": "https://github.com/test/poc", "tags": ["Exploit"]}
                    ],
                    "weaknesses": [
                        {"description": [{"value": "CWE-78"}]}
                    ],
                }
            }
        ],
    }

    respx.get(NVD_API_URL).mock(return_value=httpx.Response(200, json=mock_nvd_response))

    fetcher = NVDFetcher(test_settings)
    cves = await fetcher.fetch_latest(limit=10)
    await fetcher.close()

    assert len(cves) == 1
    item = cves[0]
    assert item.id == "CVE-2024-3000"
    assert item.source == SourceType.NVD
    assert item.cvss.score == 9.1
    assert item.severity == Severity.CRITICAL
    assert item.cwes == ["CWE-78"]
    assert len(item.poc_urls) == 1


@pytest.mark.asyncio
@respx.mock
async def test_cisa_kev_fetcher_success(test_settings: Settings):
    mock_cisa_response = {
        "title": "CISA KEV",
        "count": 1,
        "vulnerabilities": [
            {
                "cveID": "CVE-2024-3400",
                "vendorProject": "Palo Alto Networks",
                "product": "PAN-OS",
                "vulnerabilityName": "PAN-OS Command Injection",
                "dateAdded": "2024-04-12",
                "shortDescription": "Command injection vulnerability in GlobalProtect feature.",
                "requiredAction": "Apply vendor hotfix.",
                "dueDate": "2024-04-19",
                "notes": "https://nvd.nist.gov/vuln/detail/CVE-2024-3400",
            }
        ],
    }

    respx.get(CISA_KEV_FEED_URL).mock(return_value=httpx.Response(200, json=mock_cisa_response))

    fetcher = CISAKEVFetcher(test_settings)
    cves = await fetcher.fetch_latest(limit=10)
    await fetcher.close()

    assert len(cves) == 1
    item = cves[0]
    assert item.id == "CVE-2024-3400"
    assert item.source == SourceType.CISA_KEV
    assert item.is_cisa_kev is True
    assert item.affected_vendors == ["Palo Alto Networks"]
    assert item.affected_products == ["PAN-OS"]


@pytest.mark.asyncio
@respx.mock
async def test_github_advisory_fetcher_success(test_settings: Settings):
    mock_gh_response = [
        {
            "ghsa_id": "GHSA-1234-5678-90ab",
            "cve_id": "CVE-2024-5000",
            "summary": "High severity Prototype Pollution in Lib",
            "description": "Prototype pollution via object merge.",
            "severity": "high",
            "cvss": {"score": 7.5, "vector_string": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N"},
            "cwe_ids": ["CWE-1321"],
            "vulnerabilities": [
                {"package": {"name": "lodash", "ecosystem": "npm"}}
            ],
            "published_at": "2024-05-01T12:00:00Z",
        }
    ]

    respx.get(GITHUB_ADVISORY_URL).mock(return_value=httpx.Response(200, json=mock_gh_response))

    fetcher = GitHubAdvisoryFetcher(test_settings)
    cves = await fetcher.fetch_latest(limit=10)
    await fetcher.close()

    assert len(cves) == 1
    item = cves[0]
    assert item.id == "CVE-2024-5000"
    assert item.source == SourceType.GITHUB
    assert item.cvss.score == 7.5
    assert item.severity == Severity.HIGH
    assert "lodash" in item.affected_products

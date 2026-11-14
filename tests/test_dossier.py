"""Tests for CVEDossierService lookup and fallback."""

import httpx
import pytest
import respx

from cve_tracker.core.config import Settings
from cve_tracker.fetchers.epss import EPSS_API_URL, EPSSClient
from cve_tracker.fetchers.nvd import NVD_API_URL, NVDFetcher
from cve_tracker.models.cve import CVEItem, CVSSData, Severity, SourceType
from cve_tracker.services.dossier import CVEDossierService
from cve_tracker.storage.repository import CVERepository


@pytest.mark.asyncio
async def test_dossier_from_local_cache(
    test_settings: Settings,
    repository: CVERepository,
    sample_cve: CVEItem,
):
    await repository.upsert_cve(sample_cve)

    service = CVEDossierService(test_settings, repository)
    item = await service.get_cve_dossier(sample_cve.id)

    assert item is not None
    assert item.id == sample_cve.id
    assert item.cvss.score == 9.8


@pytest.mark.asyncio
@respx.mock
async def test_dossier_live_fallback(
    test_settings: Settings,
    repository: CVERepository,
):
    cve_id = "CVE-2024-7777"

    mock_nvd = {
        "vulnerabilities": [
            {
                "cve": {
                    "id": cve_id,
                    "descriptions": [{"lang": "en", "value": "A newly reported live vulnerability."}],
                    "metrics": {
                        "cvssMetricV31": [
                            {
                                "cvssData": {
                                    "version": "3.1",
                                    "baseScore": 8.8,
                                    "vectorString": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H",
                                }
                            }
                        ]
                    },
                }
            }
        ]
    }
    mock_epss = {
        "data": [{"cve": cve_id, "epss": "0.4200", "percentile": "0.8500"}]
    }

    respx.get(NVD_API_URL).mock(return_value=httpx.Response(200, json=mock_nvd))
    respx.get(EPSS_API_URL).mock(return_value=httpx.Response(200, json=mock_epss))

    service = CVEDossierService(test_settings, repository)
    item = await service.get_cve_dossier(cve_id)

    assert item is not None
    assert item.id == cve_id
    assert item.cvss.score == 8.8
    assert item.epss_score == 0.42

    # Verify it is now cached in the database
    cached = await repository.get_cve(cve_id)
    assert cached is not None

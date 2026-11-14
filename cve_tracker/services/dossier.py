"""On-Demand CVE Threat Dossier Service."""

from typing import Optional, Tuple
import httpx
from loguru import logger
from telegram import InlineKeyboardButton, InlineKeyboardMarkup

from cve_tracker.core.config import Settings
from cve_tracker.fetchers.epss import EPSSClient
from cve_tracker.fetchers.nvd import NVD_API_URL, NVDFetcher
from cve_tracker.models.cve import CVEItem
from cve_tracker.notifiers.telegram import TelegramNotifier
from cve_tracker.storage.repository import CVERepository


class CVEDossierService:
    """Provides fast local lookup and live external fallback for CVE threat dossiers."""

    def __init__(
        self,
        settings: Settings,
        repository: CVERepository,
        epss_client: Optional[EPSSClient] = None,
        nvd_fetcher: Optional[NVDFetcher] = None,
    ):
        self.settings = settings
        self.repository = repository
        self.epss_client = epss_client or EPSSClient(settings)
        self.nvd_fetcher = nvd_fetcher or NVDFetcher(settings)

    async def get_cve_dossier(self, cve_id: str) -> Optional[CVEItem]:
        """
        Retrieve a full intelligence dossier on a CVE.
        Checks local cache first; if missing, falls back to live NVD + EPSS queries.
        """
        cve_id_clean = cve_id.strip().upper()
        # 1. Check local database
        item = await self.repository.get_cve(cve_id_clean)
        if item:
            # If item has no EPSS score yet, try enriching in background
            if item.epss_score is None:
                epss_res = await self.epss_client.get_score(cve_id_clean)
                if epss_res:
                    item.epss_score, item.epss_percentile = epss_res
                    await self.repository.upsert_cve(item)
            return item

        # 2. Live fallback to NVD API 2.0
        logger.info(f"CVE {cve_id_clean} not in local cache. Performing live lookup...")
        client = await self.nvd_fetcher.get_client()
        headers = {}
        if self.settings.nvd_api_key:
            headers["apiKey"] = self.settings.nvd_api_key

        try:
            resp = await client.get(
                NVD_API_URL,
                headers=headers,
                params={"cveId": cve_id_clean},
            )
            if resp.status_code == 200:
                data = resp.json()
                vulns = data.get("vulnerabilities", [])
                if vulns:
                    parsed_item = self.nvd_fetcher._parse_cve_item(vulns[0])
                    if parsed_item:
                        # Enrich with EPSS
                        epss_res = await self.epss_client.get_score(cve_id_clean)
                        if epss_res:
                            parsed_item.epss_score, parsed_item.epss_percentile = epss_res

                        # Cache into repository
                        saved_item, _ = await self.repository.upsert_cve(parsed_item)
                        return saved_item
        except Exception as e:
            logger.error(f"Error during live CVE fallback lookup for {cve_id_clean}: {e}")

        return None

    @staticmethod
    def get_dossier_markup(cve_id: str) -> InlineKeyboardMarkup:
        """Create action keyboard for a CVE dossier."""
        return InlineKeyboardMarkup([
            [
                InlineKeyboardButton(
                    "🗺️ ATT&CK Mapping",
                    callback_data=f"mitre_{cve_id}",
                ),
                InlineKeyboardButton(
                    "📥 Export STIX 2.1",
                    callback_data=f"export_stix_{cve_id}",
                ),
            ],
            [
                InlineKeyboardButton(
                    "💡 Threat Explainer",
                    callback_data=f"explain_{cve_id}",
                ),
                InlineKeyboardButton(
                    "🌐 NVD Advisory",
                    url=f"https://nvd.nist.gov/vuln/detail/{cve_id}",
                ),
            ],
        ])

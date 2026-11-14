"""Discord Webhook notification dispatcher."""

from typing import Any, Dict, List, Optional
import httpx
from loguru import logger

from cve_tracker.core.rate_limiter import AsyncRateLimiter, execute_with_retry
from cve_tracker.core.security import mask_sensitive_url, validate_outbound_url
from cve_tracker.models.cve import CVEItem, Severity
from cve_tracker.models.subscriber import ChannelType
from cve_tracker.notifiers.base import BaseNotifier


class DiscordNotifier(BaseNotifier):
    """Sends rich embeds to Discord webhooks."""

    def __init__(self, client: Optional[httpx.AsyncClient] = None):
        self._external_client = client
        self._client: Optional[httpx.AsyncClient] = None
        self.rate_limiter = AsyncRateLimiter(rate=5.0, capacity=10.0)

    @property
    def channel_type(self) -> ChannelType:
        return ChannelType.DISCORD

    async def get_client(self) -> httpx.AsyncClient:
        if self._external_client:
            return self._external_client
        if self._client is None or self._client.is_closed:
            self._client = httpx.AsyncClient(timeout=15.0)
        return self._client

    async def close(self) -> None:
        """Close HTTP client session."""
        if self._client and not self._client.is_closed:
            await self._client.aclose()

    @staticmethod
    def _get_color_for_severity(severity: Severity) -> int:
        colors = {
            Severity.CRITICAL: 0xDC2626,  # Red
            Severity.HIGH: 0xEA580C,      # Orange
            Severity.MEDIUM: 0xCA8A04,    # Yellow
            Severity.LOW: 0x2563EB,       # Blue
            Severity.UNKNOWN: 0x6B7280,   # Gray
        }
        return colors.get(severity, 0x6B7280)

    def format_embed(self, cve: CVEItem) -> Dict[str, Any]:
        """Build Discord webhook payload."""
        score_val = f"{cve.cvss.score:.1f}" if cve.cvss and cve.cvss.score is not None else "N/A"
        desc = cve.description
        if len(desc) > 1000:
            desc = desc[:1000] + "..."

        fields: List[Dict[str, Any]] = [
            {"name": "Severity", "value": cve.severity.value, "inline": True},
            {"name": "CVSS Score", "value": score_val, "inline": True},
        ]

        if cve.is_cisa_kev:
            fields.append({"name": "🔥 CISA KEV", "value": "Actively Exploited in the Wild", "inline": True})

        if cve.affected_vendors or cve.affected_products:
            val = f"Vendors: {', '.join(cve.affected_vendors[:3])} | Products: {', '.join(cve.affected_products[:3])}"
            fields.append({"name": "Affected Target", "value": val[:1024], "inline": False})

        if cve.poc_urls:
            pocs_val = "\n".join(f"• [Link]({u})" for u in cve.poc_urls[:3])
            fields.append({"name": "🧪 PoC Exploit", "value": pocs_val[:1024], "inline": False})

        return {
            "embeds": [
                {
                    "title": f"🚨 {cve.id}" + (f": {cve.title}" if cve.title else ""),
                    "description": desc,
                    "url": f"https://nvd.nist.gov/vuln/detail/{cve.id}",
                    "color": self._get_color_for_severity(cve.severity),
                    "fields": fields,
                    "footer": {"text": f"CVE Tracker • Source: {cve.source.value}"},
                }
            ]
        }

    async def send_alert(self, target_id: str, cve: CVEItem) -> bool:
        """Send message payload to Discord webhook URL."""
        try:
            validated_url = validate_outbound_url(target_id)
        except Exception as err:
            logger.warning(f"Blocked Discord dispatch to {mask_sensitive_url(target_id)}: {err}")
            return False

        client = await self.get_client()
        payload = self.format_embed(cve)

        async def _do_send():
            await self.rate_limiter.acquire()
            resp = await client.post(validated_url, json=payload)
            resp.raise_for_status()
            return resp

        try:
            await execute_with_retry(_do_send, max_retries=3, operation_name="Discord Webhook")
            return True
        except Exception as e:
            logger.error(f"Failed to post to Discord webhook {mask_sensitive_url(target_id)}: {e}")
            return False

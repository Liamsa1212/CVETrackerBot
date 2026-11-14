"""Generic HTTP Webhook notification dispatcher."""

from typing import Optional
import httpx
from loguru import logger

from cve_tracker.core.rate_limiter import AsyncRateLimiter, execute_with_retry
from cve_tracker.models.cve import CVEItem
from cve_tracker.models.subscriber import ChannelType
from cve_tracker.notifiers.base import BaseNotifier


class GenericWebhookNotifier(BaseNotifier):
    """Sends JSON alert payloads to generic HTTP endpoints."""

    def __init__(self, client: Optional[httpx.AsyncClient] = None):
        self._external_client = client
        self._client: Optional[httpx.AsyncClient] = None
        self.rate_limiter = AsyncRateLimiter(rate=10.0, capacity=20.0)

    @property
    def channel_type(self) -> ChannelType:
        return ChannelType.WEBHOOK

    async def get_client(self) -> httpx.AsyncClient:
        if self._external_client:
            return self._external_client
        if self._client is None or self._client.is_closed:
            self._client = httpx.AsyncClient(timeout=15.0)
        return self._client

    async def send_alert(self, target_id: str, cve: CVEItem) -> bool:
        if not target_id.startswith("http"):
            logger.warning(f"Invalid webhook URL: {target_id}")
            return False

        client = await self.get_client()
        payload = {
            "event": "cve_alert",
            "cve": cve.model_dump(mode="json"),
        }

        async def _do_send():
            await self.rate_limiter.acquire()
            resp = await client.post(target_id, json=payload)
            resp.raise_for_status()
            return resp

        try:
            await execute_with_retry(_do_send, max_retries=3, operation_name="Generic Webhook")
            return True
        except Exception as e:
            logger.error(f"Failed to post to generic webhook {target_id}: {e}")
            return False

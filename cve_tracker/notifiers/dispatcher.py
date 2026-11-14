"""Notification dispatcher matching CVEs against subscribers and managing delivery idempotency."""

import asyncio
from typing import Dict, List, Optional
from loguru import logger

from cve_tracker.core.config import Settings
from cve_tracker.core.security import mask_sensitive_url
from cve_tracker.models.cve import CVEItem
from cve_tracker.models.subscriber import ChannelType, SubscriberTarget
from cve_tracker.notifiers.base import BaseNotifier
from cve_tracker.notifiers.discord import DiscordNotifier
from cve_tracker.notifiers.telegram import TelegramNotifier
from cve_tracker.notifiers.webhook import GenericWebhookNotifier
from cve_tracker.storage.repository import CVERepository


class NotificationDispatcher:
    """Orchestrates matching, filtering, and idempotent alert delivery across channels."""

    def __init__(
        self,
        settings: Settings,
        repository: CVERepository,
        notifiers: Optional[Dict[ChannelType, BaseNotifier]] = None,
    ):
        self.settings = settings
        self.repository = repository
        self.notifiers = notifiers or {}
        self._concurrency_limit = asyncio.Semaphore(15)

    def register_notifier(self, notifier: BaseNotifier) -> None:
        """Register a channel notifier."""
        self.notifiers[notifier.channel_type] = notifier

    async def close(self) -> None:
        """Close network sessions for all registered notifiers."""
        for notifier in self.notifiers.values():
            try:
                await notifier.close()
            except Exception as e:
                logger.warning(f"Error closing notifier {notifier.channel_type}: {e}")

    async def _send_to_subscriber(
        self,
        subscriber: SubscriberTarget,
        cve: CVEItem,
    ) -> bool:
        """Send an individual alert to a single subscriber target if not already delivered."""
        if not subscriber.id:
            return False

        # Fast in-memory filter criteria check before gating
        if not subscriber.filters.matches(cve):
            return False

        async with self._concurrency_limit:
            # Verify idempotency inside semaphore to bound database connection load
            already_sent = await self.repository.is_alert_delivered(
                cve_id=cve.id,
                subscriber_id=subscriber.id,
                content_hash=cve.content_hash,
            )
            if already_sent:
                return False

            notifier = self.notifiers.get(subscriber.channel_type)
            if not notifier:
                logger.warning(f"No notifier registered for channel {subscriber.channel_type}")
                return False

            success = await notifier.send_alert(subscriber.target_id, cve)

            if success:
                await self.repository.record_alert_delivery(
                    cve_id=cve.id,
                    subscriber_id=subscriber.id,
                    content_hash=cve.content_hash,
                )
                logger.info(
                    f"Delivered alert for {cve.id} to {subscriber.channel_type.value} [{mask_sensitive_url(subscriber.target_id)}]."
                )
                return True
            else:
                logger.warning(
                    f"Failed to deliver {cve.id} to {subscriber.channel_type.value} [{mask_sensitive_url(subscriber.target_id)}]."
                )
                return False

    async def dispatch_cves(self, cves: List[CVEItem]) -> int:
        """
        Evaluate and dispatch alerts for the given CVE items across all active subscribers.
        Returns total count of successfully delivered notifications.
        """
        if not cves:
            return 0

        subscribers = await self.repository.get_active_subscribers()
        if not subscribers:
            logger.info("No active subscribers found for dispatching alerts.")
            return 0

        logger.info(f"Dispatching {len(cves)} CVEs across {len(subscribers)} subscribers...")

        tasks = []
        for sub in subscribers:
            for cve in cves:
                tasks.append(self._send_to_subscriber(sub, cve))

        results = await asyncio.gather(*tasks, return_exceptions=True)
        delivered_count = sum(1 for r in results if r is True)

        logger.info(f"Alert dispatch completed. {delivered_count} notifications successfully sent.")
        return delivered_count

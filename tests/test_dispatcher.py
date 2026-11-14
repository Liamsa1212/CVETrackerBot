"""Tests for Notification Dispatcher and multi-channel alerting."""

import pytest

from cve_tracker.core.config import Settings
from cve_tracker.models.cve import CVEItem, CVSSData, Severity, SourceType
from cve_tracker.models.filter import SubscriptionFilter
from cve_tracker.models.subscriber import ChannelType
from cve_tracker.notifiers.base import BaseNotifier
from cve_tracker.notifiers.dispatcher import NotificationDispatcher
from cve_tracker.storage.repository import CVERepository


class DummyNotifier(BaseNotifier):
    """Test double for verifying alert deliveries."""

    def __init__(self, channel: ChannelType):
        self._channel = channel
        self.sent_alerts = []

    @property
    def channel_type(self) -> ChannelType:
        return self._channel

    async def send_alert(self, target_id: str, cve: CVEItem) -> bool:
        self.sent_alerts.append((target_id, cve.id))
        return True


@pytest.mark.asyncio
async def test_dispatcher_filters_and_delivers(
    test_settings: Settings,
    repository: CVERepository,
    sample_cve: CVEItem,
):
    # Setup test double notifiers
    tg_notifier = DummyNotifier(ChannelType.TELEGRAM)
    dispatcher = NotificationDispatcher(test_settings, repository)
    dispatcher.register_notifier(tg_notifier)

    # Subscriber 1: Interested in critical CVSS >= 9.0
    sub1, _ = await repository.add_or_activate_subscriber(
        target_id="1001",
        channel_type=ChannelType.TELEGRAM,
        filters=SubscriptionFilter(min_cvss=9.0),
    )

    # Subscriber 2: Interested in medium only (min_cvss 4.0, max not exceeding 7.0 by setting severities)
    sub2, _ = await repository.add_or_activate_subscriber(
        target_id="1002",
        channel_type=ChannelType.TELEGRAM,
        filters=SubscriptionFilter(severities=[Severity.MEDIUM]),
    )

    # Dispatch sample_cve (CVSS 9.8, Severity CRITICAL)
    delivered_count = await dispatcher.dispatch_cves([sample_cve])

    assert delivered_count == 1
    assert ("1001", sample_cve.id) in tg_notifier.sent_alerts
    assert ("1002", sample_cve.id) not in tg_notifier.sent_alerts

    # Idempotency check: Dispatching same CVE again should send 0 new alerts
    delivered_count_again = await dispatcher.dispatch_cves([sample_cve])
    assert delivered_count_again == 0
    assert len(tg_notifier.sent_alerts) == 1

"""Tests for Database Repository and Persistence."""

import json
from pathlib import Path
import pytest

from cve_tracker.models.cve import CVEItem, CVSSData, Severity
from cve_tracker.models.filter import SubscriptionFilter
from cve_tracker.models.subscriber import ChannelType
from cve_tracker.storage.repository import CVERepository


@pytest.mark.asyncio
async def test_upsert_cve_and_deduplication(repository: CVERepository, sample_cve: CVEItem):
    # First insert
    saved, is_new = await repository.upsert_cve(sample_cve)
    assert is_new is True
    assert saved.id == sample_cve.id
    assert saved.cvss.score == 9.8

    # Second insert with identical content hash -> should detect duplicate
    saved_dup, is_new_dup = await repository.upsert_cve(sample_cve)
    assert is_new_dup is False
    assert saved_dup.id == sample_cve.id


@pytest.mark.asyncio
async def test_upsert_cve_content_update(repository: CVERepository, sample_cve: CVEItem):
    await repository.upsert_cve(sample_cve)

    # Modify CVSS score
    updated_cve = sample_cve.model_copy(deep=True)
    updated_cve.cvss = CVSSData(score=10.0, severity=Severity.CRITICAL)

    saved_updated, is_new = await repository.upsert_cve(updated_cve)
    assert is_new is True
    assert saved_updated.cvss.score == 10.0


@pytest.mark.asyncio
async def test_subscriber_lifecycle(repository: CVERepository):
    chat_id = "987654321"

    # Subscribe
    sub, was_new = await repository.add_or_activate_subscriber(
        target_id=chat_id,
        channel_type=ChannelType.TELEGRAM,
        filters=SubscriptionFilter(min_cvss=8.0),
    )
    assert was_new is True
    assert sub.target_id == chat_id
    assert sub.is_active is True
    assert sub.filters.min_cvss == 8.0

    # Retrieve
    active_subs = await repository.get_active_subscribers()
    assert len(active_subs) == 1
    assert active_subs[0].target_id == chat_id

    # Unsubscribe
    unsub_success = await repository.deactivate_subscriber(chat_id, ChannelType.TELEGRAM)
    assert unsub_success is True

    # Check active subscribers again
    active_subs_after = await repository.get_active_subscribers()
    assert len(active_subs_after) == 0


@pytest.mark.asyncio
async def test_alert_delivery_idempotency(repository: CVERepository, sample_cve: CVEItem):
    # Save CVE
    await repository.upsert_cve(sample_cve)

    # Save Subscriber
    sub, _ = await repository.add_or_activate_subscriber(
        target_id="11223344",
        channel_type=ChannelType.TELEGRAM,
    )

    # Initially not delivered
    delivered = await repository.is_alert_delivered(
        cve_id=sample_cve.id,
        subscriber_id=sub.id,
        content_hash=sample_cve.content_hash,
    )
    assert delivered is False

    # Record delivery
    await repository.record_alert_delivery(
        cve_id=sample_cve.id,
        subscriber_id=sub.id,
        content_hash=sample_cve.content_hash,
    )

    # Check now delivered
    delivered_now = await repository.is_alert_delivered(
        cve_id=sample_cve.id,
        subscriber_id=sub.id,
        content_hash=sample_cve.content_hash,
    )
    assert delivered_now is True


@pytest.mark.asyncio
async def test_legacy_json_migration(repository: CVERepository, tmp_path: Path):
    subs_file = tmp_path / "subscribers.json"
    filters_file = tmp_path / "filters.json"

    subs_file.write_text(json.dumps([123456, 789012]), encoding="utf-8")
    filters_file.write_text(
        json.dumps({
            "123456": {"vendor": ["microsoft", "cisco"], "keyword": ["rce"]},
        }),
        encoding="utf-8",
    )

    await repository.migrate_legacy_json_data(
        subscribers_path=subs_file,
        filters_path=filters_file,
    )

    subs = await repository.get_active_subscribers()
    assert len(subs) == 2

    sub123456 = next(s for s in subs if s.target_id == "123456")
    assert "microsoft" in sub123456.filters.vendors
    assert "rce" in sub123456.filters.keywords

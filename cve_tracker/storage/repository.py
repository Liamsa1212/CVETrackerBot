"""Database repository layer handling persistence, queries, and legacy migrations."""

from datetime import datetime, timezone
import json
from pathlib import Path
from typing import List, Optional, Tuple
from loguru import logger
from sqlalchemy import delete, desc, select, update
from sqlalchemy.dialects.sqlite import insert as sqlite_insert
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from cve_tracker.core.exceptions import StorageError
from cve_tracker.models.cve import CVEItem, CVSSData, Reference, Severity, SourceType
from cve_tracker.models.filter import SubscriptionFilter
from cve_tracker.models.subscriber import ChannelType, SubscriberTarget
from cve_tracker.storage.models import AlertDeliveryRecord, CVERecord, SubscriberRecord


class CVERepository:
    """Repository handling all database operations."""

    def __init__(self, session_factory: async_sessionmaker[AsyncSession]):
        self.session_factory = session_factory

    @staticmethod
    def _record_to_cve_item(record: CVERecord) -> CVEItem:
        """Convert ORM record to Pydantic domain model."""
        cvss = None
        if record.cvss_score is not None or record.severity:
            cvss = CVSSData(
                version=record.cvss_version,
                score=record.cvss_score,
                vector_string=record.cvss_vector,
                severity=Severity(record.severity) if record.severity in Severity._value2member_map_ else Severity.UNKNOWN,
            )

        refs_raw = json.loads(record.references_json or "[]")
        references = [
            Reference(url=r.get("url", ""), tags=r.get("tags", []))
            for r in refs_raw
            if isinstance(r, dict) and "url" in r
        ]

        return CVEItem(
            id=record.id,
            source=SourceType(record.source),
            title=record.title,
            description=record.description,
            cvss=cvss,
            cwes=json.loads(record.cwes_json or "[]"),
            affected_vendors=json.loads(record.vendors_json or "[]"),
            affected_products=json.loads(record.products_json or "[]"),
            references=references,
            is_cisa_kev=record.is_cisa_kev,
            cisa_action_due=record.cisa_action_due,
            epss_score=record.epss_score,
            epss_percentile=record.epss_percentile,
            published_at=record.first_seen_at,
            updated_at=record.last_updated_at,
        )

    @staticmethod
    def _record_to_subscriber_target(record: SubscriberRecord) -> SubscriberTarget:
        """Convert ORM record to Subscriber domain model."""
        raw_filter = json.loads(record.filter_data_json or "{}")
        return SubscriberTarget(
            id=record.id,
            target_id=record.target_id,
            channel_type=ChannelType(record.channel_type),
            is_active=record.is_active,
            filters=SubscriptionFilter(**raw_filter),
            created_at=record.created_at,
            last_notified_at=record.last_notified_at,
        )

    async def upsert_cve(self, item: CVEItem) -> Tuple[CVEItem, bool]:
        """
        Insert or update a CVE.
        Returns the saved CVEItem and a boolean indicating if it is new/updated.
        """
        async with self.session_factory() as session:
            try:
                stmt = select(CVERecord).where(CVERecord.id == item.id)
                res = await session.execute(stmt)
                existing = res.scalar_one_or_none()

                refs_json = json.dumps([r.model_dump() for r in item.references])
                now = datetime.now(timezone.utc)

                if existing:
                    # Check if content has meaningfully changed
                    if existing.content_hash == item.content_hash:
                        return self._record_to_cve_item(existing), False

                    existing.source = item.source.value
                    existing.title = item.title
                    existing.description = item.description
                    existing.cvss_score = item.cvss.score if item.cvss else None
                    existing.cvss_version = item.cvss.version if item.cvss else None
                    existing.cvss_vector = item.cvss.vector_string if item.cvss else None
                    existing.severity = item.severity.value
                    existing.cwes_json = json.dumps(item.cwes)
                    existing.vendors_json = json.dumps(item.affected_vendors)
                    existing.products_json = json.dumps(item.affected_products)
                    existing.references_json = refs_json
                    existing.is_cisa_kev = item.is_cisa_kev
                    existing.cisa_action_due = item.cisa_action_due
                    existing.epss_score = item.epss_score
                    existing.epss_percentile = item.epss_percentile
                    existing.content_hash = item.content_hash
                    existing.last_updated_at = now
                    await session.commit()
                    await session.refresh(existing)
                    return self._record_to_cve_item(existing), True

                new_record = CVERecord(
                    id=item.id,
                    source=item.source.value,
                    title=item.title,
                    description=item.description,
                    cvss_score=item.cvss.score if item.cvss else None,
                    cvss_version=item.cvss.version if item.cvss else None,
                    cvss_vector=item.cvss.vector_string if item.cvss else None,
                    severity=item.severity.value,
                    cwes_json=json.dumps(item.cwes),
                    vendors_json=json.dumps(item.affected_vendors),
                    products_json=json.dumps(item.affected_products),
                    references_json=refs_json,
                    is_cisa_kev=item.is_cisa_kev,
                    cisa_action_due=item.cisa_action_due,
                    epss_score=item.epss_score,
                    epss_percentile=item.epss_percentile,
                    content_hash=item.content_hash,
                    first_seen_at=item.published_at or now,
                    last_updated_at=item.updated_at or now,
                )
                session.add(new_record)
                await session.commit()
                await session.refresh(new_record)
                return self._record_to_cve_item(new_record), True

            except Exception as e:
                await session.rollback()
                raise StorageError(f"Failed to upsert CVE {item.id}: {e}") from e

    async def get_cve(self, cve_id: str) -> Optional[CVEItem]:
        """Fetch a single CVE by ID."""
        async with self.session_factory() as session:
            stmt = select(CVERecord).where(CVERecord.id == cve_id)
            res = await session.execute(stmt)
            record = res.scalar_one_or_none()
            return self._record_to_cve_item(record) if record else None

    async def get_latest_cves(
        self,
        limit: int = 10,
        min_score: Optional[float] = None,
        cisa_only: bool = False,
    ) -> List[CVEItem]:
        """Fetch the most recent CVEs with optional severity filters."""
        async with self.session_factory() as session:
            query = select(CVERecord)
            if min_score is not None:
                query = query.where(CVERecord.cvss_score >= min_score)
            if cisa_only:
                query = query.where(CVERecord.is_cisa_kev.is_(True))

            query = query.order_by(desc(CVERecord.last_updated_at)).limit(limit)
            res = await session.execute(query)
            records = res.scalars().all()
            return [self._record_to_cve_item(r) for r in records]

    async def get_cves_by_product(self, product_name: str, limit: int = 5) -> List[CVEItem]:
        """Find CVEs affecting a given product or component name."""
        clean_name = product_name.strip().lower()
        if not clean_name:
            return []
        async with self.session_factory() as session:
            pattern = f"%{clean_name}%"
            stmt = (
                select(CVERecord)
                .where(
                    (CVERecord.products_json.like(pattern))
                    | (CVERecord.description.like(pattern))
                )
                .order_by(desc(CVERecord.cvss_score))
                .limit(limit)
            )
            res = await session.execute(stmt)
            records = res.scalars().all()
            return [self._record_to_cve_item(r) for r in records]

    async def get_subscriber(
        self, target_id: str, channel_type: ChannelType
    ) -> Optional[SubscriberTarget]:
        """Find a subscriber by target ID and channel."""
        async with self.session_factory() as session:
            stmt = select(SubscriberRecord).where(
                SubscriberRecord.target_id == str(target_id),
                SubscriberRecord.channel_type == channel_type.value,
            )
            res = await session.execute(stmt)
            rec = res.scalar_one_or_none()
            return self._record_to_subscriber_target(rec) if rec else None

    async def get_active_subscribers(
        self, channel_type: Optional[ChannelType] = None
    ) -> List[SubscriberTarget]:
        """List all active subscribers."""
        async with self.session_factory() as session:
            query = select(SubscriberRecord).where(SubscriberRecord.is_active.is_(True))
            if channel_type:
                query = query.where(SubscriberRecord.channel_type == channel_type.value)
            res = await session.execute(query)
            return [self._record_to_subscriber_target(r) for r in res.scalars().all()]

    async def add_or_activate_subscriber(
        self,
        target_id: str,
        channel_type: ChannelType,
        filters: Optional[SubscriptionFilter] = None,
    ) -> Tuple[SubscriberTarget, bool]:
        """
        Add a new subscriber or reactivate an inactive one.
        Returns (subscriber, was_created_or_reactivated).
        """
        target_id = str(target_id)
        filter_dict = (filters or SubscriptionFilter()).model_dump()
        filter_json = json.dumps(filter_dict)

        async with self.session_factory() as session:
            try:
                stmt = select(SubscriberRecord).where(
                    SubscriberRecord.target_id == target_id,
                    SubscriberRecord.channel_type == channel_type.value,
                )
                res = await session.execute(stmt)
                sub = res.scalar_one_or_none()

                if sub:
                    if not sub.is_active:
                        sub.is_active = True
                        if filters:
                            sub.filter_data_json = filter_json
                        await session.commit()
                        await session.refresh(sub)
                        return self._record_to_subscriber_target(sub), True
                    return self._record_to_subscriber_target(sub), False

                new_sub = SubscriberRecord(
                    target_id=target_id,
                    channel_type=channel_type.value,
                    is_active=True,
                    filter_data_json=filter_json,
                )
                session.add(new_sub)
                await session.commit()
                await session.refresh(new_sub)
                return self._record_to_subscriber_target(new_sub), True

            except Exception as e:
                await session.rollback()
                raise StorageError(f"Failed to subscribe target {target_id}: {e}") from e

    async def deactivate_subscriber(self, target_id: str, channel_type: ChannelType) -> bool:
        """Deactivate a subscriber."""
        async with self.session_factory() as session:
            stmt = select(SubscriberRecord).where(
                SubscriberRecord.target_id == str(target_id),
                SubscriberRecord.channel_type == channel_type.value,
            )
            res = await session.execute(stmt)
            sub = res.scalar_one_or_none()
            if sub and sub.is_active:
                sub.is_active = False
                await session.commit()
                return True
            return False

    async def update_subscriber_filters(
        self,
        target_id: str,
        channel_type: ChannelType,
        filters: SubscriptionFilter,
    ) -> SubscriberTarget:
        """Update filter rules for an existing subscriber."""
        async with self.session_factory() as session:
            stmt = select(SubscriberRecord).where(
                SubscriberRecord.target_id == str(target_id),
                SubscriberRecord.channel_type == channel_type.value,
            )
            res = await session.execute(stmt)
            sub = res.scalar_one_or_none()
            if not sub:
                # Create subscriber with given filters
                sub = SubscriberRecord(
                    target_id=str(target_id),
                    channel_type=channel_type.value,
                    is_active=True,
                    filter_data_json=json.dumps(filters.model_dump()),
                )
                session.add(sub)
            else:
                sub.filter_data_json = json.dumps(filters.model_dump())
            await session.commit()
            await session.refresh(sub)
            return self._record_to_subscriber_target(sub)

    async def is_alert_delivered(
        self, cve_id: str, subscriber_id: int, content_hash: str
    ) -> bool:
        """Check if an alert has already been sent to this subscriber for this content hash."""
        async with self.session_factory() as session:
            stmt = select(AlertDeliveryRecord.id).where(
                AlertDeliveryRecord.cve_id == cve_id,
                AlertDeliveryRecord.subscriber_id == subscriber_id,
                AlertDeliveryRecord.content_hash == content_hash,
            )
            res = await session.execute(stmt)
            return res.scalar_one_or_none() is not None

    async def record_alert_delivery(
        self, cve_id: str, subscriber_id: int, content_hash: str
    ) -> None:
        """Record an alert delivery to prevent duplicate notifications."""
        async with self.session_factory() as session:
            try:
                delivery = AlertDeliveryRecord(
                    cve_id=cve_id,
                    subscriber_id=subscriber_id,
                    content_hash=content_hash,
                )
                session.add(delivery)

                # Update subscriber's last_notified_at
                stmt = update(SubscriberRecord).where(
                    SubscriberRecord.id == subscriber_id
                ).values(last_notified_at=datetime.now(timezone.utc))
                await session.execute(stmt)

                await session.commit()
            except Exception as e:
                await session.rollback()
                # If unique constraint violated, it's already recorded
                logger.debug(f"Alert delivery already recorded or failed: {e}")

    async def migrate_legacy_json_data(
        self,
        subscribers_path: Path = Path("subscribers.json"),
        filters_path: Path = Path("filters.json"),
    ) -> None:
        """Migrate legacy subscribers.json and filters.json data into the database."""
        if not subscribers_path.exists() and not filters_path.exists():
            return

        logger.info("Checking for legacy JSON data to migrate...")
        legacy_subs = []
        legacy_filters = {}

        if subscribers_path.exists():
            try:
                with open(subscribers_path, "r", encoding="utf-8") as f:
                    data = json.load(f)
                    if isinstance(data, list):
                        legacy_subs = data
            except Exception as e:
                logger.warning(f"Could not read {subscribers_path}: {e}")

        if filters_path.exists():
            try:
                with open(filters_path, "r", encoding="utf-8") as f:
                    data = json.load(f)
                    if isinstance(data, dict):
                        legacy_filters = data
            except Exception as e:
                logger.warning(f"Could not read {filters_path}: {e}")

        migrated_count = 0
        for chat_id in legacy_subs:
            str_id = str(chat_id)
            user_filter_raw = legacy_filters.get(str_id, {})
            # Map legacy filter fields (vendor, keyword, cwe)
            filt = SubscriptionFilter(
                vendors=user_filter_raw.get("vendor", []),
                keywords=user_filter_raw.get("keyword", []),
                cwes=user_filter_raw.get("cwe", []),
            )
            sub, was_new = await self.add_or_activate_subscriber(
                target_id=str_id,
                channel_type=ChannelType.TELEGRAM,
                filters=filt,
            )
            if was_new:
                migrated_count += 1

        if migrated_count > 0:
            logger.info(f"Successfully migrated {migrated_count} legacy subscribers into SQLite.")

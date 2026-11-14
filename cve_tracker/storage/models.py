"""SQLAlchemy ORM models for database persistence."""

from datetime import datetime, timezone
import json
from typing import Any, Dict, List, Optional
from sqlalchemy import (
    Boolean,
    Column,
    DateTime,
    Float,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.orm import DeclarativeBase, relationship


class Base(DeclarativeBase):
    pass


class CVERecord(Base):
    """Stores fetched vulnerabilities and their computed metrics."""

    __tablename__ = "cves"

    id = Column(String(64), primary_key=True)
    source = Column(String(32), nullable=False, index=True)
    title = Column(String(512), nullable=True)
    description = Column(Text, nullable=False)
    cvss_score = Column(Float, nullable=True, index=True)
    cvss_version = Column(String(16), nullable=True)
    cvss_vector = Column(String(128), nullable=True)
    severity = Column(String(16), nullable=False, index=True)
    cwes_json = Column(Text, nullable=False, default="[]")
    vendors_json = Column(Text, nullable=False, default="[]")
    products_json = Column(Text, nullable=False, default="[]")
    references_json = Column(Text, nullable=False, default="[]")
    is_cisa_kev = Column(Boolean, nullable=False, default=False, index=True)
    cisa_action_due = Column(DateTime, nullable=True)
    epss_score = Column(Float, nullable=True, index=True)
    epss_percentile = Column(Float, nullable=True)
    content_hash = Column(String(64), nullable=False, index=True)
    first_seen_at = Column(DateTime, nullable=False, default=lambda: datetime.now(timezone.utc))
    last_updated_at = Column(DateTime, nullable=False, default=lambda: datetime.now(timezone.utc))

    deliveries = relationship("AlertDeliveryRecord", back_populates="cve", cascade="all, delete-orphan")


class SubscriberRecord(Base):
    """Stores subscribers across platforms and their associated filter preferences."""

    __tablename__ = "subscribers"

    id = Column(Integer, primary_key=True, autoincrement=True)
    target_id = Column(String(256), nullable=False, index=True)
    channel_type = Column(String(32), nullable=False, index=True)
    is_active = Column(Boolean, nullable=False, default=True, index=True)
    filter_data_json = Column(Text, nullable=False, default="{}")
    created_at = Column(DateTime, nullable=False, default=lambda: datetime.now(timezone.utc))
    last_notified_at = Column(DateTime, nullable=True)

    deliveries = relationship("AlertDeliveryRecord", back_populates="subscriber", cascade="all, delete-orphan")

    __table_args__ = (
        UniqueConstraint("target_id", "channel_type", name="uq_target_channel"),
    )


class AlertDeliveryRecord(Base):
    """Audit log tracking delivered alerts to ensure strict idempotency."""

    __tablename__ = "alert_deliveries"

    id = Column(Integer, primary_key=True, autoincrement=True)
    cve_id = Column(String(64), ForeignKey("cves.id", ondelete="CASCADE"), nullable=False, index=True)
    subscriber_id = Column(Integer, ForeignKey("subscribers.id", ondelete="CASCADE"), nullable=False, index=True)
    content_hash = Column(String(64), nullable=False)
    delivered_at = Column(DateTime, nullable=False, default=lambda: datetime.now(timezone.utc))

    cve = relationship("CVERecord", back_populates="deliveries")
    subscriber = relationship("SubscriberRecord", back_populates="deliveries")

    __table_args__ = (
        UniqueConstraint("cve_id", "subscriber_id", "content_hash", name="uq_delivery_idempotency"),
    )

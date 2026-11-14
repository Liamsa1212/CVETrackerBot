"""Subscriber domain models for multi-platform delivery targets."""

from datetime import datetime, timezone
from enum import Enum
from typing import Optional
from pydantic import BaseModel, ConfigDict, Field
from cve_tracker.models.filter import SubscriptionFilter


class ChannelType(str, Enum):
    TELEGRAM = "TELEGRAM"
    DISCORD = "DISCORD"
    WEBHOOK = "WEBHOOK"


class SubscriberTarget(BaseModel):
    """Represents an active notification target with its specific filter rules."""

    model_config = ConfigDict(from_attributes=True)

    id: Optional[int] = None
    target_id: str = Field(..., description="Telegram chat ID, Discord webhook URL, or HTTP endpoint")
    channel_type: ChannelType
    is_active: bool = True
    filters: SubscriptionFilter = Field(default_factory=SubscriptionFilter)
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    last_notified_at: Optional[datetime] = None

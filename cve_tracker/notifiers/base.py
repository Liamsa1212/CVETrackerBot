"""Base notifier interface for dispatching alerts."""

from abc import ABC, abstractmethod
from cve_tracker.models.cve import CVEItem
from cve_tracker.models.subscriber import ChannelType


class BaseNotifier(ABC):
    """Abstract interface for all alerting destinations."""

    @property
    @abstractmethod
    def channel_type(self) -> ChannelType:
        """The channel type handled by this notifier."""

    @abstractmethod
    async def send_alert(self, target_id: str, cve: CVEItem) -> bool:
        """
        Send a vulnerability alert to the specified target.
        Returns True if delivered successfully, False otherwise.
        """

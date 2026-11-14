"""Custom domain-specific exceptions."""


class CVETrackerError(Exception):
    """Base exception for all CVE Tracker errors."""


class ConfigurationError(CVETrackerError):
    """Raised when configuration validation or environment loading fails."""


class ValidationError(CVETrackerError):
    """Raised when user input, URL, or data validation fails."""


class FetcherError(CVETrackerError):
    """Raised when an external CVE source request fails permanently."""


class RateLimitExceededError(FetcherError):
    """Raised when an API rate limit cannot be resolved within retry bounds."""


class ParseError(CVETrackerError):
    """Raised when an external vulnerability payload cannot be parsed."""


class StorageError(CVETrackerError):
    """Raised when a database or repository operation fails."""


class NotificationError(CVETrackerError):
    """Raised when delivering an alert to a subscriber/channel fails."""

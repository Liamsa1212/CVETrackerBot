"""Asynchronous Token Bucket Rate Limiter and Retry Handler with exponential backoff and jitter."""

import asyncio
import random
import time
from typing import Any, Awaitable, Callable, TypeVar
import httpx
from loguru import logger
from cve_tracker.core.exceptions import RateLimitExceededError

T = TypeVar("T")


class AsyncRateLimiter:
    """Token bucket rate limiter for asynchronous tasks."""

    def __init__(self, rate: float, capacity: float):
        """
        Initialize rate limiter.

        :param rate: Number of tokens added per second.
        :param capacity: Maximum burst capacity of the bucket.
        """
        self.rate = rate
        self.capacity = capacity
        self.tokens = capacity
        self.updated_at = time.monotonic()
        self._lock = asyncio.Lock()

    async def acquire(self, tokens: float = 1.0) -> None:
        """Wait until sufficient tokens are available and consume them."""
        if tokens > self.capacity:
            raise ValueError(f"Requested tokens ({tokens}) cannot exceed bucket capacity ({self.capacity}).")

        wait_time = 0.0
        async with self._lock:
            now = time.monotonic()
            elapsed = now - self.updated_at
            self.tokens = min(self.capacity, self.tokens + elapsed * self.rate)
            self.updated_at = now

            if self.tokens < tokens:
                deficit = tokens - self.tokens
                wait_time = deficit / self.rate
                # Reserve tokens into negative balance so waiters queue behind
                self.tokens -= tokens
            else:
                self.tokens -= tokens

        if wait_time > 0:
            await asyncio.sleep(wait_time)


async def execute_with_retry(
    operation: Callable[[], Awaitable[T]],
    max_retries: int = 4,
    backoff_factor: float = 1.5,
    operation_name: str = "request",
) -> T:
    """
    Execute an async HTTP operation with exponential backoff and jitter.
    Handles HTTP 429, 500, 502, 503, 504 and network disconnects.
    """
    attempt = 0
    while True:
        try:
            return await operation()
        except httpx.HTTPStatusError as exc:
            status = exc.response.status_code
            attempt += 1

            # Do not retry 4xx errors other than 429 (Too Many Requests)
            if status != 429 and status < 500:
                raise

            if attempt > max_retries:
                logger.error(
                    f"Max retries ({max_retries}) exceeded for {operation_name} (HTTP {status})"
                )
                if status == 429:
                    raise RateLimitExceededError(
                        f"Rate limit exceeded for {operation_name} after {max_retries} retries"
                    ) from exc
                raise

            # Check if server provided a Retry-After header
            retry_after = exc.response.headers.get("Retry-After")
            if retry_after and retry_after.isdigit():
                delay = float(retry_after) + random.uniform(0.1, 1.0)
            else:
                delay = (backoff_factor ** attempt) + random.uniform(0.5, 1.5)

            logger.warning(
                f"HTTP {status} during {operation_name}. Retrying in {delay:.2f}s "
                f"(attempt {attempt}/{max_retries})..."
            )
            await asyncio.sleep(delay)

        except (httpx.ConnectError, httpx.ReadTimeout, httpx.WriteTimeout, httpx.PoolTimeout) as exc:
            attempt += 1
            if attempt > max_retries:
                logger.error(
                    f"Max retries ({max_retries}) exceeded for {operation_name} due to network timeout: {exc}"
                )
                raise

            delay = (backoff_factor ** attempt) + random.uniform(0.5, 1.5)
            logger.warning(
                f"Network issue ({exc.__class__.__name__}) during {operation_name}. "
                f"Retrying in {delay:.2f}s (attempt {attempt}/{max_retries})..."
            )
            await asyncio.sleep(delay)

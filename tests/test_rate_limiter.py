"""Tests for Rate Limiter and Retry Handler."""

import asyncio
import time
import httpx
import pytest

from cve_tracker.core.exceptions import RateLimitExceededError
from cve_tracker.core.rate_limiter import AsyncRateLimiter, execute_with_retry


@pytest.mark.asyncio
async def test_async_rate_limiter_acquire():
    limiter = AsyncRateLimiter(rate=10.0, capacity=2.0)

    start = time.monotonic()
    # Acquire burst capacity
    await limiter.acquire(1.0)
    await limiter.acquire(1.0)

    # Next acquire must wait for refill (~0.1s)
    await limiter.acquire(1.0)
    elapsed = time.monotonic() - start

    assert elapsed >= 0.08


@pytest.mark.asyncio
async def test_execute_with_retry_success():
    call_count = 0

    async def _op():
        nonlocal call_count
        call_count += 1
        return "success"

    res = await execute_with_retry(_op, max_retries=3, backoff_factor=1.1)
    assert res == "success"
    assert call_count == 1


@pytest.mark.asyncio
async def test_execute_with_retry_recovers_from_503():
    call_count = 0

    async def _op():
        nonlocal call_count
        call_count += 1
        if call_count < 2:
            req = httpx.Request("GET", "https://example.com")
            resp = httpx.Response(503, request=req)
            raise httpx.HTTPStatusError("Service Unavailable", request=req, response=resp)
        return "recovered"

    res = await execute_with_retry(_op, max_retries=3, backoff_factor=1.0)
    assert res == "recovered"
    assert call_count == 2


@pytest.mark.asyncio
async def test_execute_with_retry_exceeds_max_retries_on_429():
    async def _op():
        req = httpx.Request("GET", "https://example.com")
        resp = httpx.Response(429, request=req)
        raise httpx.HTTPStatusError("Too Many Requests", request=req, response=resp)

    with pytest.raises(RateLimitExceededError):
        await execute_with_retry(_op, max_retries=2, backoff_factor=1.0)


@pytest.mark.asyncio
async def test_execute_with_retry_non_retryable_404():
    call_count = 0

    async def _op():
        nonlocal call_count
        call_count += 1
        req = httpx.Request("GET", "https://example.com")
        resp = httpx.Response(404, request=req)
        raise httpx.HTTPStatusError("Not Found", request=req, response=resp)

    with pytest.raises(httpx.HTTPStatusError):
        await execute_with_retry(_op, max_retries=3)

    assert call_count == 1

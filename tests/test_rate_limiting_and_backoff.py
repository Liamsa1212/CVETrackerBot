"""Tests for token bucket limiter, HTTP 429 retry-after backoff, jitter, and EPSS batching."""

import asyncio
import time
import httpx
import pytest
import respx

from cve_tracker.core.config import Settings
from cve_tracker.core.exceptions import RateLimitExceededError
from cve_tracker.core.rate_limiter import AsyncRateLimiter, execute_with_retry
from cve_tracker.fetchers.epss import EPSS_API_URL, EPSSClient


@pytest.mark.asyncio
async def test_token_bucket_rate_limiting():
    """Verify that AsyncRateLimiter enforces token consumption rate."""
    limiter = AsyncRateLimiter(rate=5.0, capacity=2.0)

    start = time.monotonic()
    # Consume burst capacity immediately
    await limiter.acquire(1.0)
    await limiter.acquire(1.0)
    elapsed_burst = time.monotonic() - start
    assert elapsed_burst < 0.1  # Burst should be instantaneous

    # Next acquire requires waiting ~0.2s for token replenishment
    await limiter.acquire(1.0)
    elapsed_total = time.monotonic() - start
    assert elapsed_total >= 0.15


@pytest.mark.asyncio
async def test_token_bucket_over_capacity_safeguard():
    """Verify that requesting tokens > capacity raises ValueError immediately rather than deadlocking."""
    limiter = AsyncRateLimiter(rate=1.0, capacity=2.0)

    with pytest.raises(ValueError, match="cannot exceed bucket capacity"):
        await limiter.acquire(5.0)


@pytest.mark.asyncio
async def test_execute_with_retry_respects_retry_after_header():
    """Verify that HTTP 429 with 'Retry-After' header sleeps the specified duration."""
    attempt_count = 0
    start_time = time.monotonic()

    async def flaky_operation():
        nonlocal attempt_count
        attempt_count += 1
        if attempt_count == 1:
            req = httpx.Request("GET", "https://api.test/rate-limited")
            resp = httpx.Response(429, headers={"Retry-After": "1"}, request=req)
            raise httpx.HTTPStatusError("Rate limited", request=req, response=resp)
        return "success"

    result = await execute_with_retry(
        flaky_operation,
        max_retries=2,
        operation_name="RateLimitTest",
    )

    elapsed = time.monotonic() - start_time
    assert result == "success"
    assert attempt_count == 2
    assert elapsed >= 1.0


@pytest.mark.asyncio
async def test_execute_with_retry_exhaustion_raises_rate_limit_exceeded():
    """Verify that persistent HTTP 429 raises RateLimitExceededError upon exhausting max retries."""
    async def always_rate_limited():
        req = httpx.Request("GET", "https://api.test/rate-limited")
        resp = httpx.Response(429, headers={"Retry-After": "0"}, request=req)
        raise httpx.HTTPStatusError("Rate limited", request=req, response=resp)

    with pytest.raises(RateLimitExceededError):
        await execute_with_retry(
            always_rate_limited,
            max_retries=2,
            backoff_factor=1.0,
            operation_name="PersistentRateLimit",
        )


@pytest.mark.asyncio
@respx.mock
async def test_epss_batching_splits_large_query_chunks(test_settings: Settings):
    """Verify that querying >50 CVEs splits requests into chunks of at most 50."""
    cve_list = [f"CVE-2024-{1000 + i}" for i in range(120)]  # 120 CVEs

    route = respx.get(EPSS_API_URL).mock(
        return_value=httpx.Response(200, json={"data": [{"cve": "CVE-2024-1000", "epss": "0.5", "percentile": "0.9"}]})
    )

    client = EPSSClient(test_settings)
    scores = await client.get_scores(cve_list)
    await client.close()

    # 120 items chunked into 50 -> 3 separate HTTP requests (50, 50, 20)
    assert route.call_count == 3

"""Tests for GenericWebhookNotifier: SSRF security validation, payload format, and failure recovery."""

import httpx
import pytest
import respx

from cve_tracker.core.exceptions import ValidationError
from cve_tracker.core.security import validate_outbound_url
from cve_tracker.models.cve import CVEItem
from cve_tracker.notifiers.webhook import GenericWebhookNotifier


@pytest.mark.asyncio
async def test_webhook_ssrf_forbidden_destinations(sample_cve: CVEItem):
    """Verify that dangerous local, internal, and cloud-metadata addresses are rejected."""
    notifier = GenericWebhookNotifier()

    dangerous_urls = [
        "http://127.0.0.1:8000/internal-api",
        "http://localhost:5000/admin",
        "http://169.254.169.254/latest/meta-data/",
        "http://10.0.0.15/secrets",
        "http://192.168.1.1/router-login",
        "ftp://example.com/payload",
        "file:///etc/passwd",
    ]

    for bad_url in dangerous_urls:
        success = await notifier.send_alert(bad_url, sample_cve)
        assert success is False, f"Expected {bad_url} to be blocked by SSRF filter"


@pytest.mark.asyncio
@respx.mock
async def test_webhook_delivery_success(sample_cve: CVEItem):
    """Verify successful delivery of JSON payload and valid schema structure."""
    target_url = "https://siem.example.com/api/v1/cve-inbox"
    mock_route = respx.post(target_url).mock(return_value=httpx.Response(200, json={"status": "received"}))

    notifier = GenericWebhookNotifier()
    success = await notifier.send_alert(target_url, sample_cve)

    assert success is True
    assert mock_route.called
    sent_request = mock_route.calls.last.request
    import json
    data = json.loads(sent_request.content)
    assert data["event"] == "cve_alert"
    assert data["cve"]["id"] == sample_cve.id
    assert data["cve"]["cvss"]["score"] == 9.8


@pytest.mark.asyncio
@respx.mock
async def test_webhook_delivery_failure_http_500_retries(sample_cve: CVEItem):
    """Verify transient HTTP 500 triggers retry and eventually reports delivery failure."""
    target_url = "https://alerting.example.com/hooks"
    mock_route = respx.post(target_url).mock(return_value=httpx.Response(500, text="Internal Server Error"))

    notifier = GenericWebhookNotifier()
    success = await notifier.send_alert(target_url, sample_cve)

    assert success is False
    # Max retries = 3, so total attempts should be 4 (1 initial + 3 retries)
    assert mock_route.call_count == 4


@pytest.mark.asyncio
@respx.mock
async def test_webhook_delivery_client_error_404_no_retry(sample_cve: CVEItem):
    """Verify HTTP 404 client error halts immediately without wasting retry cycles."""
    target_url = "https://alerting.example.com/missing-hook"
    mock_route = respx.post(target_url).mock(return_value=httpx.Response(404, text="Not Found"))

    notifier = GenericWebhookNotifier()
    success = await notifier.send_alert(target_url, sample_cve)

    assert success is False
    assert mock_route.call_count == 1  # No retries on 4xx errors other than 429


@pytest.mark.asyncio
@respx.mock
async def test_webhook_network_timeout(sample_cve: CVEItem):
    """Verify network read timeouts are caught and reported as delivery failures."""
    target_url = "https://unresponsive.example.com/hook"
    respx.post(target_url).mock(side_effect=httpx.ReadTimeout("Server timed out"))

    notifier = GenericWebhookNotifier()
    success = await notifier.send_alert(target_url, sample_cve)

    assert success is False

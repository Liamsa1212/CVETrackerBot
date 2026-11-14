"""Tests for Telegram notification formatting and HTML escaping."""

from cve_tracker.models.cve import CVEItem, CVSSData, Reference, Severity, SourceType
from cve_tracker.notifiers.telegram import TelegramNotifier


def test_telegram_html_formatting():
    cve = CVEItem(
        id="CVE-2024-8888",
        source=SourceType.NVD,
        title="Test <XSS> & Special 'Chars' Vulnerability",
        description="A vulnerability with <script>alert(1)</script> & special & characters.",
        cvss=CVSSData(
            version="3.1",
            score=8.5,
            vector_string="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            severity=Severity.HIGH,
        ),
        cwes=["CWE-79"],
        affected_vendors=["test <vendor>"],
        affected_products=["test <product>"],
        references=[
            Reference(url="https://github.com/test/poc", tags=["exploit"]),
        ],
    )

    formatted = TelegramNotifier.format_html_alert(cve)

    # HTML special characters must be properly escaped
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in formatted
    assert "&lt;vendor&gt;" in formatted
    assert "&lt;product&gt;" in formatted
    assert "CVE-2024-8888" in formatted
    assert "<code>HIGH 8.5</code>" in formatted
    assert "https://github.com/test/poc" in formatted


def test_telegram_format_briefing_list():
    cve1 = CVEItem(
        id="CVE-2024-0001",
        source=SourceType.NVD,
        description="First issue",
        cvss=CVSSData(score=9.8, severity=Severity.CRITICAL),
    )
    cve2 = CVEItem(
        id="CVE-2024-0002",
        source=SourceType.CISA_KEV,
        description="Second zero-day issue",
        cvss=CVSSData(score=9.0, severity=Severity.CRITICAL),
        is_cisa_kev=True,
    )

    briefing = TelegramNotifier.format_briefing_list([cve1, cve2], title="Latest Vulnerabilities")

    assert "LATEST VULNERABILITIES" in briefing
    assert "1. <code>CVE-2024-0001</code>" in briefing
    assert "2. <code>CVE-2024-0002</code>" in briefing
    assert "[KEV]" in briefing

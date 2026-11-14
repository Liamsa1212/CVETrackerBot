"""Tests for Pydantic domain models and filter matching logic."""

import pytest
from pydantic import ValidationError

from cve_tracker.models.cve import (
    CVEItem,
    CVSSData,
    Reference,
    Severity,
    SourceType,
)
from cve_tracker.models.filter import SubscriptionFilter


def test_severity_from_score():
    assert Severity.from_score(9.8) == Severity.CRITICAL
    assert Severity.from_score(9.0) == Severity.CRITICAL
    assert Severity.from_score(8.9) == Severity.HIGH
    assert Severity.from_score(7.0) == Severity.HIGH
    assert Severity.from_score(6.9) == Severity.MEDIUM
    assert Severity.from_score(4.0) == Severity.MEDIUM
    assert Severity.from_score(3.9) == Severity.LOW
    assert Severity.from_score(0.1) == Severity.LOW
    assert Severity.from_score(0.0) == Severity.UNKNOWN
    assert Severity.from_score(None) == Severity.UNKNOWN


def test_reference_exploit_detection():
    ref_github = Reference(url="https://github.com/someone/poc-exploit")
    assert ref_github.is_exploit is True

    ref_exploitdb = Reference(url="https://www.exploit-db.com/exploits/12345")
    assert ref_exploitdb.is_exploit is True

    ref_tag = Reference(url="https://security.example.com/writeup", tags=["exploit", "advisory"])
    assert ref_tag.is_exploit is True

    ref_normal = Reference(url="https://example.com/docs", tags=["vendor-advisory"])
    assert ref_normal.is_exploit is False


def test_cve_item_validation(sample_cve):
    assert sample_cve.id == "CVE-2024-9999"
    assert sample_cve.severity == Severity.CRITICAL
    assert len(sample_cve.poc_urls) == 1
    assert sample_cve.poc_urls[0] == "https://github.com/example/poc"
    assert len(sample_cve.content_hash) == 64


def test_cve_item_invalid_id():
    with pytest.raises(ValidationError):
        CVEItem(
            id="INVALID-ID-123",
            source=SourceType.NVD,
            description="Test invalid id",
        )


def test_filter_matches_min_cvss(sample_cve):
    # Filter with min score 9.0 should match score 9.8
    f_match = SubscriptionFilter(min_cvss=9.0)
    assert f_match.matches(sample_cve) is True

    # Filter with min score 9.9 should NOT match
    f_no_match = SubscriptionFilter(min_cvss=9.9)
    assert f_no_match.matches(sample_cve) is False


def test_filter_matches_vendors_and_products(sample_cve):
    # Matches vendor
    f_vendor = SubscriptionFilter(vendors=["microsoft"])
    assert f_vendor.matches(sample_cve) is True

    # Unmatched vendor
    f_other_vendor = SubscriptionFilter(vendors=["oracle"])
    assert f_other_vendor.matches(sample_cve) is False

    # Matches product
    f_prod = SubscriptionFilter(products=["windows_server"])
    assert f_prod.matches(sample_cve) is True


def test_filter_matches_keywords(sample_cve):
    f_kw = SubscriptionFilter(keywords=["remote code execution"])
    assert f_kw.matches(sample_cve) is True

    f_kw_miss = SubscriptionFilter(keywords=["sql injection"])
    assert f_kw_miss.matches(sample_cve) is False


def test_filter_matches_cisa_kev(sample_cve, sample_cisa_cve):
    f_cisa = SubscriptionFilter(cisa_kev_only=True)
    assert f_cisa.matches(sample_cve) is False
    assert f_cisa.matches(sample_cisa_cve) is True


def test_filter_matches_poc_only(sample_cve, sample_cisa_cve):
    f_poc = SubscriptionFilter(has_poc_only=True)
    # sample_cve has GitHub PoC url
    assert f_poc.matches(sample_cve) is True
    # sample_cisa_cve has no PoC url
    assert f_poc.matches(sample_cisa_cve) is False

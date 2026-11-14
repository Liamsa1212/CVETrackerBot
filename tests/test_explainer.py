"""Tests for ThreatExplainerService plain-English summaries."""

from cve_tracker.models.cve import CVEItem, CVSSData, Severity, SourceType
from cve_tracker.services.explainer import ThreatExplainerService


def test_explainer_with_known_cwe(sample_cve: CVEItem):
    # sample_cve has CWE-120
    text = ThreatExplainerService.generate_explanation(sample_cve)

    assert "Plain-English Threat Breakdown" in text
    assert "Classic Buffer Overflow" in text
    assert "Business & Security Impact" in text
    assert "Recommended Mitigation" in text


def test_explainer_with_cisa_zero_day(sample_cisa_cve: CVEItem):
    text = ThreatExplainerService.generate_explanation(sample_cisa_cve)

    assert "Plain-English Threat Breakdown" in text
    assert "OS Command Injection" in text
    assert "Active Exploit Alert" in text

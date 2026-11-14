"""Tests for Mutation diff detector, STIX 2.1 exporter, MITRE ATT&CK mapping, and SBOM audit."""

import json
import pytest

from cve_tracker.core.security import mask_sensitive_url, validate_outbound_url
from cve_tracker.core.exceptions import ValidationError
from cve_tracker.models.cve import CVEItem, CVSSData, Reference, Severity, SourceType
from cve_tracker.services.audit import ManifestAuditService
from cve_tracker.services.mitre import MitreAttackService
from cve_tracker.services.mutation import MutationDetector
from cve_tracker.services.stix_exporter import STIX21Exporter
from cve_tracker.storage.models import CVERecord
from cve_tracker.storage.repository import CVERepository


def test_mutation_diff_detection_cisa_added():
    """Verify significant mutation triggered when CVE is added to CISA KEV."""
    existing = CVERecord(
        id="CVE-2024-3400",
        source="nvd",
        description="PAN-OS vulnerability",
        cvss_score=9.8,
        severity="CRITICAL",
        is_cisa_kev=False,
    )
    incoming = CVEItem(
        id="CVE-2024-3400",
        source=SourceType.NVD,
        description="PAN-OS vulnerability",
        cvss=CVSSData(score=9.8, vector_string="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", severity=Severity.CRITICAL),
        is_cisa_kev=True,
    )

    diff = MutationDetector.detect_mutation(existing, incoming)
    assert diff is not None
    assert diff.is_significant is True
    assert diff.cisa_kev_added is True
    alert_text = diff.format_diff_alert()
    assert "Added to Active Exploitation Catalog" in alert_text


def test_mutation_diff_detection_poc_weaponization():
    """Verify significant mutation triggered when first public PoC is detected."""
    existing = CVERecord(
        id="CVE-2024-1234",
        source="nvd",
        description="Memory corruption",
        cvss_score=8.5,
        severity="HIGH",
        is_cisa_kev=False,
        references_json="[]",
    )
    incoming = CVEItem(
        id="CVE-2024-1234",
        source=SourceType.NVD,
        description="Memory corruption",
        cvss=CVSSData(score=8.5, vector_string="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", severity=Severity.HIGH),
        references=[Reference(url="https://github.com/threat/cve-2024-1234-poc")],
    )

    diff = MutationDetector.detect_mutation(existing, incoming)
    assert diff is not None
    assert diff.is_significant is True
    assert diff.new_poc_detected is True


def test_stix21_bundle_generation(sample_cve: CVEItem):
    """Verify STIX 2.1 JSON bundle meets schema requirements."""
    bundle_bytes = STIX21Exporter.export_json_bytes(sample_cve)
    assert isinstance(bundle_bytes, bytes)

    bundle = json.loads(bundle_bytes.decode("utf-8"))
    assert bundle["type"] == "bundle"
    assert len(bundle["objects"]) >= 1

    vuln_obj = next(o for o in bundle["objects"] if o["type"] == "vulnerability")
    assert vuln_obj["name"] == sample_cve.id
    assert vuln_obj["x_cvss_score"] == 9.8


def test_mitre_attack_mapping(sample_cve: CVEItem):
    """Verify mapping CWEs to MITRE ATT&CK techniques."""
    cve_with_cwe = sample_cve.model_copy()
    cve_with_cwe.cwes = ["CWE-77"]

    techniques = MitreAttackService.get_techniques_for_cve(cve_with_cwe)
    assert len(techniques) >= 1
    tech_ids = [t["id"] for t in techniques]
    assert "T1059" in tech_ids

    breakdown_text = MitreAttackService.format_mitre_breakdown(cve_with_cwe)
    assert "T1059" in breakdown_text
    assert "Command and Scripting Interpreter" in breakdown_text


@pytest.mark.asyncio
async def test_sbom_manifest_audit_service(repository: CVERepository, sample_cve: CVEItem):
    """Verify SBOM manifest audit grading and report compilation."""
    await repository.upsert_cve(sample_cve)

    audit_svc = ManifestAuditService(repository)
    report = await audit_svc.audit_dependencies(["windows_server", "clean-lib"])

    assert report.total_packages == 2
    assert "windows_server" in [p for p, _ in report.vulnerable_packages]
    assert "GRADE F" in report.health_grade or "CRITICAL" in report.health_grade
    assert "EXPOSURE HIGHLIGHTS" in report.summary_html


def test_url_masking():
    """Verify sensitive Discord webhook URLs are redacted."""
    url = "https://discord.com/api/webhooks/123456789/SecretTokenStringABC"
    masked = mask_sensitive_url(url)
    assert "SecretTokenStringABC" not in masked
    assert "[REDACTED]" in masked

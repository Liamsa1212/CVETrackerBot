"""Dependency Manifest Audit & Security Posture Scoring Service."""

from dataclasses import dataclass
import html
from typing import List, Tuple
from cve_tracker.models.cve import CVEItem
from cve_tracker.storage.repository import CVERepository


@dataclass
class AuditReport:
    """Security audit outcome for a software dependency manifest."""
    total_packages: int
    vulnerable_packages: List[Tuple[str, List[CVEItem]]]
    health_grade: str
    summary_html: str


class ManifestAuditService:
    """Audits software package manifests against stored CVE and KEV intelligence."""

    def __init__(self, repository: CVERepository):
        self.repository = repository

    async def audit_dependencies(self, package_names: List[str]) -> AuditReport:
        """Analyze a list of packages against the vulnerability database."""
        vulnerable_items: List[Tuple[str, List[CVEItem]]] = []
        max_cvss = 0.0
        total_vuln_count = 0

        for pkg in package_names:
            cves = await self.repository.get_cves_by_product(pkg, limit=5)
            if cves:
                vulnerable_items.append((pkg, cves))
                total_vuln_count += len(cves)
                for c in cves:
                    if c.cvss and c.cvss.score and c.cvss.score > max_cvss:
                        max_cvss = c.cvss.score

        # Grade Calculation: A (Clean) to F (Active KEV or Critical CVSS 9.0+)
        has_kev = any(c.is_cisa_kev for _, cve_list in vulnerable_items for c in cve_list)
        if has_kev or max_cvss >= 9.0:
            grade = "F (CRITICAL EXPOSURE)"
        elif max_cvss >= 7.0:
            grade = "D (HIGH RISK)"
        elif max_cvss >= 4.0:
            grade = "C (MODERATE RISK)"
        elif total_vuln_count > 0:
            grade = "B (LOW RISK)"
        else:
            grade = "A (CLEAN)"

        lines = [
            "<b>DEPENDENCY MANIFEST AUDIT COMPLETE</b>",
            f"<b>Components Evaluated:</b> <code>{len(package_names)}</code>",
            f"<b>Security Posture Rating:</b> <code>GRADE {grade}</code>",
            f"<b>Vulnerable Components:</b> <code>{len(vulnerable_items)}</code>\n",
        ]

        if vulnerable_items:
            lines.append("<b>EXPOSURE HIGHLIGHTS</b>")
            for pkg, cves in vulnerable_items[:5]:
                top_cve = cves[0]
                score = f"{top_cve.cvss.score:.1f}" if top_cve.cvss and top_cve.cvss.score else "N/A"
                kev_str = " [<b>CISA KEV</b>]" if top_cve.is_cisa_kev else ""
                lines.append(
                    f"• <code>{html.escape(pkg)}</code>: Affected by <b>{top_cve.id}</b> (<code>{score}</code>){kev_str}"
                )
        else:
            lines.append("<i>No known vulnerabilities identified in current threat feeds for these components.</i>")

        return AuditReport(
            total_packages=len(package_names),
            vulnerable_packages=vulnerable_items,
            health_grade=grade,
            summary_html="\n".join(lines),
        )

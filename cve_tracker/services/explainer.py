"""Plain-English Threat Explainer and Mitigation Advisor."""

import html
import re
from typing import Optional
from loguru import logger

from cve_tracker.models.cve import CVEItem, Severity


class ThreatExplainerService:
    """Generates human-readable vulnerability impact breakdowns and mitigation steps."""

    CWE_EXPLANATIONS = {
        "CWE-78": ("OS Command Injection", "An attacker can append arbitrary system commands to input parameters, forcing the host operating system to execute attacker commands with the privileges of the application."),
        "CWE-79": ("Cross-Site Scripting (XSS)", "Malicious scripts are injected into web pages viewed by other users, allowing session hijacking, credential theft, or page defacement."),
        "CWE-89": ("SQL Injection", "Untrusted user input is directly concatenated into database queries, allowing attackers to dump database contents, modify records, or bypass authentication."),
        "CWE-119": ("Memory Buffer Error", "The software reads from or writes to memory outside the intended buffer boundaries, potentially leading to arbitrary code execution or server crash."),
        "CWE-120": ("Classic Buffer Overflow", "Input data exceeds the allocated buffer size without boundary checking, overwriting adjacent memory and enabling remote code execution."),
        "CWE-287": ("Improper Authentication", "The system fails to adequately verify the identity of the actor, allowing attackers to access protected endpoints without valid credentials."),
        "CWE-352": ("Cross-Site Request Forgery (CSRF)", "An attacker tricks an authenticated user's browser into executing unauthorized actions on their behalf."),
        "CWE-502": ("Insecure Deserialization", "Untrusted data is deserialized without validation, allowing remote attackers to instantiate arbitrary objects and execute arbitrary code."),
        "CWE-918": ("Server-Side Request Forgery (SSRF)", "The server can be manipulated into issuing internal network requests, exposing cloud metadata (e.g. AWS/GCP credentials) or private internal microservices."),
        "CWE-1321": ("Prototype Pollution", "Modifying object prototype properties in JavaScript/Node.js leads to unexpected behavior, denial of service, or remote code execution."),
    }

    @classmethod
    def generate_explanation(cls, cve: CVEItem) -> str:
        """Generate structured 3-part plain English breakdown."""
        title = html.escape(cve.title or cve.id)

        # 1. Root Cause & Vector
        cwe_title = "Vulnerability Mechanism"
        cwe_desc = None
        for cwe in cve.cwes:
            if cwe in cls.CWE_EXPLANATIONS:
                cwe_title, cwe_desc = cls.CWE_EXPLANATIONS[cwe]
                break

        if not cwe_desc:
            desc_lower = cve.description.lower()
            if "remote code execution" in desc_lower or "rce" in desc_lower:
                cwe_title = "Remote Code Execution (RCE)"
                cwe_desc = "Flaw allows untrusted external network actors to execute code on the host machine without physical access."
            elif "denial of service" in desc_lower or "dos" in desc_lower:
                cwe_title = "Denial of Service (DoS)"
                cwe_desc = "Sending specially crafted requests crashes the target service or exhausts server resources."
            elif "privilege escalation" in desc_lower:
                cwe_title = "Privilege Escalation"
                cwe_desc = "A low-privileged user or process can gain root/administrator access."
            else:
                cwe_desc = html.escape(cve.description[:350])

        # 2. Potential Attack Impact
        if cve.severity in (Severity.CRITICAL, Severity.HIGH):
            impact = "<b>High/Critical Threat:</b> Full system compromise, unauthorized data exfiltration, or complete takeover of host environment."
        elif cve.severity == Severity.MEDIUM:
            impact = "<b>Moderate Threat:</b> Partial data leakage, integrity loss, or localized service degradation."
        else:
            impact = "<b>Low Threat:</b> Informational disclosure or minor reliability disruption."

        # 3. Actionable Mitigation Workarounds
        mitigations = [
            "• <b>Immediate Patching:</b> Upgrade affected software to the vendor's latest security release."
        ]
        if cve.is_cisa_kev:
            mitigations.append("• <b>Active Exploit Alert:</b> This CVE is actively exploited in the wild. Apply emergency patches or disconnect exposed interfaces immediately.")

        if cve.affected_products:
            mitigations.append(f"• <b>Affected Target:</b> Review configuration for <code>{html.escape(', '.join(cve.affected_products[:3]))}</code>.")

        mitigations.append("• <b>Network Defense:</b> Restrict ingress traffic to trusted IP ranges or place behind a Web Application Firewall (WAF).")

        mitigations_text = "\n".join(mitigations)

        explanation = (
            f"💡 <b>Plain-English Threat Breakdown: {html.escape(cve.id)}</b>\n\n"
            f"🎯 <b>1. What Happened ({cwe_title}):</b>\n"
            f"{cwe_desc}\n\n"
            f"💥 <b>2. Business & Security Impact:</b>\n"
            f"{impact}\n\n"
            f"🛡️ <b>3. Recommended Mitigation:</b>\n"
            f"{mitigations_text}\n"
        )
        return explanation

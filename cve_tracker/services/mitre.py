"""MITRE ATT&CK Technique Mapping and Ransomware Correlation Service."""

from typing import Dict, List, Optional
from cve_tracker.models.cve import CVEItem

# Knowledge base mapping common CWE weaknesses to MITRE ATT&CK Enterprise Techniques
CWE_TO_ATTACK: Dict[str, List[Dict[str, str]]] = {
    "CWE-77": [
        {"id": "T1059", "name": "Command and Scripting Interpreter", "tactic": "Execution"},
        {"id": "T1203", "name": "Exploitation for Client Execution", "tactic": "Execution"},
    ],
    "CWE-78": [
        {"id": "T1059", "name": "Command and Scripting Interpreter", "tactic": "Execution"},
        {"id": "T1190", "name": "Exploit Public-Facing Application", "tactic": "Initial Access"},
    ],
    "CWE-89": [
        {"id": "T1190", "name": "Exploit Public-Facing Application", "tactic": "Initial Access"},
        {"id": "T1505", "name": "Server Software Component", "tactic": "Persistence"},
    ],
    "CWE-94": [
        {"id": "T1190", "name": "Exploit Public-Facing Application", "tactic": "Initial Access"},
        {"id": "T1059", "name": "Command and Scripting Interpreter", "tactic": "Execution"},
    ],
    "CWE-22": [
        {"id": "T1005", "name": "Data from Local System", "tactic": "Collection"},
        {"id": "T1190", "name": "Exploit Public-Facing Application", "tactic": "Initial Access"},
    ],
    "CWE-287": [
        {"id": "T1078", "name": "Valid Accounts", "tactic": "Defense Evasion"},
        {"id": "T1190", "name": "Exploit Public-Facing Application", "tactic": "Initial Access"},
    ],
    "CWE-798": [
        {"id": "T1078.001", "name": "Default Accounts", "tactic": "Initial Access"},
        {"id": "T1552", "name": "Unsecured Credentials", "tactic": "Credential Access"},
    ],
    "CWE-502": [
        {"id": "T1190", "name": "Exploit Public-Facing Application", "tactic": "Initial Access"},
        {"id": "T1059", "name": "Command and Scripting Interpreter", "tactic": "Execution"},
    ],
    "CWE-269": [
        {"id": "T1068", "name": "Exploitation for Privilege Escalation", "tactic": "Privilege Escalation"},
    ],
    "CWE-119": [
        {"id": "T1203", "name": "Exploitation for Client Execution", "tactic": "Execution"},
        {"id": "T1068", "name": "Exploitation for Privilege Escalation", "tactic": "Privilege Escalation"},
    ],
    "CWE-120": [
        {"id": "T1203", "name": "Exploitation for Client Execution", "tactic": "Execution"},
        {"id": "T1068", "name": "Exploitation for Privilege Escalation", "tactic": "Privilege Escalation"},
    ],
    "CWE-416": [
        {"id": "T1203", "name": "Exploitation for Client Execution", "tactic": "Execution"},
        {"id": "T1068", "name": "Exploitation for Privilege Escalation", "tactic": "Privilege Escalation"},
    ],
}


class MitreAttackService:
    """Correlates vulnerabilities against the MITRE ATT&CK framework."""

    @staticmethod
    def get_techniques_for_cve(cve: CVEItem) -> List[Dict[str, str]]:
        """Extract applicable ATT&CK Enterprise techniques based on CWE classification and vector."""
        techniques: List[Dict[str, str]] = []
        seen_ids = set()

        # Match from CWEs
        for cwe in cve.cwes:
            cwe_upper = cwe.strip().upper()
            if cwe_upper in CWE_TO_ATTACK:
                for tech in CWE_TO_ATTACK[cwe_upper]:
                    if tech["id"] not in seen_ids:
                        techniques.append(tech)
                        seen_ids.add(tech["id"])

        # Fallback heuristic based on CVSS attack vector
        if not techniques and cve.cvss and cve.cvss.vector_string:
            if "AV:N" in cve.cvss.vector_string:
                techniques.append({
                    "id": "T1190",
                    "name": "Exploit Public-Facing Application",
                    "tactic": "Initial Access",
                })
            elif "AV:L" in cve.cvss.vector_string:
                techniques.append({
                    "id": "T1068",
                    "name": "Exploitation for Privilege Escalation",
                    "tactic": "Privilege Escalation",
                })

        return techniques

    @classmethod
    def format_mitre_breakdown(cls, cve: CVEItem) -> str:
        """Render Telegram HTML summary of mapped ATT&CK techniques."""
        techniques = cls.get_techniques_for_cve(cve)
        lines = [
            f"<b>MITRE ATT&CK MAPPING // {cve.id}</b>",
            f"<b>Primary Weakness:</b> <code>{cve.cwes[0] if cve.cwes else 'N/A'}</code>\n",
        ]

        if techniques:
            lines.append("<b>APPLICABLE ENTERPRISE TECHNIQUES</b>")
            for t in techniques[:5]:
                lines.append(
                    f"• <code>{t['id']}</code> — <b>{t['name']}</b> (Tactic: <i>{t['tactic']}</i>)"
                )
        else:
            lines.append("<i>No direct technique correlation identified for this vulnerability weakness.</i>")

        if cve.is_cisa_kev:
            lines.append("\n<b>OPERATIONAL CONTEXT</b>")
            lines.append("• <b>CISA KEV Catalog:</b> Listed for active exploitation in the wild.")
            lines.append("• <b>Ransomware Association:</b> Monitored under CISA BOD 22-01 mandates.")

        return "\n".join(lines)

"""Vulnerability Lifecycle Mutation and Diff Detection Engine."""

from dataclasses import dataclass
import json
from typing import Optional
from cve_tracker.models.cve import CVEItem
from cve_tracker.storage.models import CVERecord


@dataclass(frozen=True)
class CVEMutationDiff:
    """Represents detected state changes in a vulnerability."""
    cve_id: str
    cvss_old: Optional[float]
    cvss_new: Optional[float]
    epss_old: Optional[float]
    epss_new: Optional[float]
    cisa_kev_added: bool
    new_poc_detected: bool

    @property
    def is_significant(self) -> bool:
        """Evaluate if mutation warrants high-priority re-alerting."""
        # 1. Added to CISA KEV
        if self.cisa_kev_added:
            return True
        # 2. First public weaponized PoC
        if self.new_poc_detected:
            return True
        # 3. CVSS escalation >= 1.0 or newly assigned High/Critical
        if self.cvss_new is not None:
            if self.cvss_old is None and self.cvss_new >= 7.0:
                return True
            if self.cvss_old is not None and (self.cvss_new - self.cvss_old) >= 1.0:
                return True
        # 4. EPSS probability surge >= 25%
        if self.epss_new is not None and self.epss_old is not None:
            if (self.epss_new - self.epss_old) >= 0.25:
                return True
        return False

    def format_diff_alert(self) -> str:
        """Format an executive mutation notice for Telegram."""
        lines = [
            f"<b>LIFECYCLE MUTATION DETECTED // <code>{self.cve_id}</code></b>",
            "<b>Trigger:</b> Upstream Intelligence Escalation\n",
            "<b>DETECTED STATE DELTAS</b>",
        ]
        if self.cisa_kev_added:
            lines.append("• <b>CISA KEV:</b> <code>Added to Active Exploitation Catalog</code>")
        if self.new_poc_detected:
            lines.append("• <b>Weaponization:</b> <code>Public Exploit Verified</code>")
        if self.cvss_new != self.cvss_old:
            old_s = f"{self.cvss_old:.1f}" if self.cvss_old is not None else "N/A"
            new_s = f"{self.cvss_new:.1f}" if self.cvss_new is not None else "N/A"
            lines.append(f"• <b>CVSS Score:</b> <code>{old_s}</code> ➔ <code>{new_s}</code>")
        if self.epss_new != self.epss_old:
            old_p = f"{self.epss_old * 100:.1f}%" if self.epss_old is not None else "N/A"
            new_p = f"{self.epss_new * 100:.1f}%" if self.epss_new is not None else "N/A"
            lines.append(f"• <b>EPSS Risk:</b> <code>{old_p}</code> ➔ <code>{new_p}</code>")

        lines.append("\n<i>Run /cve " + self.cve_id + " for complete updated intelligence dossier.</i>")
        return "\n".join(lines)


class MutationDetector:
    """Detects meaningful security posture shifts between existing records and polled items."""

    @staticmethod
    def detect_mutation(existing: CVERecord, incoming: CVEItem) -> Optional[CVEMutationDiff]:
        # Existing PoC count
        had_poc = False
        if existing.references_json:
            try:
                refs = json.loads(existing.references_json)
                had_poc = any(
                    "exploit" in r.get("url", "").lower() or "poc" in r.get("url", "").lower()
                    for r in refs if isinstance(r, dict)
                )
            except Exception:
                pass

        now_has_poc = len(incoming.poc_urls) > 0
        new_poc = now_has_poc and not had_poc
        cisa_added = incoming.is_cisa_kev and not existing.is_cisa_kev

        diff = CVEMutationDiff(
            cve_id=incoming.id,
            cvss_old=existing.cvss_score,
            cvss_new=incoming.cvss.score if incoming.cvss else None,
            epss_old=existing.epss_score,
            epss_new=incoming.epss_score,
            cisa_kev_added=cisa_added,
            new_poc_detected=new_poc,
        )

        return diff if diff.is_significant else None

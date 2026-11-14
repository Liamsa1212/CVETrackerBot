"""Daily Morning Threat Digest Compiler."""

from datetime import datetime, timedelta, timezone
import html
from typing import List, Optional
from loguru import logger

from cve_tracker.models.cve import CVEItem, Severity
from cve_tracker.storage.repository import CVERepository


def _ensure_utc(dt: Optional[datetime]) -> Optional[datetime]:
    if dt is None:
        return None
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


class DailyDigestCompiler:
    """Compiles daily vulnerability intelligence into an executive threat summary."""

    def __init__(self, repository: CVERepository):
        self.repository = repository

    async def compile_morning_digest(self, hours: int = 24) -> Optional[str]:
        """
        Compile vulnerabilities from the past N hours into an executive briefing.
        Returns HTML formatted briefing string or None if no significant activity.
        """
        # Fetch the most recent 100 CVEs
        cves = await self.repository.get_latest_cves(limit=100)
        if not cves:
            return None

        cutoff = datetime.now(timezone.utc) - timedelta(hours=hours)

        def _is_recent(c: CVEItem) -> bool:
            pub = _ensure_utc(c.published_at)
            upd = _ensure_utc(c.updated_at)
            return (pub is not None and pub >= cutoff) or (upd is not None and upd >= cutoff)

        recent_cves = [c for c in cves if _is_recent(c)]
        if not recent_cves:
            recent_cves = cves[:15]  # Fallback to latest available

        total_count = len(recent_cves)
        cisa_cves = [c for c in recent_cves if c.is_cisa_kev]
        critical_cves = [c for c in recent_cves if c.severity == Severity.CRITICAL]
        poc_cves = [c for c in recent_cves if c.poc_urls]

        # Top EPSS probability risers
        epss_cves = sorted(
            [c for c in recent_cves if c.epss_score is not None],
            key=lambda c: c.epss_score or 0.0,
            reverse=True,
        )

        lines = [
            "<b>EXECUTIVE THREAT INTELLIGENCE BRIEFING</b>",
            f"<b>Period:</b> <code>{cutoff.strftime('%Y-%m-%d %H:%M')} UTC</code> to <code>{datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M')} UTC</code>",
            "<b>Classification:</b> TLP:CLEAR // AUTOMATED DISPATCH\n",
            "<b>SURFACE TELEMETRY</b>",
            f"• Total Analyzed: <code>{total_count}</code> | Critical (9.0+): <code>{len(critical_cves)}</code>",
            f"• CISA KEV Additions: <code>{len(cisa_cves)}</code> | Weaponized PoCs: <code>{len(poc_cves)}</code>",
        ]

        if epss_cves and epss_cves[0].epss_score:
            lines.append(f"• Peak EPSS Weaponization Risk: <code>{epss_cves[0].epss_score * 100:.1f}%</code>\n")
        else:
            lines.append("")

        # 1. CISA KEV urgent actions
        if cisa_cves:
            lines.append("<b>URGENT REMEDIATION ACTIONS (CISA KEV)</b>")
            for c in cisa_cves[:3]:
                due_info = f" [Remediation Due: <b>{c.cisa_action_due.strftime('%Y-%m-%d')}</b>]" if c.cisa_action_due else ""
                lines.append(f"• <code>{c.id}</code>: {html.escape(c.title or c.description[:80])}{due_info}")
            lines.append("")

        # 2. Top Criticals
        if critical_cves:
            lines.append("<b>TOP CRITICAL VULNERABILITIES</b>")
            for c in critical_cves[:3]:
                score_str = f"CVSS {c.cvss.score:.1f}" if c.cvss and c.cvss.score else "Critical"
                lines.append(f"• <code>{c.id}</code> (<code>{score_str}</code>) — {html.escape(c.description[:100])}...")
            lines.append("")

        # 3. High EPSS exploitation risk
        if epss_cves and epss_cves[0].epss_score and epss_cves[0].epss_score >= 0.15:
            lines.append("<b>EXPLOITATION PROBABILITY SURGES (EPSS)</b>")
            for c in epss_cves[:3]:
                prob = f"{c.epss_score * 100:.1f}%" if c.epss_score else "N/A"
                pct_str = f" ({c.epss_percentile * 100:.0f}th percentile)" if c.epss_percentile else ""
                lines.append(f"• <code>{c.id}</code>: <code>{prob}</code>{pct_str} weaponization likelihood")
            lines.append("")

        lines.append("<i>Run /cve &lt;ID&gt; for full intelligence dossier and mitigation analysis.</i>")
        return "\n".join(lines)

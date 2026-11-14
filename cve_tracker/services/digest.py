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
            "☕ <b>Daily Threat Intelligence Briefing</b>",
            f"📅 <code>{datetime.now(timezone.utc).strftime('%A, %B %d, %Y')}</code>\n",
            "📊 <b>24-Hour Threat Statistics:</b>",
            f"• <b>Total Discovered:</b> {total_count}",
            f"• <b>🔴 Critical Severity:</b> {len(critical_cves)}",
            f"• <b>🔥 CISA Actively Exploited:</b> {len(cisa_cves)}",
            f"• <b>🧪 Public PoC Available:</b> {len(poc_cves)}\n",
        ]

        # 1. CISA KEV highlights
        if cisa_cves:
            lines.append("🔥 <b>Active 0-Day / KEV Additions:</b>")
            for c in cisa_cves[:3]:
                due_info = f" (Due: {c.cisa_action_due.strftime('%Y-%m-%d')})" if c.cisa_action_due else ""
                lines.append(f"• <b>{c.id}</b>: {html.escape(c.title or c.description[:80])}{due_info}")
            lines.append("")

        # 2. Top Criticals
        if critical_cves:
            lines.append("🔴 <b>Top Critical Vulnerabilities:</b>")
            for c in critical_cves[:3]:
                score_str = f"CVSS {c.cvss.score:.1f}" if c.cvss and c.cvss.score else "Critical"
                lines.append(f"• <b>{c.id}</b> [{score_str}] — {html.escape(c.description[:100])}...")
            lines.append("")

        # 3. High EPSS exploitation risk
        if epss_cves and epss_cves[0].epss_score and epss_cves[0].epss_score >= 0.20:
            lines.append("📈 <b>Highest Exploit Probability (EPSS):</b>")
            for c in epss_cves[:3]:
                prob = f"{c.epss_score * 100:.1f}%" if c.epss_score else "N/A"
                lines.append(f"• <b>{c.id}</b>: <code>{prob}</code> probability of weaponization")
            lines.append("")

        lines.append("💡 <i>Tip: Send any CVE ID or use /cve &lt;ID&gt; for an instant threat dossier.</i>")
        return "\n".join(lines)

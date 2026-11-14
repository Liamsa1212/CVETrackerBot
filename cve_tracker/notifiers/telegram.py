"""Telegram alert notifier using clean, executive-grade HTML formatting."""

import html
from typing import List, Optional
from loguru import logger
import telegram
from telegram import LinkPreviewOptions
from telegram.constants import ParseMode

from cve_tracker.models.cve import CVEItem, Severity
from cve_tracker.models.subscriber import ChannelType
from cve_tracker.notifiers.base import BaseNotifier


class TelegramNotifier(BaseNotifier):
    """Notifier for Telegram chats and channels with professional, high-signal formatting."""

    def __init__(self, bot: Optional[telegram.Bot] = None, token: Optional[str] = None):
        if bot:
            self.bot = bot
        elif token:
            self.bot = telegram.Bot(token=token)
        else:
            self.bot = None

    @property
    def channel_type(self) -> ChannelType:
        return ChannelType.TELEGRAM

    @staticmethod
    def format_html_alert(cve: CVEItem) -> str:
        """Format an individual CVE into a sleek, executive-grade security card."""
        sev_tag = cve.severity.value
        score_str = f"{cve.cvss.score:.1f}" if cve.cvss and cve.cvss.score is not None else "N/A"
        kev_status = " · <code>CISA KEV ACTIVE</code>" if cve.is_cisa_kev else ""

        # Title & classification banner
        lines = [
            f"<b>SECURITY ADVISORY // {html.escape(cve.id)}</b>",
            f"<b>Severity:</b> <code>{sev_tag} {score_str}</code>{kev_status}",
        ]

        # Target classification
        vendors = [v for v in cve.affected_vendors if v]
        products = [p for p in cve.affected_products if p]
        if vendors or products:
            target_v = html.escape(", ".join(vendors[:2])) if vendors else "generic"
            target_p = html.escape(", ".join(products[:2])) if products else "system"
            lines.append(f"<b>Target:</b> <code>{target_v}</code> : <code>{target_p}</code>")

        # Technical abstract in native expandable blockquote
        desc_clean = " ".join(cve.description.strip().split())
        lines.append(f"\n<blockquote expandable>{html.escape(desc_clean)}</blockquote>\n")

        # Triage metrics
        lines.append("<b>OPERATIONAL METRICS</b>")
        if cve.cvss and cve.cvss.vector_string:
            lines.append(f"• <b>CVSS Vector:</b> <code>{html.escape(cve.cvss.vector_string)}</code>")

        if cve.epss_score is not None:
            pct_str = f" ({cve.epss_percentile * 100:.0f}th percentile)" if cve.epss_percentile else ""
            lines.append(f"• <b>EPSS Risk:</b> <code>{cve.epss_score * 100:.1f}%</code>{pct_str}")

        if cve.cwes:
            lines.append(f"• <b>Weakness:</b> <code>{html.escape(cve.cwes[0])}</code>")

        if cve.is_cisa_kev and cve.cisa_action_due:
            lines.append(f"• <b>Remediation Due:</b> <code>{cve.cisa_action_due.strftime('%Y-%m-%d')}</code>")

        # Intelligence & References
        lines.append("\n<b>INTELLIGENCE & REFERENCES</b>")
        links = [f'<a href="https://nvd.nist.gov/vuln/detail/{cve.id}">NVD Advisory</a>']
        if cve.poc_urls and cve.poc_urls[0].startswith("https://"):
            links.append(f'<a href="{html.escape(cve.poc_urls[0])}">PoC Exploit</a>')
        if cve.detection_urls and cve.detection_urls[0].startswith("https://"):
            links.append(f'<a href="{html.escape(cve.detection_urls[0])}">Detection Template</a>')
        lines.append(" · ".join(links))

        return "\n".join(lines)

    @staticmethod
    def format_briefing_list(cves: List[CVEItem], title: str = "LATEST SECURITY ADVISORIES") -> str:
        """Format a list of CVEs into a dense columnar executive briefing."""
        if not cves:
            return f"<b>{html.escape(title)}</b>\n\n<i>No advisory records matching current criteria.</i>"

        lines = [
            f"<b>{html.escape(title).upper()}</b>",
            f"<b>Records Returned:</b> <code>{len(cves)}</code> // TLP:CLEAR\n",
        ]

        for idx, cve in enumerate(cves, 1):
            sev_tag = cve.severity.value
            score_str = f"{cve.cvss.score:.1f}" if cve.cvss and cve.cvss.score is not None else "N/A"
            kev_badge = " [KEV]" if cve.is_cisa_kev else ""

            # Target & short summary
            targets = []
            if cve.affected_products:
                targets.append(cve.affected_products[0])
            elif cve.affected_vendors:
                targets.append(cve.affected_vendors[0])
            target_str = f"({html.escape(targets[0])}) " if targets else ""

            desc = " ".join(cve.description.strip().split())
            if len(desc) > 115:
                desc = desc[:112] + "..."

            lines.append(
                f"<b>{idx}. <code>{cve.id}</code></b> · <code>{sev_tag} {score_str}</code>{kev_badge}\n"
                f"   {target_str}{html.escape(desc)}"
            )

        lines.append("\n<i>Tap any button below for the full threat dossier and mitigation breakdown:</i>")
        return "\n".join(lines)

    async def send_alert(self, target_id: str, cve: CVEItem) -> bool:
        if not self.bot:
            logger.warning("Telegram bot instance not configured. Cannot send alert.")
            return False

        message_html = self.format_html_alert(cve)
        chat_target = int(target_id) if target_id.lstrip("-").isdigit() else target_id

        try:
            await self.bot.send_message(
                chat_id=chat_target,
                text=message_html,
                parse_mode=ParseMode.HTML,
                link_preview_options=LinkPreviewOptions(is_disabled=True),
            )
            return True
        except telegram.error.Forbidden:
            logger.warning(f"Telegram target {target_id} blocked bot or chat was deleted.")
            return False
        except Exception as e:
            logger.error(f"Failed to send Telegram alert to {target_id}: {e}")
            return False

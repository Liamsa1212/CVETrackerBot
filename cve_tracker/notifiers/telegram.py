"""Telegram alert notifier using safe HTML formatting."""

import html
from typing import Optional
from loguru import logger
import telegram
from telegram.constants import ParseMode

from cve_tracker.models.cve import CVEItem, Severity
from cve_tracker.models.subscriber import ChannelType
from cve_tracker.notifiers.base import BaseNotifier


class TelegramNotifier(BaseNotifier):
    """Notifier for Telegram chats and channels."""

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
        """Format CVE into clean, robust HTML for Telegram."""
        sev_icons = {
            Severity.CRITICAL: "🔴",
            Severity.HIGH: "🟠",
            Severity.MEDIUM: "🟡",
            Severity.LOW: "🔵",
            Severity.UNKNOWN: "⚪",
        }
        icon = sev_icons.get(cve.severity, "⚪")

        lines = [f"{icon} <b>{html.escape(cve.id)}</b> ({html.escape(cve.severity.value)})"]

        if cve.is_cisa_kev:
            lines.append("🔥 <b>CISA KEV: ACTIVELY EXPLOITED IN THE WILD</b>")
            if cve.cisa_action_due:
                lines.append(f"⏰ Remediation Due: <code>{cve.cisa_action_due.strftime('%Y-%m-%d')}</code>")

        if cve.title:
            lines.append(f"\n<b>Title:</b> {html.escape(cve.title)}")

        # Score & CVSS details
        score_str = f"{cve.cvss.score:.1f}" if cve.cvss and cve.cvss.score is not None else "N/A"
        version_str = f" (v{cve.cvss.version})" if cve.cvss and cve.cvss.version else ""
        lines.append(f"📊 <b>CVSS:</b> <code>{score_str}</code>{version_str}")

        if cve.cvss and cve.cvss.vector_string:
            lines.append(f"⚡ <b>Vector:</b> <code>{html.escape(cve.cvss.vector_string)}</code>")

        # Affected vendors & products
        if cve.affected_vendors or cve.affected_products:
            vp_parts = []
            if cve.affected_vendors:
                vp_parts.append(f"Vendors: {', '.join(html.escape(v) for v in cve.affected_vendors[:5])}")
            if cve.affected_products:
                vp_parts.append(f"Products: {', '.join(html.escape(p) for p in cve.affected_products[:5])}")
            lines.append(f"🎯 <b>Target:</b> {'; '.join(vp_parts)}")

        # CWEs
        if cve.cwes:
            lines.append(f"🏷️ <b>Weakness:</b> {', '.join(html.escape(c) for c in cve.cwes[:4])}")

        # Description (truncate to avoid Telegram 4096 char limit)
        desc = cve.description.strip()
        max_desc_len = 1200
        if len(desc) > max_desc_len:
            desc = desc[:max_desc_len] + "..."
        lines.append(f"\n📝 <b>Description:</b>\n{html.escape(desc)}")

        # PoCs
        if cve.poc_urls:
            pocs_text = "\n".join(f"• <a href='{html.escape(url)}'>{html.escape(url)}</a>" for url in cve.poc_urls[:3])
            lines.append(f"\n🧪 <b>Proof of Concept:</b>\n{pocs_text}")

        # Reference links
        nvd_url = f"https://nvd.nist.gov/vuln/detail/{cve.id}"
        lines.append(f"\n🔗 <a href='{nvd_url}'>NVD Advisory</a>")

        return "\n".join(lines)

    async def send_alert(self, target_id: str, cve: CVEItem) -> bool:
        if not self.bot:
            logger.warning("Telegram bot instance not configured. Cannot send alert.")
            return False

        message_html = self.format_html_alert(cve)
        try:
            await self.bot.send_message(
                chat_id=int(target_id),
                text=message_html,
                parse_mode=ParseMode.HTML,
                disable_web_page_preview=True,
            )
            return True
        except telegram.error.Forbidden:
            logger.warning(f"Telegram user {target_id} blocked bot or chat was deleted.")
            return False
        except Exception as e:
            logger.error(f"Failed to send Telegram alert to {target_id}: {e}")
            return False

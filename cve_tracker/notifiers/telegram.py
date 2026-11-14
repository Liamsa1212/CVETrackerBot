"""Telegram alert notifier using clean, minimalist, professional HTML formatting."""

import html
from typing import List, Optional
from loguru import logger
import telegram
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
        """Format an individual CVE into a sleek, concise security card."""
        sev_tag = cve.severity.value
        score_str = f"{cve.cvss.score:.1f}" if cve.cvss and cve.cvss.score is not None else "N/A"

        # Clean header badge
        header = f"<b>{html.escape(cve.id)}</b> · <code>{sev_tag} {score_str}</code>"
        if cve.is_cisa_kev:
            header += " [<b>CISA KEV</b>]"
        if cve.title:
            header += f"\n<b>{html.escape(cve.title)}</b>"

        lines = [header]

        # Target (vendor & product)
        targets = []
        if cve.affected_vendors:
            targets.extend(cve.affected_vendors[:2])
        if cve.affected_products:
            targets.extend(cve.affected_products[:2])
        if targets:
            unique_targets = list(dict.fromkeys(targets))
            lines.append(f"<b>Target:</b> {html.escape(' / '.join(unique_targets))}")

        # Clean, concise description (max 300 chars)
        desc = " ".join(cve.description.strip().split())
        if len(desc) > 300:
            desc = desc[:297] + "..."
        lines.append(f"\n{html.escape(desc)}")

        # Metrics row
        meta_items = []
        if cve.epss_score is not None:
            meta_items.append(f"<b>EPSS:</b> {cve.epss_score * 100:.1f}%")
        if cve.cwes:
            meta_items.append(f"<b>CWE:</b> {html.escape(cve.cwes[0])}")
        if cve.is_cisa_kev and cve.cisa_action_due:
            meta_items.append(f"<b>Due:</b> {cve.cisa_action_due.strftime('%Y-%m-%d')}")

        if meta_items:
            lines.append(" · ".join(meta_items))

        # Links
        links = [f"<a href='https://nvd.nist.gov/vuln/detail/{cve.id}'>NVD Details</a>"]
        if cve.poc_urls:
            links.append(f"<a href='{html.escape(cve.poc_urls[0])}'>PoC Exploit</a>")
        lines.append(" · ".join(links))

        return "\n".join(lines)

    @staticmethod
    def format_briefing_list(cves: List[CVEItem], title: str = "Latest Vulnerabilities") -> str:
        """Format a list of CVEs into a single scannable executive briefing."""
        if not cves:
            return f"<b>{html.escape(title)}</b>\n\n<i>No recent records matching filter criteria.</i>"

        lines = [f"🛡️ <b>{html.escape(title)}</b>\n"]

        for idx, cve in enumerate(cves, 1):
            sev_tag = cve.severity.value
            score_str = f"{cve.cvss.score:.1f}" if cve.cvss and cve.cvss.score is not None else "N/A"
            cisa_badge = " [<b>CISA KEV</b>]" if cve.is_cisa_kev else ""

            # Target & short summary
            targets = []
            if cve.affected_vendors:
                targets.extend(cve.affected_vendors[:1])
            if cve.affected_products:
                targets.extend(cve.affected_products[:1])
            target_str = f"<b>{html.escape(' '.join(dict.fromkeys(targets)))}</b> — " if targets else ""

            desc = " ".join(cve.description.strip().split())
            if len(desc) > 130:
                desc = desc[:127] + "..."

            epss_str = f" · EPSS: {cve.epss_score * 100:.0f}%" if cve.epss_score is not None else ""
            poc_str = " · <a href='" + html.escape(cve.poc_urls[0]) + "'>PoC</a>" if cve.poc_urls else ""

            item_block = (
                f"{idx}. <b>{html.escape(cve.id)}</b> · <code>{sev_tag} {score_str}</code>{cisa_badge}\n"
                f"   {target_str}{html.escape(desc)}\n"
                f"   <a href='https://nvd.nist.gov/vuln/detail/{cve.id}'>Advisory</a>{poc_str}{epss_str}"
            )
            lines.append(item_block)

        lines.append("\n<i>Tap any button below for the full threat dossier and mitigation breakdown:</i>")
        return "\n\n".join(lines)

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

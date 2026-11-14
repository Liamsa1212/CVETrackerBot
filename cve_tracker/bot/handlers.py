"""Telegram bot command handlers and interaction flows."""

import html
import io
import re
from typing import Optional
from loguru import logger
from telegram import InlineKeyboardButton, InlineKeyboardMarkup, Update
from telegram.constants import ParseMode
from telegram.error import BadRequest
from telegram.ext import (
    CallbackQueryHandler,
    CommandHandler,
    ContextTypes,
    ConversationHandler,
    MessageHandler,
    filters,
)

from cve_tracker.bot.keyboards import (
    get_filter_type_menu,
    get_main_menu,
    get_persistent_reply_keyboard,
)
from cve_tracker.models.filter import SubscriptionFilter
from cve_tracker.models.subscriber import ChannelType
from cve_tracker.notifiers.telegram import TelegramNotifier
from cve_tracker.services.audit import ManifestAuditService
from cve_tracker.services.digest import DailyDigestCompiler
from cve_tracker.services.dossier import CVEDossierService
from cve_tracker.services.explainer import ThreatExplainerService
from cve_tracker.services.mitre import MitreAttackService
from cve_tracker.services.stix_exporter import STIX21Exporter
from cve_tracker.services.watchlist import WatchlistParser
from cve_tracker.storage.repository import CVERepository


def _get_repo(context: ContextTypes.DEFAULT_TYPE) -> CVERepository:
    return context.bot_data["repository"]


def _get_dossier_service(context: ContextTypes.DEFAULT_TYPE) -> CVEDossierService:
    if "dossier_service" not in context.bot_data:
        context.bot_data["dossier_service"] = CVEDossierService(
            settings=context.bot_data["settings"],
            repository=context.bot_data["repository"],
        )
    return context.bot_data["dossier_service"]


def format_filters_summary(f: SubscriptionFilter) -> str:
    """Render a clean HTML overview of active filters."""
    cisa_text = "🟢 Enabled (Alert only on actively exploited 0-days)" if f.cisa_kev_only else "⚪ Disabled (All CVE sources)"
    poc_text = "🟢 Enabled (Alert only if public exploit exists)" if f.has_poc_only else "⚪ Disabled"
    min_score_text = f"{f.min_cvss:.1f}" if f.min_cvss is not None else "Any"
    min_epss_text = f"{f.min_epss * 100:.0f}%" if f.min_epss is not None else "Any"

    lines = [
        "⚙️ <b>Your Current Alert Filters:</b>\n",
        f"• <b>Minimum CVSS Score:</b> <code>{min_score_text}</code>",
        f"• <b>Minimum EPSS Probability:</b> <code>{min_epss_text}</code>",
        f"• <b>CISA KEV 0-Day Only:</b> {cisa_text}",
        f"• <b>Must Have PoC Exploit:</b> {poc_text}",
        f"• <b>Tech Stack Watchlist:</b> {', '.join(f'<code>{html.escape(w)}</code>' for w in f.watchlist[:10]) if f.watchlist else '<i>None</i>'}",
        f"• <b>Vendors:</b> {', '.join(f'<code>{html.escape(v)}</code>' for v in f.vendors[:5]) if f.vendors else '<i>All Vendors</i>'}",
        f"• <b>Products:</b> {', '.join(f'<code>{html.escape(p)}</code>' for p in f.products[:5]) if f.products else '<i>All Products</i>'}",
        f"• <b>Keywords:</b> {', '.join(f'<code>{html.escape(k)}</code>' for k in f.keywords[:5]) if f.keywords else '<i>All Keywords</i>'}",
        f"• <b>CWEs:</b> {', '.join(f'<code>{html.escape(c)}</code>' for c in f.cwes[:5]) if f.cwes else '<i>All CWEs</i>'}",
        "\n<i>Tap an action below to add a filter or toggle rules:</i>",
    ]
    return "\n".join(lines)


MAX_MANIFEST_SIZE_BYTES = 512 * 1024  # 512 KB
MAX_WATCHLIST_ITEMS = 100


async def start_command(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Handle /start command with a unified, executive sentinel dashboard."""
    welcome_text = (
        "<b>SENTINEL ACTIVE // CVE TRACKER BOT v2.1</b>\n"
        "<b>Classification:</b> TLP:CLEAR // SOC OPERATIONAL CONSOLE\n\n"
        "<b>INTELLIGENCE FEEDS MONITORED</b>\n"
        "• <b>NIST NVD API 2.0:</b> Real-time ingestion with CVSS v4/v3/v2 scoring\n"
        "• <b>CISA KEV Catalog:</b> Actively weaponized 0-days in the wild\n"
        "• <b>GitHub Advisories:</b> Ecosystem dependencies (npm, PyPI, Go, Cargo)\n"
        "• <b>FIRST.org EPSS:</b> Predictive exploitation probability modeling\n\n"
        "<b>COMMAND SHORTCUTS</b>\n"
        "• <code>/latest</code> — 5 most recent high-signal advisories\n"
        "• <code>/cisa</code> — Active 0-days under federal remediation mandates\n"
        "• <code>/cve &lt;ID&gt;</code> — Full intelligence dossier, ATT&CK mapping & STIX export\n"
        "• <code>/watch</code> — Software watchlist inventory & real-time matching\n"
        "• <code>/audit</code> — Instant SBOM security posture evaluation (Grade A–F)\n"
        "• <code>/digest</code> — 24-hour executive morning threat intelligence briefing\n"
        "• <code>/filters</code> — Fine-tune CVSS, EPSS, and vendor notification rules\n\n"
        "<i>Use the persistent navigation console below to begin:</i>"
    )
    if update.effective_message:
        await update.effective_message.reply_text(
            welcome_text,
            parse_mode=ParseMode.HTML,
            reply_markup=get_persistent_reply_keyboard(),
        )


async def help_command(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Handle /help command."""
    help_text = (
        "<b>SENTINEL COMMAND REFERENCE // CVE TRACKER BOT</b>\n\n"
        "<b>THREAT DISCOVERY & INVESTIGATION</b>\n"
        "• <code>/latest</code> — Dense columnar list of recent vulnerabilities\n"
        "• <code>/cisa</code> — Active CISA KEV entries with remediation countdowns\n"
        "• <code>/cve CVE-YYYY-NNNN</code> — Technical dossier, PoC status & ATT&CK mapping\n"
        "• <code>/digest</code> — 24-hour executive threat intelligence summary\n\n"
        "<b>SUPPLY CHAIN & ASSET INVENTORY</b>\n"
        "• <code>/watch [pkg1, pkg2]</code> — Monitor specific software or packages\n"
        "• <code>/audit</code> — Instant SBOM security posture check (Grade A–F)\n"
        "• <i>Tip: Drag and drop requirements.txt or package.json into this chat!</i>\n\n"
        "<b>SUBSCRIPTIONS & ALERT FILTERING</b>\n"
        "• <code>/subscribe</code> — Activate automated push notifications\n"
        "• <code>/unsubscribe</code> — Pause automated alerts\n"
        "• <code>/filters</code> — Interactive filter wizard (CVSS, EPSS, Vendors)\n"
        "• <code>/setminscore &lt;score&gt;</code> — Set minimum CVSS threshold (e.g. 7.5)\n"
        "• <code>/clearfilters</code> — Reset all filters to default\n"
    )
    if update.effective_message:
        await update.effective_message.reply_text(
            help_text,
            parse_mode=ParseMode.HTML,
            reply_markup=get_persistent_reply_keyboard(),
        )


async def cve_lookup_command(update: Update, context: ContextTypes.DEFAULT_TYPE, cve_id_override: Optional[str] = None) -> None:
    """Zero-leak in-place CVE Dossier lookup."""
    cve_id = cve_id_override
    if not cve_id and context.args:
        cve_id = context.args[0]

    if not cve_id:
        if update.effective_message:
            await update.effective_message.reply_text(
                "<b>Usage:</b> <code>/cve CVE-2024-3400</code>",
                parse_mode=ParseMode.HTML,
            )
        return

    cve_id = cve_id.strip().upper()
    if not re.match(r"^CVE-\d{4}-\d{4,}$", cve_id):
        if update.effective_message:
            await update.effective_message.reply_text(
                "<b>Error:</b> Invalid CVE ID format (expected <code>CVE-YYYY-NNNN</code>).",
                parse_mode=ParseMode.HTML,
            )
        return

    # Single editable status message preventing chat clutter
    status_msg = None
    if update.effective_message:
        status_msg = await update.effective_message.reply_text(
            f"<code>QUERY // Fetching dossier for {cve_id}...</code>",
            parse_mode=ParseMode.HTML,
        )

    dossier_svc = _get_dossier_service(context)
    cve = await dossier_svc.get_cve_dossier(cve_id)

    if not cve:
        err_msg = f"<b>Error:</b> No intelligence records found for <code>{html.escape(cve_id)}</code>."
        if status_msg:
            await status_msg.edit_text(err_msg, parse_mode=ParseMode.HTML)
        elif update.effective_message:
            await update.effective_message.reply_text(err_msg, parse_mode=ParseMode.HTML)
        return

    html_msg = TelegramNotifier.format_html_alert(cve)
    markup = CVEDossierService.get_dossier_markup(cve.id)

    if status_msg:
        await status_msg.edit_text(
            html_msg,
            parse_mode=ParseMode.HTML,
            reply_markup=markup,
        )
    elif update.effective_message:
        await update.effective_message.reply_text(
            html_msg,
            parse_mode=ParseMode.HTML,
            reply_markup=markup,
        )


async def watchlist_command(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Handle /watch or watchlist management with capped bounds and clean escaping."""
    chat_id = str(update.effective_chat.id)
    repo = _get_repo(context)
    sub = await repo.get_subscriber(chat_id, ChannelType.TELEGRAM)
    filt = sub.filters if sub else SubscriptionFilter()

    if context.args:
        raw_text = " ".join(context.args)
        new_items = WatchlistParser.parse_comma_separated(raw_text)
        if new_items:
            combined = sorted(list(set(filt.watchlist + new_items)))
            if len(combined) > MAX_WATCHLIST_ITEMS:
                if update.effective_message:
                    await update.effective_message.reply_text(
                        f"⚠️ Watchlist capacity limit reached ({MAX_WATCHLIST_ITEMS} items maximum).",
                        parse_mode=ParseMode.HTML,
                    )
                return

            filt.watchlist = combined
            await repo.update_subscriber_filters(chat_id, ChannelType.TELEGRAM, filt)
            escaped_items = ", ".join(f"<code>{html.escape(i)}</code>" for i in new_items[:10])
            msg = f"✅ Added {len(new_items)} components to watchlist: {escaped_items}"
            if update.effective_message:
                await update.effective_message.reply_text(msg, parse_mode=ParseMode.HTML)
            return

    # Display watchlist summary
    MAX_DISPLAY = 30
    if filt.watchlist:
        displayed = filt.watchlist[:MAX_DISPLAY]
        wl_text = "\n".join(f"• <code>{html.escape(item)}</code>" for item in displayed)
        overflow = f"\n<i>...and {len(filt.watchlist) - MAX_DISPLAY} more components</i>" if len(filt.watchlist) > MAX_DISPLAY else ""
        body = f"<b>TECH STACK WATCHLIST ({len(filt.watchlist)} components):</b>\n\n{wl_text}{overflow}\n\n"
    else:
        body = "<b>TECH STACK WATCHLIST (0 components):</b>\n\n<i>No software components currently tracked.</i>\n\n"

    body += (
        "<b>USAGE INSTRUCTIONS:</b>\n"
        "• Add components: <code>/watch nginx, redis, postgresql</code>\n"
        "• Or <b>drag and drop a requirements.txt or package.json</b> file into this chat for an instant SBOM security audit!"
    )

    if update.effective_message:
        await update.effective_message.reply_text(body, parse_mode=ParseMode.HTML)


async def handle_document_upload(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Handle uploaded requirements.txt or package.json files for instant SBOM security audit."""
    if not update.effective_message or not update.effective_message.document:
        return

    doc = update.effective_message.document
    filename = doc.file_name or "manifest.txt"

    # Enforce file size limit to prevent memory exhaustion
    if doc.file_size and doc.file_size > MAX_MANIFEST_SIZE_BYTES:
        await update.effective_message.reply_text(
            f"❌ Manifest exceeds the 512 KB upload limit (file size: {doc.file_size // 1024} KB)."
        )
        return

    # Verify plausible manifest name
    if not (filename.endswith(".txt") or filename.endswith(".json") or "requirements" in filename.lower() or "package" in filename.lower()):
        return

    status_msg = await update.effective_message.reply_text(
        f"<code>AUDIT // Ingesting and evaluating '{html.escape(filename)}'...</code>",
        parse_mode=ParseMode.HTML,
    )

    try:
        tg_file = await doc.get_file()
        file_bytes = await tg_file.download_as_bytearray()
        content = file_bytes.decode("utf-8", errors="ignore")

        packages = WatchlistParser.parse_manifest(filename, content)
        if not packages:
            await status_msg.edit_text(
                "<b>Warning:</b> No valid software dependencies detected in the uploaded file.",
                parse_mode=ParseMode.HTML,
            )
            return

        chat_id = str(update.effective_chat.id)
        repo = _get_repo(context)
        sub = await repo.get_subscriber(chat_id, ChannelType.TELEGRAM)
        filt = sub.filters if sub else SubscriptionFilter()

        # Update subscriber watchlist up to limit
        combined = sorted(list(set(filt.watchlist + packages)))
        if len(combined) > MAX_WATCHLIST_ITEMS:
            combined = combined[:MAX_WATCHLIST_ITEMS]

        filt.watchlist = combined
        await repo.update_subscriber_filters(chat_id, ChannelType.TELEGRAM, filt)

        # Execute instant SBOM audit across vulnerability database
        audit_svc = ManifestAuditService(repo)
        report = await audit_svc.audit_dependencies(packages)

        audit_text = (
            f"{report.summary_html}\n\n"
            f"<i>Added {len(packages)} components to your active watchlist (total tracked: {len(filt.watchlist)}).</i>"
        )

        await status_msg.edit_text(audit_text, parse_mode=ParseMode.HTML)

    except Exception as e:
        logger.error(f"Error handling manifest upload: {e}")
        await status_msg.edit_text("<b>Error:</b> Failed to process manifest. Verify valid UTF-8 encoding.", parse_mode=ParseMode.HTML)


async def digest_command(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Compile and display the 24-hour threat intelligence digest."""
    repo = _get_repo(context)
    compiler = DailyDigestCompiler(repo)
    digest_text = await compiler.compile_morning_digest(hours=24)

    if not digest_text:
        digest_text = "ℹ️ No vulnerability activity recorded in the past 24 hours."

    if update.effective_message:
        await update.effective_message.reply_text(
            digest_text,
            parse_mode=ParseMode.HTML,
            disable_web_page_preview=True,
            reply_markup=get_persistent_reply_keyboard(),
        )


async def export_command(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Export OASIS STIX 2.1 Threat Intelligence bundle for a CVE."""
    if not context.args:
        if update.effective_message:
            await update.effective_message.reply_text("<b>Usage:</b> <code>/export CVE-2024-3400</code>", parse_mode=ParseMode.HTML)
        return

    cve_id = context.args[0].strip().upper()
    dossier_svc = _get_dossier_service(context)
    cve = await dossier_svc.get_cve_dossier(cve_id)
    if not cve:
        if update.effective_message:
            await update.effective_message.reply_text(
                f"<b>Error:</b> Could not find intelligence records for <code>{html.escape(cve_id)}</code>.",
                parse_mode=ParseMode.HTML,
            )
        return

    stix_bytes = STIX21Exporter.export_json_bytes(cve)
    chat_id = update.effective_chat.id
    await context.bot.send_document(
        chat_id=chat_id,
        document=io.BytesIO(stix_bytes),
        filename=f"{cve_id}_stix21.json",
        caption=f"OASIS STIX 2.1 Threat Intelligence Bundle // {cve_id}",
    )


async def audit_command(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Perform an instant SBOM security posture audit on watchlist components."""
    chat_id = str(update.effective_chat.id)
    repo = _get_repo(context)
    sub = await repo.get_subscriber(chat_id, ChannelType.TELEGRAM)
    filt = sub.filters if sub else SubscriptionFilter()

    targets = filt.watchlist
    if context.args:
        targets = WatchlistParser.parse_comma_separated(" ".join(context.args))

    if not targets:
        if update.effective_message:
            await update.effective_message.reply_text(
                "<b>SBOM Audit:</b> No components monitored. Upload a <code>requirements.txt</code> or run <code>/audit nginx, redis, curl</code> to evaluate.",
                parse_mode=ParseMode.HTML,
            )
        return

    status_msg = None
    if update.effective_message:
        status_msg = await update.effective_message.reply_text(
            "<code>AUDIT // Running SBOM vulnerability posture scan...</code>",
            parse_mode=ParseMode.HTML,
        )

    audit_svc = ManifestAuditService(repo)
    report = await audit_svc.audit_dependencies(targets)

    if status_msg:
        await status_msg.edit_text(report.summary_html, parse_mode=ParseMode.HTML)
    elif update.effective_message:
        await update.effective_message.reply_text(report.summary_html, parse_mode=ParseMode.HTML)


async def subscribe_command(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Handle /subscribe command."""
    chat_id = str(update.effective_chat.id)
    repo = _get_repo(context)
    sub, was_new = await repo.add_or_activate_subscriber(
        target_id=chat_id,
        channel_type=ChannelType.TELEGRAM,
    )
    if was_new:
        msg = "✅ <b>Subscribed successfully!</b> You will receive real-time CVE alerts matching your filters."
    else:
        msg = "📬 <b>Already subscribed.</b> Use the ⚙️ <b>My Filters</b> button to adjust your preferences."

    if update.effective_message:
        await update.effective_message.reply_text(
            msg,
            parse_mode=ParseMode.HTML,
            reply_markup=get_persistent_reply_keyboard(),
        )


async def unsubscribe_command(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Handle /unsubscribe command."""
    chat_id = str(update.effective_chat.id)
    repo = _get_repo(context)
    success = await repo.deactivate_subscriber(
        target_id=chat_id,
        channel_type=ChannelType.TELEGRAM,
    )
    if success:
        msg = "🔕 <b>Unsubscribed.</b> You will no longer receive automated CVE alerts."
    else:
        msg = "ℹ️ This chat is not currently subscribed."

    if update.effective_message:
        await update.effective_message.reply_text(
            msg,
            parse_mode=ParseMode.HTML,
            reply_markup=get_persistent_reply_keyboard(),
        )


async def latest_command(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Fetch and display latest CVEs, respecting active subscriber filters or custom keywords."""
    repo = _get_repo(context)
    chat_id = str(update.effective_chat.id)
    sub = await repo.get_subscriber(chat_id, ChannelType.TELEGRAM)
    user_filter = sub.filters if sub else None

    # Check for CLI args like: /latest all, /latest rce, /latest nginx
    query_arg = " ".join(context.args).strip() if context.args else None

    if query_arg and query_arg.lower() == "all":
        # Unfiltered global latest
        cves = await repo.get_latest_cves(limit=5)
        title = "Latest Vulnerabilities (All)"
    elif query_arg:
        # Dynamic query filter on-demand
        temp_filter = SubscriptionFilter(keywords=[query_arg.lower()])
        candidates = await repo.get_latest_cves(limit=100)
        cves = [c for c in candidates if temp_filter.matches(c)][:5]
        title = f"Latest Advisories ({query_arg.upper()})"
    elif user_filter and (
        user_filter.keywords or user_filter.vendors or user_filter.products or
        user_filter.watchlist or user_filter.cwes or user_filter.cisa_kev_only or
        user_filter.has_poc_only or user_filter.min_cvss or user_filter.min_epss
    ):
        # Apply user's saved subscription filters
        candidates = await repo.get_latest_cves(limit=150)
        cves = [c for c in candidates if user_filter.matches(c)][:5]

        filter_tags = []
        if user_filter.keywords:
            filter_tags.append(f"Keyword: {', '.join(user_filter.keywords[:2])}")
        if user_filter.vendors:
            filter_tags.append(f"Vendor: {', '.join(user_filter.vendors[:2])}")
        if user_filter.products:
            filter_tags.append(f"Product: {', '.join(user_filter.products[:2])}")
        if user_filter.watchlist:
            filter_tags.append("Watchlist")
        if user_filter.cisa_kev_only:
            filter_tags.append("0-Days Only")

        tag_str = f" ({' · '.join(filter_tags)})" if filter_tags else " (Filtered)"
        title = f"Latest Advisories{tag_str}"
    else:
        # Default latest (no custom filters)
        cves = await repo.get_latest_cves(limit=5)
        title = "Latest Vulnerabilities"

    if not cves:
        if user_filter and (user_filter.keywords or user_filter.vendors or user_filter.products or user_filter.watchlist):
            active_info = ", ".join(user_filter.keywords + user_filter.vendors + user_filter.products)
            msg = (
                f"ℹ️ <b>No recent advisories matched your active filter:</b> <code>{html.escape(active_info or 'custom')}</code>\n\n"
                "None of the latest 150 ingested vulnerabilities matched these criteria.\n"
                "• View global unfiltered advisories: <code>/latest all</code>\n"
                "• Adjust or reset your filters: <code>/filters</code>"
            )
        else:
            msg = "ℹ️ No recent vulnerabilities found matching the current threshold."

        if update.effective_message:
            await update.effective_message.reply_text(
                msg,
                parse_mode=ParseMode.HTML,
                reply_markup=get_persistent_reply_keyboard(),
            )
        return

    briefing_text = TelegramNotifier.format_briefing_list(cves, title=title)

    buttons = []
    row = []
    for idx, cve in enumerate(cves, 1):
        row.append(InlineKeyboardButton(f"{idx}. {cve.id}", callback_data=f"cve_view_{cve.id}"))
        if len(row) == 2:
            buttons.append(row)
            row = []
    if row:
        buttons.append(row)

    markup = InlineKeyboardMarkup(buttons) if buttons else None

    if update.effective_message:
        await update.effective_message.reply_text(
            briefing_text,
            parse_mode=ParseMode.HTML,
            disable_web_page_preview=True,
            reply_markup=markup,
        )


async def cisa_command(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Fetch and display recent CISA KEV entries in a single scannable briefing."""
    repo = _get_repo(context)
    cves = await repo.get_latest_cves(limit=5, cisa_only=True)

    if not cves:
        msg = "ℹ️ No active CISA KEV records available at the moment."
        if update.effective_message:
            await update.effective_message.reply_text(
                msg,
                reply_markup=get_persistent_reply_keyboard(),
            )
        return

    briefing_text = TelegramNotifier.format_briefing_list(cves, title="CISA Known Exploited 0-Days")

    buttons = []
    row = []
    for idx, cve in enumerate(cves, 1):
        row.append(InlineKeyboardButton(f"{idx}. {cve.id}", callback_data=f"cve_view_{cve.id}"))
        if len(row) == 2:
            buttons.append(row)
            row = []
    if row:
        buttons.append(row)

    markup = InlineKeyboardMarkup(buttons) if buttons else None

    if update.effective_message:
        await update.effective_message.reply_text(
            briefing_text,
            parse_mode=ParseMode.HTML,
            disable_web_page_preview=True,
            reply_markup=markup,
        )


async def filters_command(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Display active filters for the current chat."""
    repo = _get_repo(context)
    chat_id = str(update.effective_chat.id)
    sub = await repo.get_subscriber(chat_id, ChannelType.TELEGRAM)

    f = sub.filters if sub else SubscriptionFilter()
    msg = format_filters_summary(f)

    if update.effective_message:
        await update.effective_message.reply_text(
            msg,
            parse_mode=ParseMode.HTML,
            reply_markup=get_filter_type_menu(f),
        )


async def set_min_score_command(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Set minimum CVSS score threshold."""
    if not context.args:
        if update.effective_message:
            await update.effective_message.reply_text(
                "Usage: <code>/setminscore 7.5</code>",
                parse_mode=ParseMode.HTML,
                reply_markup=get_persistent_reply_keyboard(),
            )
        return

    try:
        score = float(context.args[0])
        if not (0.0 <= score <= 10.0):
            raise ValueError()
    except ValueError:
        if update.effective_message:
            await update.effective_message.reply_text(
                "❌ Please enter a valid number between 0.0 and 10.0.",
                reply_markup=get_persistent_reply_keyboard(),
            )
        return

    repo = _get_repo(context)
    chat_id = str(update.effective_chat.id)
    sub = await repo.get_subscriber(chat_id, ChannelType.TELEGRAM)
    filt = sub.filters if sub else SubscriptionFilter()
    filt.min_cvss = score
    await repo.update_subscriber_filters(chat_id, ChannelType.TELEGRAM, filt)

    if update.effective_message:
        await update.effective_message.reply_text(
            f"✅ Minimum CVSS filter set to <b>{score:.1f}</b>",
            parse_mode=ParseMode.HTML,
            reply_markup=get_persistent_reply_keyboard(),
        )


async def add_filter_command(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Add a filter rule via command line."""
    if not context.args or len(context.args) < 2:
        if update.effective_message:
            await update.effective_message.reply_text(
                "Usage: <code>/addfilter &lt;vendor|product|keyword|cwe&gt; &lt;value&gt;</code>\n"
                "Example: <code>/addfilter vendor microsoft</code>",
                parse_mode=ParseMode.HTML,
                reply_markup=get_persistent_reply_keyboard(),
            )
        return

    ftype = context.args[0].lower()
    val = " ".join(context.args[1:]).strip().lower()

    valid_types = {"vendor": "vendors", "product": "products", "keyword": "keywords", "cwe": "cwes"}
    if ftype not in valid_types:
        if update.effective_message:
            await update.effective_message.reply_text(
                f"❌ Unknown filter type '{ftype}'. Allowed: {', '.join(valid_types.keys())}",
                reply_markup=get_persistent_reply_keyboard(),
            )
        return

    target_attr = valid_types[ftype]
    repo = _get_repo(context)
    chat_id = str(update.effective_chat.id)
    sub = await repo.get_subscriber(chat_id, ChannelType.TELEGRAM)
    filt = sub.filters if sub else SubscriptionFilter()

    curr_list: list = getattr(filt, target_attr)
    if val not in curr_list:
        curr_list.append(val)
        setattr(filt, target_attr, curr_list)
        await repo.update_subscriber_filters(chat_id, ChannelType.TELEGRAM, filt)
        msg = f"✅ Added <code>{html.escape(val)}</code> to <b>{ftype}</b> filters."
    else:
        msg = f"⚠️ <code>{html.escape(val)}</code> is already in your {ftype} filters."

    if update.effective_message:
        await update.effective_message.reply_text(
            msg,
            parse_mode=ParseMode.HTML,
            reply_markup=get_persistent_reply_keyboard(),
        )


async def clear_filters_command(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Clear all custom filter rules."""
    repo = _get_repo(context)
    chat_id = str(update.effective_chat.id)
    empty_filter = SubscriptionFilter()
    await repo.update_subscriber_filters(chat_id, ChannelType.TELEGRAM, empty_filter)
    if update.effective_message:
        await update.effective_message.reply_text(
            "🧹 <b>All filters cleared.</b> You will now receive all alerts matching global defaults.",
            parse_mode=ParseMode.HTML,
            reply_markup=get_persistent_reply_keyboard(),
        )


async def handle_callback_navigation(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Handle inline button clicks from menus with dynamic feedback."""
    query = update.callback_query
    if not query:
        return
    await query.answer()

    data = query.data
    chat_id = str(query.message.chat.id)
    repo = _get_repo(context)

    # 1. Main Navigation Handlers
    if data == "nav_latest":
        await latest_command(update, context)
    elif data == "nav_cisa":
        await cisa_command(update, context)
    elif data == "nav_watchlist":
        await watchlist_command(update, context)
    elif data == "nav_digest":
        await digest_command(update, context)
    elif data == "nav_subscribe":
        await subscribe_command(update, context)
    elif data == "nav_unsubscribe":
        await unsubscribe_command(update, context)
    elif data == "nav_filterlist":
        await filters_command(update, context)
    elif data == "nav_help":
        await help_command(update, context)
    elif data == "nav_menu":
        await start_command(update, context)

    # 2. Threat Explanation Callback
    elif data.startswith("explain_"):
        cve_id = data.replace("explain_", "")
        dossier_svc = _get_dossier_service(context)
        cve = await dossier_svc.get_cve_dossier(cve_id)
        if cve:
            explanation = ThreatExplainerService.generate_explanation(cve)
            await query.message.reply_text(explanation, parse_mode=ParseMode.HTML)
        else:
            await query.message.reply_text(f"❌ Details for {cve_id} not available.")

    # 3. MITRE ATT&CK Mapping Callback
    elif data.startswith("mitre_"):
        cve_id = data.replace("mitre_", "")
        dossier_svc = _get_dossier_service(context)
        cve = await dossier_svc.get_cve_dossier(cve_id)
        if cve:
            breakdown = MitreAttackService.format_mitre_breakdown(cve)
            await query.message.reply_text(breakdown, parse_mode=ParseMode.HTML)
        else:
            await query.message.reply_text(f"❌ Details for {cve_id} not available.")

    # 4. Export STIX 2.1 Bundle Callback
    elif data.startswith("export_stix_"):
        cve_id = data.replace("export_stix_", "")
        dossier_svc = _get_dossier_service(context)
        cve = await dossier_svc.get_cve_dossier(cve_id)
        if cve:
            stix_bytes = STIX21Exporter.export_json_bytes(cve)
            await context.bot.send_document(
                chat_id=query.message.chat.id,
                document=io.BytesIO(stix_bytes),
                filename=f"{cve_id}_stix21.json",
                caption=f"OASIS STIX 2.1 Threat Intelligence Bundle // {cve_id}",
            )
        else:
            await query.message.reply_text(f"❌ Details for {cve_id} not available.")

    # 5. View Full CVE Dossier from Briefing
    elif data.startswith("cve_view_"):
        cve_id = data.replace("cve_view_", "")
        await cve_lookup_command(update, context, cve_id_override=cve_id)

    # 3. Filter Actions & Input Prompts
    elif data == "filter_add_vendor":
        context.user_data["awaiting_filter"] = "vendor"
        await query.message.reply_text(
            "🏢 <b>Add Vendor Filter</b>\n\n"
            "Please send the vendor name you want to track (e.g. <code>Microsoft</code>, <code>Cisco</code>, <code>Apple</code>):",
            parse_mode=ParseMode.HTML,
        )

    elif data == "filter_add_product":
        context.user_data["awaiting_filter"] = "product"
        await query.message.reply_text(
            "📦 <b>Add Product Filter</b>\n\n"
            "Please send the product name you want to track (e.g. <code>Windows</code>, <code>Chrome</code>, <code>IOS_XE</code>):",
            parse_mode=ParseMode.HTML,
        )

    elif data == "filter_add_keyword":
        context.user_data["awaiting_filter"] = "keyword"
        await query.message.reply_text(
            "🔑 <b>Add Keyword Filter</b>\n\n"
            "Please send the vulnerability keyword (e.g. <code>remote code execution</code>, <code>privilege escalation</code>, <code>rce</code>):",
            parse_mode=ParseMode.HTML,
        )

    elif data == "filter_add_cwe":
        context.user_data["awaiting_filter"] = "cwe"
        await query.message.reply_text(
            "🏷️ <b>Add CWE Filter</b>\n\n"
            "Please send the CWE identifier (e.g. <code>CWE-79</code> for XSS, <code>CWE-89</code> for SQLi):",
            parse_mode=ParseMode.HTML,
        )

    elif data == "filter_set_score":
        context.user_data["awaiting_filter"] = "min_cvss"
        await query.message.reply_text(
            "📊 <b>Set Minimum CVSS Score</b>\n\n"
            "Please send the minimum score (e.g. <code>7.0</code> for High+, <code>9.0</code> for Critical, or <code>0</code> for Any):",
            parse_mode=ParseMode.HTML,
        )

    elif data == "filter_set_epss":
        context.user_data["awaiting_filter"] = "min_epss"
        await query.message.reply_text(
            "📈 <b>Set Minimum EPSS Exploit Probability</b>\n\n"
            "Please send the minimum probability percentage (e.g. <code>20</code> for 20% probability, or <code>0</code> for Any):",
            parse_mode=ParseMode.HTML,
        )

    # 4. Filter Toggles
    elif data == "filter_toggle_cisa":
        sub = await repo.get_subscriber(chat_id, ChannelType.TELEGRAM)
        filt = sub.filters if sub else SubscriptionFilter()
        filt.cisa_kev_only = not filt.cisa_kev_only
        await repo.update_subscriber_filters(chat_id, ChannelType.TELEGRAM, filt)
        new_text = format_filters_summary(filt)
        try:
            await query.edit_message_text(
                new_text,
                parse_mode=ParseMode.HTML,
                reply_markup=get_filter_type_menu(filt),
            )
        except BadRequest as e:
            if "not modified" not in str(e).lower() and "exactly the same" not in str(e).lower():
                logger.warning(f"Failed to edit filter message: {e}")

    elif data == "filter_toggle_poc":
        sub = await repo.get_subscriber(chat_id, ChannelType.TELEGRAM)
        filt = sub.filters if sub else SubscriptionFilter()
        filt.has_poc_only = not filt.has_poc_only
        await repo.update_subscriber_filters(chat_id, ChannelType.TELEGRAM, filt)
        new_text = format_filters_summary(filt)
        try:
            await query.edit_message_text(
                new_text,
                parse_mode=ParseMode.HTML,
                reply_markup=get_filter_type_menu(filt),
            )
        except BadRequest as e:
            if "not modified" not in str(e).lower() and "exactly the same" not in str(e).lower():
                logger.warning(f"Failed to edit filter message: {e}")

    elif data == "filter_clear":
        empty_filter = SubscriptionFilter()
        await repo.update_subscriber_filters(chat_id, ChannelType.TELEGRAM, empty_filter)
        new_text = format_filters_summary(empty_filter)
        try:
            await query.edit_message_text(
                new_text,
                parse_mode=ParseMode.HTML,
                reply_markup=get_filter_type_menu(empty_filter),
            )
        except BadRequest as e:
            if "not modified" not in str(e).lower() and "exactly the same" not in str(e).lower():
                logger.warning(f"Failed to edit filter message: {e}")


async def handle_text_menu_buttons(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Handle persistent bottom keyboard button presses, text shortcuts, filter input responses, or CVE lookups."""
    if not update.effective_message or not update.effective_message.text:
        return

    text = update.effective_message.text.strip()
    chat_id = str(update.effective_chat.id)
    repo = _get_repo(context)

    # 1. Check if user typed a CVE identifier directly (e.g. "CVE-2024-3400")
    cve_match = re.search(r"CVE-\d{4}-\d{4,}", text, re.IGNORECASE)
    if cve_match and len(text) <= 30:
        await cve_lookup_command(update, context, cve_id_override=cve_match.group(0))
        return

    MENU_BUTTONS = [
        "🔍 Latest CVEs", "🔥 CISA 0-Days", "📦 My Watchlist",
        "☕ Threat Digest", "⚙️ My Filters", "❓ Help",
        "🔔 Subscribe", "🔕 Unsubscribe"
    ]
    is_command_or_menu = text.startswith("/") or text in MENU_BUTTONS

    # 2. Check if we were waiting for user input for a filter
    awaiting = context.user_data.get("awaiting_filter")
    if awaiting and not is_command_or_menu:
        context.user_data.pop("awaiting_filter")
        sub = await repo.get_subscriber(chat_id, ChannelType.TELEGRAM)
        filt = sub.filters if sub else SubscriptionFilter()

        if awaiting == "min_cvss":
            try:
                score = float(text)
                if not (0.0 <= score <= 10.0):
                    raise ValueError()
                filt.min_cvss = score if score > 0 else None
                await repo.update_subscriber_filters(chat_id, ChannelType.TELEGRAM, filt)
                await update.effective_message.reply_text(
                    f"✅ <b>Minimum CVSS threshold set to:</b> <code>{score:.1f}</code>",
                    parse_mode=ParseMode.HTML,
                )
                await filters_command(update, context)
                return
            except ValueError:
                await update.effective_message.reply_text("❌ Please enter a valid number between 0.0 and 10.0 (e.g. 7.5).")
                context.user_data["awaiting_filter"] = "min_cvss"
                return

        if awaiting == "min_epss":
            try:
                pct = float(text.replace("%", "").strip())
                if not (0.0 <= pct <= 100.0):
                    raise ValueError()
                filt.min_epss = (pct / 100.0) if pct > 0 else None
                await repo.update_subscriber_filters(chat_id, ChannelType.TELEGRAM, filt)
                await update.effective_message.reply_text(
                    f"✅ <b>Minimum EPSS exploit probability set to:</b> <code>{pct:.0f}%</code>",
                    parse_mode=ParseMode.HTML,
                )
                await filters_command(update, context)
                return
            except ValueError:
                await update.effective_message.reply_text("❌ Please enter a valid percentage between 0 and 100 (e.g. 20).")
                context.user_data["awaiting_filter"] = "min_epss"
                return

        mapping = {"vendor": "vendors", "product": "products", "keyword": "keywords", "cwe": "cwes"}
        target_list_name = mapping.get(awaiting)
        if target_list_name:
            val = text.lower()
            curr_list: list = getattr(filt, target_list_name)
            if val not in curr_list:
                curr_list.append(val)
                setattr(filt, target_list_name, curr_list)
                await repo.update_subscriber_filters(chat_id, ChannelType.TELEGRAM, filt)
                await update.effective_message.reply_text(
                    f"✅ Added <code>{html.escape(val)}</code> to your <b>{awaiting}</b> filters!",
                    parse_mode=ParseMode.HTML,
                )
            else:
                await update.effective_message.reply_text(
                    f"⚠️ <code>{html.escape(val)}</code> is already in your {awaiting} filter list.",
                    parse_mode=ParseMode.HTML,
                )
            await filters_command(update, context)
            return

    # 3. Normal menu navigation matches
    lower_text = text.lower()
    if "latest" in lower_text:
        await latest_command(update, context)
    elif "cisa" in lower_text or "0-day" in lower_text or "zero-day" in lower_text:
        await cisa_command(update, context)
    elif "watchlist" in lower_text or "stack" in lower_text:
        await watchlist_command(update, context)
    elif "digest" in lower_text or "brief" in lower_text:
        await digest_command(update, context)
    elif "unsubscribe" in lower_text:
        await unsubscribe_command(update, context)
    elif "subscribe" in lower_text:
        await subscribe_command(update, context)
    elif "filter" in lower_text:
        await filters_command(update, context)
    elif "help" in lower_text or "menu" in lower_text:
        await help_command(update, context)
    else:
        await update.effective_message.reply_text(
            "🤖 Tap an option from the menu below or send a CVE ID (e.g. <code>CVE-2024-3400</code>):",
            parse_mode=ParseMode.HTML,
            reply_markup=get_persistent_reply_keyboard(),
        )

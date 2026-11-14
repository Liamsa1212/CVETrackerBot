"""Telegram bot command handlers and interaction flows."""

import html
import io
import re
from typing import Optional
from loguru import logger
from telegram import Update
from telegram.constants import ParseMode
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
from cve_tracker.services.digest import DailyDigestCompiler
from cve_tracker.services.dossier import CVEDossierService
from cve_tracker.services.explainer import ThreatExplainerService
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


async def start_command(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Handle /start command."""
    welcome_text = (
        "🛡️ <b>Welcome to CVE Tracker Bot v2.1</b>\n\n"
        "Your automated vulnerability intelligence sentinel.\n"
        "Tracking <b>NIST NVD</b>, <b>CISA KEV</b>, and <b>GitHub Security Advisories</b> in real time.\n\n"
        "Use the persistent menu buttons below or the inline dashboard to navigate:"
    )
    if update.effective_message:
        await update.effective_message.reply_text(
            welcome_text,
            parse_mode=ParseMode.HTML,
            reply_markup=get_persistent_reply_keyboard(),
        )
        await update.effective_message.reply_text(
            "👇 <b>Quick Action Dashboard:</b>",
            parse_mode=ParseMode.HTML,
            reply_markup=get_main_menu(),
        )


async def help_command(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Handle /help command."""
    help_text = (
        "📖 <b>CVE Tracker Bot Help:</b>\n\n"
        "Use the persistent buttons at the bottom of your screen anytime.\n\n"
        "<b>Available features:</b>\n"
        "• 🔍 <b>Latest CVEs</b> — View the 5 most recent vulnerabilities\n"
        "• 🔥 <b>CISA 0-Days</b> — View actively exploited CVEs (CISA KEV catalog)\n"
        "• 📦 <b>My Watchlist</b> — Monitor your specific tech stack or dependencies\n"
        "• ☕ <b>Threat Digest</b> — 24-hour executive morning briefing\n"
        "• 🔔 <b>Subscribe</b> — Receive real-time alerts automatically\n"
        "• 🔕 <b>Unsubscribe</b> — Pause automated alerts\n"
        "• ⚙️ <b>My Filters</b> — Configure alert thresholds and rules\n\n"
        "<b>Commands & Shortcuts:</b>\n"
        "• <code>/cve CVE-YYYY-NNNN</code> — Instant vulnerability dossier & exploit status\n"
        "• <code>/watch nginx, redis, postgresql</code> — Add software to watchlist\n"
        "• <i>Tip: Drag and drop any requirements.txt or package.json into this chat!</i>\n"
        "• <code>/setminscore &lt;score&gt;</code> — Set minimum CVSS (e.g. <code>/setminscore 7.5</code>)\n"
        "• <code>/clearfilters</code> — Reset all filters to default\n"
    )
    if update.effective_message:
        await update.effective_message.reply_text(
            help_text,
            parse_mode=ParseMode.HTML,
            reply_markup=get_persistent_reply_keyboard(),
        )


async def cve_lookup_command(update: Update, context: ContextTypes.DEFAULT_TYPE, cve_id_override: Optional[str] = None) -> None:
    """Handle /cve <ID> or on-demand CVE lookups."""
    cve_id = cve_id_override
    if not cve_id and context.args:
        cve_id = context.args[0]

    if not cve_id:
        if update.effective_message:
            await update.effective_message.reply_text("Usage: <code>/cve CVE-2024-3400</code>", parse_mode=ParseMode.HTML)
        return

    cve_id = cve_id.strip().upper()
    if not re.match(r"^CVE-\d{4}-\d{4,}$", cve_id):
        if update.effective_message:
            await update.effective_message.reply_text("❌ Please enter a valid CVE ID format (e.g. <code>CVE-2024-3400</code>).", parse_mode=ParseMode.HTML)
        return

    if update.effective_message:
        await update.effective_message.reply_text(f"🔍 <i>Querying intelligence dossier for {cve_id}...</i>", parse_mode=ParseMode.HTML)

    dossier_svc = _get_dossier_service(context)
    cve = await dossier_svc.get_cve_dossier(cve_id)

    if not cve:
        if update.effective_message:
            await update.effective_message.reply_text(f"❌ Could not find vulnerability records for <b>{cve_id}</b>.", parse_mode=ParseMode.HTML)
        return

    html_msg = TelegramNotifier.format_html_alert(cve)
    markup = CVEDossierService.get_dossier_markup(cve.id)

    if update.effective_message:
        await update.effective_message.reply_text(
            html_msg,
            parse_mode=ParseMode.HTML,
            disable_web_page_preview=True,
            reply_markup=markup,
        )


async def watchlist_command(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Handle /watch or watchlist management."""
    chat_id = str(update.effective_chat.id)
    repo = _get_repo(context)
    sub = await repo.get_subscriber(chat_id, ChannelType.TELEGRAM)
    filt = sub.filters if sub else SubscriptionFilter()

    if context.args:
        raw_text = " ".join(context.args)
        new_items = WatchlistParser.parse_comma_separated(raw_text)
        if new_items:
            filt.watchlist = sorted(list(set(filt.watchlist + new_items)))
            await repo.update_subscriber_filters(chat_id, ChannelType.TELEGRAM, filt)
            msg = f"✅ Added {len(new_items)} components to your watchlist: {', '.join(f'<code>{i}</code>' for i in new_items)}"
            if update.effective_message:
                await update.effective_message.reply_text(msg, parse_mode=ParseMode.HTML)
            return

    # Display watchlist summary
    if filt.watchlist:
        wl_text = "\n".join(f"• <code>{html.escape(item)}</code>" for item in filt.watchlist)
        body = f"📦 <b>Your Tech Stack Watchlist ({len(filt.watchlist)} items):</b>\n\n{wl_text}\n\n"
    else:
        body = "📦 <b>Your Watchlist is empty.</b>\n\n"

    body += (
        "💡 <b>How to add components:</b>\n"
        "• Reply with software names: <code>/watch nginx, redis, docker</code>\n"
        "• Or <b>drag and drop a requirements.txt / package.json</b> file into this chat to import dependencies automatically!"
    )

    if update.effective_message:
        await update.effective_message.reply_text(body, parse_mode=ParseMode.HTML)


async def handle_document_upload(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Handle uploaded requirements.txt or package.json files to build a watchlist."""
    if not update.effective_message or not update.effective_message.document:
        return

    doc = update.effective_message.document
    filename = doc.file_name or "file.txt"

    # Verify plausible manifest name
    if not (filename.endswith(".txt") or filename.endswith(".json") or "requirements" in filename.lower() or "package" in filename.lower()):
        return

    await update.effective_message.reply_text(f"⏳ <i>Parsing dependency manifest '{html.escape(filename)}'...</i>", parse_mode=ParseMode.HTML)

    try:
        tg_file = await doc.get_file()
        file_bytes = await tg_file.download_as_bytearray()
        content = file_bytes.decode("utf-8", errors="ignore")

        packages = WatchlistParser.parse_manifest(filename, content)
        if not packages:
            await update.effective_message.reply_text("⚠️ Could not detect valid package names in the uploaded document.")
            return

        chat_id = str(update.effective_chat.id)
        repo = _get_repo(context)
        sub = await repo.get_subscriber(chat_id, ChannelType.TELEGRAM)
        filt = sub.filters if sub else SubscriptionFilter()

        filt.watchlist = sorted(list(set(filt.watchlist + packages)))
        await repo.update_subscriber_filters(chat_id, ChannelType.TELEGRAM, filt)

        summary = f"🎉 <b>Successfully imported {len(packages)} packages into your Watchlist!</b>\n\n"
        summary += f"Examples: {', '.join(f'<code>{p}</code>' for p in packages[:8])}..."
        summary += "\nYou will now be alerted whenever a new CVE affects any of these dependencies!"

        await update.effective_message.reply_text(summary, parse_mode=ParseMode.HTML)

    except Exception as e:
        logger.error(f"Error handling manifest upload: {e}")
        await update.effective_message.reply_text("❌ Failed to process document. Ensure it is a valid UTF-8 text file.")


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
    """Fetch and display latest CVEs from the database."""
    repo = _get_repo(context)
    chat_id = str(update.effective_chat.id)
    sub = await repo.get_subscriber(chat_id, ChannelType.TELEGRAM)

    min_score = sub.filters.min_cvss if sub and sub.filters else 6.0
    cves = await repo.get_latest_cves(limit=5, min_score=min_score)

    if not cves:
        msg = "ℹ️ No recent vulnerabilities found matching the current threshold."
        if update.effective_message:
            await update.effective_message.reply_text(
                msg,
                reply_markup=get_persistent_reply_keyboard(),
            )
        return

    for cve in cves:
        html_msg = TelegramNotifier.format_html_alert(cve)
        markup = CVEDossierService.get_dossier_markup(cve.id)
        if update.effective_message:
            await update.effective_message.reply_text(
                html_msg,
                parse_mode=ParseMode.HTML,
                disable_web_page_preview=True,
                reply_markup=markup,
            )


async def cisa_command(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Fetch and display recent CISA KEV entries."""
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

    for cve in cves:
        html_msg = TelegramNotifier.format_html_alert(cve)
        markup = CVEDossierService.get_dossier_markup(cve.id)
        if update.effective_message:
            await update.effective_message.reply_text(
                html_msg,
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
        await query.edit_message_text(
            new_text,
            parse_mode=ParseMode.HTML,
            reply_markup=get_filter_type_menu(filt),
        )

    elif data == "filter_toggle_poc":
        sub = await repo.get_subscriber(chat_id, ChannelType.TELEGRAM)
        filt = sub.filters if sub else SubscriptionFilter()
        filt.has_poc_only = not filt.has_poc_only
        await repo.update_subscriber_filters(chat_id, ChannelType.TELEGRAM, filt)
        new_text = format_filters_summary(filt)
        await query.edit_message_text(
            new_text,
            parse_mode=ParseMode.HTML,
            reply_markup=get_filter_type_menu(filt),
        )

    elif data == "filter_clear":
        empty_filter = SubscriptionFilter()
        await repo.update_subscriber_filters(chat_id, ChannelType.TELEGRAM, empty_filter)
        new_text = format_filters_summary(empty_filter)
        await query.edit_message_text(
            new_text,
            parse_mode=ParseMode.HTML,
            reply_markup=get_filter_type_menu(empty_filter),
        )


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

    # 2. Check if we were waiting for user input for a filter
    awaiting = context.user_data.pop("awaiting_filter", None)
    if awaiting:
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

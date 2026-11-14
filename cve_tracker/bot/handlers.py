"""Telegram bot command handlers and interaction flows."""

import html
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

from cve_tracker.bot.keyboards import get_filter_type_menu, get_main_menu
from cve_tracker.models.filter import SubscriptionFilter
from cve_tracker.models.subscriber import ChannelType
from cve_tracker.notifiers.telegram import TelegramNotifier
from cve_tracker.storage.repository import CVERepository

# Conversation States for Filter Configuration
AWAITING_FILTER_VALUE = 1


def _get_repo(context: ContextTypes.DEFAULT_TYPE) -> CVERepository:
    return context.bot_data["repository"]


async def start_command(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Handle /start command."""
    welcome_text = (
        "🛡️ <b>Welcome to CVE Tracker Bot v2.0</b>\n\n"
        "Your automated vulnerability intelligence sentinel.\n"
        "Tracking <b>NIST NVD</b>, <b>CISA KEV</b>, and <b>GitHub Security Advisories</b> in real time.\n\n"
        "Select an option below or use /help to view command shortcuts:"
    )
    if update.effective_message:
        await update.effective_message.reply_text(
            welcome_text,
            parse_mode=ParseMode.HTML,
            reply_markup=get_main_menu(),
        )


async def help_command(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Handle /help command."""
    help_text = (
        "📖 <b>CVE Tracker Bot Commands:</b>\n\n"
        "• /latest - View the 5 most recent vulnerabilities\n"
        "• /cisa - View latest actively exploited CVEs (CISA KEV)\n"
        "• /subscribe - Subscribe this chat to real-time alerts\n"
        "• /unsubscribe - Stop receiving automated alerts\n"
        "• /filters - View your active filter rules\n"
        "• /setminscore &lt;score&gt; - Set minimum CVSS threshold (e.g. <code>/setminscore 7.5</code>)\n"
        "• /addfilter &lt;vendor|product|keyword|cwe&gt; &lt;val&gt; - Add filter rule\n"
        "• /clearfilters - Reset all filters to default\n"
    )
    if update.effective_message:
        await update.effective_message.reply_text(
            help_text,
            parse_mode=ParseMode.HTML,
            reply_markup=get_main_menu(),
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
        msg = "📬 <b>Already subscribed.</b> Use /filters to adjust your alert preferences."

    if update.effective_message:
        await update.effective_message.reply_text(msg, parse_mode=ParseMode.HTML)


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
        await update.effective_message.reply_text(msg, parse_mode=ParseMode.HTML)


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
            await update.effective_message.reply_text(msg)
        return

    for cve in cves:
        html_msg = TelegramNotifier.format_html_alert(cve)
        if update.effective_message:
            await update.effective_message.reply_text(
                html_msg,
                parse_mode=ParseMode.HTML,
                disable_web_page_preview=True,
            )


async def cisa_command(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Fetch and display recent CISA KEV entries."""
    repo = _get_repo(context)
    cves = await repo.get_latest_cves(limit=5, cisa_only=True)

    if not cves:
        msg = "ℹ️ No active CISA KEV records available at the moment."
        if update.effective_message:
            await update.effective_message.reply_text(msg)
        return

    for cve in cves:
        html_msg = TelegramNotifier.format_html_alert(cve)
        if update.effective_message:
            await update.effective_message.reply_text(
                html_msg,
                parse_mode=ParseMode.HTML,
                disable_web_page_preview=True,
            )


async def filters_command(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Display active filters for the current chat."""
    repo = _get_repo(context)
    chat_id = str(update.effective_chat.id)
    sub = await repo.get_subscriber(chat_id, ChannelType.TELEGRAM)

    f = sub.filters if sub else SubscriptionFilter()
    lines = [
        "⚙️ <b>Your Current Alert Filters:</b>\n",
        f"• <b>Minimum CVSS:</b> {f.min_cvss if f.min_cvss is not None else 'Any'}",
        f"• <b>CISA KEV Only:</b> {'Yes' if f.cisa_kev_only else 'No'}",
        f"• <b>Must Have PoC:</b> {'Yes' if f.has_poc_only else 'No'}",
        f"• <b>Vendors:</b> {', '.join(f.vendors) if f.vendors else 'None (All)'}",
        f"• <b>Products:</b> {', '.join(f.products) if f.products else 'None (All)'}",
        f"• <b>Keywords:</b> {', '.join(f.keywords) if f.keywords else 'None (All)'}",
        f"• <b>CWEs:</b> {', '.join(f.cwes) if f.cwes else 'None (All)'}",
    ]

    if update.effective_message:
        await update.effective_message.reply_text(
            "\n".join(lines),
            parse_mode=ParseMode.HTML,
            reply_markup=get_filter_type_menu(),
        )


async def set_min_score_command(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Set minimum CVSS score threshold."""
    if not context.args:
        if update.effective_message:
            await update.effective_message.reply_text("Usage: <code>/setminscore 7.5</code>", parse_mode=ParseMode.HTML)
        return

    try:
        score = float(context.args[0])
        if not (0.0 <= score <= 10.0):
            raise ValueError()
    except ValueError:
        if update.effective_message:
            await update.effective_message.reply_text("❌ Please enter a valid number between 0.0 and 10.0.")
        return

    repo = _get_repo(context)
    chat_id = str(update.effective_chat.id)
    sub = await repo.get_subscriber(chat_id, ChannelType.TELEGRAM)
    filt = sub.filters if sub else SubscriptionFilter()
    filt.min_cvss = score
    await repo.update_subscriber_filters(chat_id, ChannelType.TELEGRAM, filt)

    if update.effective_message:
        await update.effective_message.reply_text(f"✅ Minimum CVSS filter set to <b>{score:.1f}</b>", parse_mode=ParseMode.HTML)


async def add_filter_command(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Add a filter rule via command line."""
    if not context.args or len(context.args) < 2:
        if update.effective_message:
            await update.effective_message.reply_text(
                "Usage: <code>/addfilter &lt;vendor|product|keyword|cwe&gt; &lt;value&gt;</code>\n"
                "Example: <code>/addfilter vendor microsoft</code>",
                parse_mode=ParseMode.HTML,
            )
        return

    ftype = context.args[0].lower()
    val = " ".join(context.args[1:]).strip().lower()

    valid_types = {"vendor": "vendors", "product": "products", "keyword": "keywords", "cwe": "cwes"}
    if ftype not in valid_types:
        if update.effective_message:
            await update.effective_message.reply_text(f"❌ Unknown filter type '{ftype}'. Allowed: {', '.join(valid_types.keys())}")
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
        await update.effective_message.reply_text(msg, parse_mode=ParseMode.HTML)


async def clear_filters_command(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Clear all custom filter rules."""
    repo = _get_repo(context)
    chat_id = str(update.effective_chat.id)
    empty_filter = SubscriptionFilter()
    await repo.update_subscriber_filters(chat_id, ChannelType.TELEGRAM, empty_filter)
    if update.effective_message:
        await update.effective_message.reply_text("🧹 <b>All filters cleared.</b> You will now receive all alerts matching global defaults.", parse_mode=ParseMode.HTML)


async def handle_callback_navigation(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Handle inline button clicks from menus."""
    query = update.callback_query
    if not query:
        return
    await query.answer()

    data = query.data
    if data == "nav_latest":
        await latest_command(update, context)
    elif data == "nav_cisa":
        await cisa_command(update, context)
    elif data == "nav_subscribe":
        await subscribe_command(update, context)
    elif data == "nav_unsubscribe":
        await unsubscribe_command(update, context)
    elif data == "nav_filterlist":
        await filters_command(update, context)
    elif data == "nav_help":
        await help_command(update, context)
    elif data == "filter_clear":
        await clear_filters_command(update, context)
    elif data == "nav_menu":
        await start_command(update, context)

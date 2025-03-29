import os
import json
import asyncio
import logging
from pathlib import Path
from telegram import (
    Update, InlineKeyboardMarkup, InlineKeyboardButton
)
from telegram.ext import (
    ApplicationBuilder, CommandHandler, CallbackQueryHandler,
    ContextTypes, ConversationHandler, MessageHandler, filters
)
from telegram.helpers import escape_markdown
from config import TELEGRAM_BOT_TOKEN
from cve_fetcher import get_latest_cves
from filters import load_filters, save_filters
import nest_asyncio

# Constants
SUBSCRIBERS_FILE = "subscribers.json"
SENT_CVES_FILE = "sent_cves.json"
FILTER_TYPE, FILTER_VALUE = range(2)
DELETE_FILTER_TYPE, DELETE_FILTER_VALUE = range(2, 4)


logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# ─────────────────────────────
# Utils
# ─────────────────────────────

def load_json(path, default):
    try:
        if Path(path).exists():
            with open(path, "r") as f:
                return json.load(f)
    except json.JSONDecodeError:
        save_json(path, default)
    return default

def save_json(path, data):
    with open(path, "w") as f:
        json.dump(data, f, indent=2)

def load_subscribers():
    return load_json(SUBSCRIBERS_FILE, [])

def save_subscribers(data):
    save_json(SUBSCRIBERS_FILE, data)

def load_sent_cves():
    return set(load_json(SENT_CVES_FILE, []))

def save_sent_cves(data):
    save_json(SENT_CVES_FILE, list(data))

def format_cve_msg(cve):
    msg = f"🚨 {escape_markdown(cve['id'], 2)}\n\n"
    msg += f"Summary: {escape_markdown(cve['summary'], 2)}"
    if "score" in cve:
        msg += f"\n\n📊 CVSS: {escape_markdown(str(cve['score']), 2)}"
    if cve.get("poc"):
        msg += f"\n\n🧪 PoC: {escape_markdown(cve['poc'], 2)}"
    return msg

def get_main_menu():
    return InlineKeyboardMarkup([
        [InlineKeyboardButton("🧪 Latest CVEs", callback_data="latest")],
        [
            InlineKeyboardButton("✅ Subscribe", callback_data="subscribe"),
            InlineKeyboardButton("❌ Unsubscribe", callback_data="unsubscribe")
        ],
        [
            InlineKeyboardButton("🧩 Filter Wizard", callback_data="filterwizard"),
            InlineKeyboardButton("🧹 Delete Filter", callback_data="deletefilter")
        ],
        [InlineKeyboardButton("📋 My Filters", callback_data="filterlist")]
    ])


# ─────────────────────────────
# Bot Commands
# ─────────────────────────────

async def start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    welcome = escape_markdown(
        "👋 Welcome to CVE Alert Bot!\n\n"
        "Stay informed with real-time CVE alerts\\.\n\n"
        "Use the menu below to get started:",
        2
    )
    await update.message.reply_text(welcome, parse_mode="MarkdownV2", reply_markup=get_main_menu())

async def subscribe(update: Update, context: ContextTypes.DEFAULT_TYPE):
    cid = update.effective_chat.id
    subs = load_subscribers()
    if cid not in subs:
        subs.append(cid)
        save_subscribers(subs)
        msg = "✅ Subscribed!"
    else:
        msg = "📬 You're already subscribed."
    await update.message.reply_text(escape_markdown(msg, 2), parse_mode="MarkdownV2")

async def unsubscribe(update: Update, context: ContextTypes.DEFAULT_TYPE):
    cid = update.effective_chat.id
    subs = load_subscribers()
    if cid in subs:
        subs.remove(cid)
        save_subscribers(subs)
        msg = "❌ Unsubscribed."
    else:
        msg = "ℹ️ You weren't subscribed."
    await update.message.reply_text(escape_markdown(msg, 2), parse_mode="MarkdownV2")

async def latest(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await update.message.reply_text(escape_markdown("🔍 Fetching CVEs...", 2), parse_mode="MarkdownV2")
    filters = load_filters()
    user_filter = filters.get(str(update.effective_chat.id), {})
    cves = get_latest_cves(limit=10, min_score=7.0, user_filter=user_filter)

    if not cves:
        await update.message.reply_text(escape_markdown("❌ No CVEs found today.", 2), parse_mode="MarkdownV2")
        return

    for cve in cves:
        msg = format_cve_msg(cve)
        await update.message.reply_text(msg, parse_mode="MarkdownV2")

async def filter_list(update: Update, context: ContextTypes.DEFAULT_TYPE):
    cid = str(update.effective_chat.id)
    filters = load_filters()
    user_filters = filters.get(cid, {})
    if not user_filters:
        await update.message.reply_text("📭 You have no filters set.")
        return

    msg = "📌 Your Filters:\n"
    for ftype, values in user_filters.items():
        msg += f"\n{ftype.title()}: " + ', '.join(f"{v}" for v in values)
    await update.message.reply_text(escape_markdown(msg, 2), parse_mode="MarkdownV2")

# ─────────────────────────────
# Filter Wizard (Conversation)
# ─────────────────────────────

async def filter_wizard_entry(update: Update, context: ContextTypes.DEFAULT_TYPE):
    keyboard = [
        [InlineKeyboardButton("🔘 Vendor", callback_data="vendor")],
        [InlineKeyboardButton("🔘 Keyword", callback_data="keyword")],
        [InlineKeyboardButton("🔘 CWE", callback_data="cwe")]
    ]
    reply_markup = InlineKeyboardMarkup(keyboard)
    await update.message.reply_text("🧠 What type of filter would you like to add?", reply_markup=reply_markup)
    return FILTER_TYPE

async def receive_filter_type(update: Update, context: ContextTypes.DEFAULT_TYPE):
    query = update.callback_query
    await query.answer()
    context.user_data["filter_type"] = query.data
    await query.edit_message_text(f"✏️ Send the {query.data} you want to add as a filter:")
    return FILTER_VALUE

async def receive_filter_value(update: Update, context: ContextTypes.DEFAULT_TYPE):
    chat_id = str(update.effective_chat.id)
    filters = load_filters()
    user_filters = filters.get(chat_id, {})
    ftype = context.user_data["filter_type"]
    value = update.message.text.strip().lower()

    user_filters.setdefault(ftype, [])
    if value not in user_filters[ftype]:
        user_filters[ftype].append(value)
        filters[chat_id] = user_filters
        save_filters(filters)
        msg = f"✅ Added {value} to your {ftype} filters."

    else:
        msg = f"⚠️ {value} already exists."
    await update.message.reply_text(escape_markdown(msg, 2), parse_mode="MarkdownV2")
    return ConversationHandler.END

async def cancel(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await update.message.reply_text("❌ Canceled.")
    return ConversationHandler.END

async def delete_filter_entry(update: Update, context: ContextTypes.DEFAULT_TYPE):
    keyboard = [
        [InlineKeyboardButton("🗑️ Vendor", callback_data="vendor")],
        [InlineKeyboardButton("🗑️ Keyword", callback_data="keyword")],
        [InlineKeyboardButton("🗑️ CWE", callback_data="cwe")]
    ]
    reply_markup = InlineKeyboardMarkup(keyboard)
    await update.message.reply_text("🧹 What type of filter do you want to remove?", reply_markup=reply_markup)
    return DELETE_FILTER_TYPE

async def receive_delete_type(update: Update, context: ContextTypes.DEFAULT_TYPE):
    query = update.callback_query
    await query.answer()
    context.user_data["delete_type"] = query.data
    await query.edit_message_text(f"✏️ Send the {query.data} you want to delete from your filters:")
    return DELETE_FILTER_VALUE

async def receive_delete_value(update: Update, context: ContextTypes.DEFAULT_TYPE):
    chat_id = str(update.effective_chat.id)
    filters = load_filters()
    user_filters = filters.get(chat_id, {})
    ftype = context.user_data["delete_type"]
    value = update.message.text.strip().lower()

    if ftype in user_filters and value in user_filters[ftype]:
        user_filters[ftype].remove(value)
        if not user_filters[ftype]:
            del user_filters[ftype]
        filters[chat_id] = user_filters
        save_filters(filters)
        msg = f"🗑️ Removed {value} from your {ftype} filters."
    else:
        msg = f"⚠️ {value} not found in your {ftype} filters."

    await update.message.reply_text(escape_markdown(msg, 2), parse_mode="MarkdownV2")
    return ConversationHandler.END


# ─────────────────────────────
# Inline Buttons Routing
# ─────────────────────────────

async def handle_buttons(update: Update, context: ContextTypes.DEFAULT_TYPE):
    query = update.callback_query
    await query.answer()
    fake = type("FakeUpdate", (), {
        "message": query.message,
        "effective_chat": query.message.chat
    })()

    if query.data == "latest":
        await latest(fake, context)
    elif query.data == "subscribe":
        await subscribe(fake, context)
    elif query.data == "unsubscribe":
        await unsubscribe(fake, context)
    elif query.data == "filterlist":
        await filter_list(fake, context)
    elif query.data == "filterwizard":
        await filter_wizard_entry(fake, context)
    elif query.data == "deletefilter":
        await delete_filter_entry(fake, context)


# ─────────────────────────────
# Broadcast CVEs
# ─────────────────────────────

async def send_cve_alerts(app):
    logger.info("📡 CVE broadcast loop started.")
    while True:
        await asyncio.sleep(3600)
        subs = load_subscribers()
        filters = load_filters()
        sent = load_sent_cves()
        new_sent = set()

        for cid in subs:
            user_filter = filters.get(str(cid), {})
            cves = get_latest_cves(limit=20, min_score=7.0, user_filter=user_filter)
            for cve in cves:
                if cve["id"] in sent:
                    continue
                msg = format_cve_msg(cve)
                try:
                    await app.bot.send_message(chat_id=cid, text=msg, parse_mode="MarkdownV2")
                    new_sent.add(cve["id"])
                except Exception as e:
                    logger.warning(f"Failed to send CVE {cve['id']} to {cid}: {e}")
        sent.update(new_sent)
        save_sent_cves(sent)

# ─────────────────────────────
# Main
# ─────────────────────────────

def main():
    nest_asyncio.apply()
    app = ApplicationBuilder().token(TELEGRAM_BOT_TOKEN).build()

    app.add_handler(CommandHandler("start", start))
    app.add_handler(CommandHandler("subscribe", subscribe))
    app.add_handler(CommandHandler("unsubscribe", unsubscribe))
    app.add_handler(CommandHandler("latest", latest))
    app.add_handler(CommandHandler("filterlist", filter_list))

    # Filter wizard
    conv_handler = ConversationHandler(
        entry_points=[
            CommandHandler("filterwizard", filter_wizard_entry),
            CallbackQueryHandler(receive_filter_type, pattern="^(vendor|keyword|cwe)$")
        ],
        states={
            FILTER_TYPE: [CallbackQueryHandler(receive_filter_type)],
            FILTER_VALUE: [MessageHandler(filters.TEXT & ~filters.COMMAND, receive_filter_value)],
        },
        fallbacks=[CommandHandler("cancel", cancel)],
    )
    
    # Delete filter wizard
    del_filter_handler = ConversationHandler(
        entry_points=[
            CommandHandler("deletefilter", delete_filter_entry),
            CallbackQueryHandler(receive_delete_type, pattern="^(vendor|keyword|cwe)$")
        ],
        states={
            DELETE_FILTER_TYPE: [CallbackQueryHandler(receive_delete_type)],
            DELETE_FILTER_VALUE: [MessageHandler(filters.TEXT & ~filters.COMMAND, receive_delete_value)],
        },
        fallbacks=[CommandHandler("cancel", cancel)],
    )

    app.add_handler(del_filter_handler)
    app.add_handler(conv_handler)
    app.add_handler(CallbackQueryHandler(handle_buttons))

    async def run():
        asyncio.create_task(send_cve_alerts(app))
        logger.info("🤖 CVE Alert Bot is running with hourly updates.")
        await app.run_polling()

    asyncio.run(run())

if __name__ == "__main__":
    main()
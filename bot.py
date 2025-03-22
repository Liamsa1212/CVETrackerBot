import asyncio
import json
from telegram import Update
from telegram.ext import (
    ApplicationBuilder,
    CommandHandler,
    ContextTypes,
)
from telegram.helpers import escape_markdown
from config import TELEGRAM_BOT_TOKEN
from cve_fetcher import get_latest_cves
from pathlib import Path
import nest_asyncio

SUBSCRIBERS_FILE = "subscribers.json"
SENT_CVES_FILE = "sent_cves.json"

# ─────────────────────────────
# Utils
# ─────────────────────────────

def load_subscribers():
    try:
        if Path(SUBSCRIBERS_FILE).exists():
            with open(SUBSCRIBERS_FILE, "r") as f:
                return json.load(f)
    except json.JSONDecodeError:
        save_subscribers([])
    return []

def save_subscribers(subscribers):
    with open(SUBSCRIBERS_FILE, "w") as f:
        json.dump(subscribers, f)

def load_sent_cves():
    try:
        if Path(SENT_CVES_FILE).exists():
            with open(SENT_CVES_FILE, "r") as f:
                return set(json.load(f))
    except json.JSONDecodeError:
        save_sent_cves(set())
    return set()

def save_sent_cves(cve_ids):
    with open(SENT_CVES_FILE, "w") as f:
        json.dump(list(cve_ids), f)

def format_cve_msg(cve):
    cve_id = escape_markdown(cve["id"], version=2)
    summary = escape_markdown(cve["summary"], version=2)
    msg = f"🚨 *{cve_id}*\n\n*Summary:* {summary}"

    if "score" in cve:
        score = escape_markdown(str(cve["score"]), version=2)
        msg += f"\n\n📊 *CVSS:* {score}"

    if cve.get("poc"):
        poc = escape_markdown(cve["poc"], version=2)
        msg += f"\n\n🧪 *PoC:* {poc}"

    return msg

# ─────────────────────────────
# Broadcast Loop
# ─────────────────────────────

async def cve_broadcast_loop(app):
    print("📡 CVE broadcast loop started!")
    while True:
        await asyncio.sleep(3600)

        subscribers = load_subscribers()
        if not subscribers:
            continue

        cves = get_latest_cves(limit=20)
        sent_cves = load_sent_cves()
        new_sent = set()

        for cve in cves:
            if cve["id"] in sent_cves:
                continue

            msg = format_cve_msg(cve)
            for chat_id in subscribers:
                try:
                    await app.bot.send_message(chat_id=chat_id, text=msg, parse_mode="MarkdownV2")
                except Exception as e:
                    print(f"⚠️ Failed to send CVE {cve['id']} to {chat_id}: {e}")
            new_sent.add(cve["id"])

        sent_cves.update(new_sent)
        save_sent_cves(sent_cves)

# ─────────────────────────────
# Bot Commands
# ─────────────────────────────

async def start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    msg = escape_markdown(
        "👋 Welcome to *CVE Alert Bot!*\n\n"
        "I track recent vulnerabilities and deliver hourly alerts.\n\n"
        "📌 Commands:\n"
        "/subscribe — Get alerts\n"
        "/unsubscribe — Stop alerts\n"
        "/latest — Show 5 newest CVEs\n"
        "/help — Show help message",
        version=2
    )
    await update.message.reply_text(msg, parse_mode="MarkdownV2")

async def help_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    msg = escape_markdown(
        "🤖 CVE Alert Bot Help\n\n"
        "/subscribe — Receive hourly CVE alerts\n"
        "/unsubscribe — Stop alerts\n"
        "/latest — Show recent CVEs\n"
        "/help — Show this help message",
        version=2
    )
    await update.message.reply_text(msg, parse_mode="MarkdownV2")

async def subscribe(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user_id = update.effective_chat.id
    subscribers = load_subscribers()
    if user_id not in subscribers:
        subscribers.append(user_id)
        save_subscribers(subscribers)
        await update.message.reply_text(escape_markdown("✅ Subscribed to CVE alerts!", version=2), parse_mode="MarkdownV2")
    else:
        await update.message.reply_text(escape_markdown("📬 You're already subscribed.", version=2), parse_mode="MarkdownV2")

async def unsubscribe(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user_id = update.effective_chat.id
    subscribers = load_subscribers()
    if user_id in subscribers:
        subscribers.remove(user_id)
        save_subscribers(subscribers)
        await update.message.reply_text(escape_markdown("❎ Unsubscribed from alerts.", version=2), parse_mode="MarkdownV2")
    else:
        await update.message.reply_text(escape_markdown("ℹ️ You weren’t subscribed.", version=2), parse_mode="MarkdownV2")

async def latest(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await update.message.reply_text(escape_markdown("🔍 Fetching recent CVEs...", version=2), parse_mode="MarkdownV2")
    cves = get_latest_cves(limit=20)
    count = 0

    for cve in cves:
        if count >= 5:
            break
        msg = format_cve_msg(cve)
        try:
            await update.message.reply_text(msg, parse_mode="MarkdownV2")
            count += 1
        except Exception as e:
            print(f"⚠️ Failed to send CVE {cve['id']}: {e}")

    if count == 0:
        await update.message.reply_text(escape_markdown("❌ No usable CVEs found in the last 24h.", version=2), parse_mode="MarkdownV2")

# ─────────────────────────────
# Main
# ─────────────────────────────

def main():
    nest_asyncio.apply()
    app = ApplicationBuilder().token(TELEGRAM_BOT_TOKEN).build()

    app.add_handler(CommandHandler("start", start))
    app.add_handler(CommandHandler("help", help_command))
    app.add_handler(CommandHandler("subscribe", subscribe))
    app.add_handler(CommandHandler("unsubscribe", unsubscribe))
    app.add_handler(CommandHandler("latest", latest))

    async def run_bot():
        asyncio.create_task(cve_broadcast_loop(app))
        print("🤖 CVE Alert Bot is running with hourly updates!")
        await app.run_polling()

    loop = asyncio.get_event_loop()
    loop.run_until_complete(run_bot())

if __name__ == "__main__":
    main()

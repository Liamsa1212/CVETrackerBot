"""Telegram bot application builder, JobQueue recurring scheduler, and lifecycle management."""

import asyncio
from typing import Optional
from loguru import logger
from telegram import BotCommand
from telegram.ext import (
    Application,
    ApplicationBuilder,
    CallbackQueryHandler,
    CommandHandler,
    ContextTypes,
    MessageHandler,
    filters,
)

from cve_tracker.bot.handlers import (
    add_filter_command,
    cisa_command,
    clear_filters_command,
    filters_command,
    handle_callback_navigation,
    handle_text_menu_buttons,
    help_command,
    latest_command,
    set_min_score_command,
    start_command,
    subscribe_command,
    unsubscribe_command,
)
from cve_tracker.core.config import Settings
from cve_tracker.fetchers.manager import FetcherManager
from cve_tracker.notifiers.dispatcher import NotificationDispatcher
from cve_tracker.notifiers.telegram import TelegramNotifier
from cve_tracker.storage.repository import CVERepository


async def scheduled_poll_job(context: ContextTypes.DEFAULT_TYPE) -> None:
    """Recurring task running inside PTB's JobQueue."""
    logger.info("Executing scheduled vulnerability poll...")
    fetcher_mgr: FetcherManager = context.bot_data["fetcher_manager"]
    dispatcher: NotificationDispatcher = context.bot_data["dispatcher"]

    try:
        new_cves = await fetcher_mgr.poll_and_ingest()
        if new_cves:
            delivered = await dispatcher.dispatch_cves(new_cves)
            logger.info(f"Poll job finished: {len(new_cves)} new CVEs, {delivered} alerts delivered.")
        else:
            logger.info("Poll job finished: No new CVEs discovered.")
    except Exception as e:
        logger.error(f"Error during scheduled poll job: {e}")


async def post_init_setup(application: Application) -> None:
    """Set persistent bot command menu visible in Telegram's [/] menu button."""
    try:
        commands = [
            BotCommand("start", "🏠 Open Main Menu & Dashboard"),
            BotCommand("latest", "🔍 View Latest 5 CVEs"),
            BotCommand("cisa", "🔥 View Actively Exploited 0-Days"),
            BotCommand("subscribe", "🔔 Subscribe to Real-time Alerts"),
            BotCommand("unsubscribe", "🔕 Stop Automated Alerts"),
            BotCommand("filters", "⚙️ Configure Alert Filters"),
            BotCommand("help", "❓ Help & Command List"),
        ]
        await application.bot.set_my_commands(commands)
        logger.info("Registered persistent bot commands in Telegram Menu.")
    except Exception as e:
        logger.warning(f"Could not register Telegram bot commands: {e}")


def build_telegram_bot_app(
    settings: Settings,
    repository: CVERepository,
    fetcher_manager: FetcherManager,
    dispatcher: NotificationDispatcher,
) -> Optional[Application]:
    """Construct and configure the python-telegram-bot Application."""
    if not settings.is_telegram_enabled:
        logger.warning("Telegram bot token not provided. Telegram bot will not be started.")
        return None

    app = (
        ApplicationBuilder()
        .token(settings.telegram_bot_token)
        .post_init(post_init_setup)
        .build()
    )

    # Register dependencies into bot_data for handlers
    app.bot_data["settings"] = settings
    app.bot_data["repository"] = repository
    app.bot_data["fetcher_manager"] = fetcher_manager
    app.bot_data["dispatcher"] = dispatcher

    # Wire Telegram Notifier with the active bot instance
    tg_notifier = TelegramNotifier(bot=app.bot)
    dispatcher.register_notifier(tg_notifier)

    # Command handlers
    app.add_handler(CommandHandler("start", start_command))
    app.add_handler(CommandHandler("help", help_command))
    app.add_handler(CommandHandler("subscribe", subscribe_command))
    app.add_handler(CommandHandler("unsubscribe", unsubscribe_command))
    app.add_handler(CommandHandler("latest", latest_command))
    app.add_handler(CommandHandler("cisa", cisa_command))
    app.add_handler(CommandHandler("filters", filters_command))
    app.add_handler(CommandHandler("setminscore", set_min_score_command))
    app.add_handler(CommandHandler("addfilter", add_filter_command))
    app.add_handler(CommandHandler("clearfilters", clear_filters_command))

    # Callback Query handlers for inline navigation menus
    app.add_handler(CallbackQueryHandler(handle_callback_navigation))

    # Text Message Handler for persistent bottom keyboard taps
    app.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, handle_text_menu_buttons))

    # Schedule recurring polling with PTB JobQueue
    if app.job_queue:
        app.job_queue.run_repeating(
            scheduled_poll_job,
            interval=settings.poll_interval_seconds,
            first=15,  # First run 15 seconds after startup
            name="scheduled_cve_poll",
        )
        logger.info(
            f"Scheduled automated CVE polling every {settings.poll_interval_seconds} seconds."
        )

    return app

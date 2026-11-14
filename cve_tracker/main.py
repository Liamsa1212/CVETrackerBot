"""Master application entry point."""

import asyncio
import signal
import sys
from loguru import logger

from cve_tracker.bot.service import build_telegram_bot_app
from cve_tracker.core.config import Settings, get_settings
from cve_tracker.core.logging import setup_logging
from cve_tracker.fetchers.manager import FetcherManager
from cve_tracker.models.filter import SubscriptionFilter
from cve_tracker.models.subscriber import ChannelType
from cve_tracker.notifiers.discord import DiscordNotifier
from cve_tracker.notifiers.dispatcher import NotificationDispatcher
from cve_tracker.notifiers.webhook import GenericWebhookNotifier
from cve_tracker.storage.database import (
    create_db_engine,
    create_session_factory,
    init_db,
)
from cve_tracker.storage.repository import CVERepository


async def run_standalone_worker(
    settings: Settings,
    fetcher_manager: FetcherManager,
    dispatcher: NotificationDispatcher,
) -> None:
    """Fallback loop for running without Telegram bot (e.g. Discord/Webhook mode only)."""
    logger.info("Running in standalone worker mode (polling every {}s)...", settings.poll_interval_seconds)
    while True:
        try:
            new_cves = await fetcher_manager.poll_and_ingest()
            if new_cves:
                delivered = await dispatcher.dispatch_cves(new_cves)
                logger.info(f"Delivered {delivered} alerts to channels.")
        except asyncio.CancelledError:
            break
        except Exception as e:
            logger.error(f"Error during standalone poll cycle: {e}")

        await asyncio.sleep(settings.poll_interval_seconds)


async def async_main() -> None:
    """Async main routine."""
    settings = get_settings()
    setup_logging(settings)

    logger.info("Starting CVE Tracker Bot System v2.0...")

    # Database Initialization
    engine = create_db_engine(settings.database_url)
    session_factory = create_session_factory(engine)
    await init_db(engine)

    repository = CVERepository(session_factory)

    # Legacy JSON Migration (seamless upgrade)
    await repository.migrate_legacy_json_data()

    # Core Services
    fetcher_manager = FetcherManager(settings=settings, repository=repository)
    dispatcher = NotificationDispatcher(settings=settings, repository=repository)

    # Register external notifiers
    discord_notifier = DiscordNotifier()
    dispatcher.register_notifier(discord_notifier)

    webhook_notifier = GenericWebhookNotifier()
    dispatcher.register_notifier(webhook_notifier)

    # Register default Discord webhook if configured in environment
    if settings.discord_webhook_url:
        await repository.add_or_activate_subscriber(
            target_id=settings.discord_webhook_url,
            channel_type=ChannelType.DISCORD,
            filters=SubscriptionFilter(min_cvss=settings.default_min_cvss),
        )
        logger.info("Registered global Discord Webhook destination.")

    # Register default generic webhook if configured in environment
    if settings.generic_webhook_url:
        await repository.add_or_activate_subscriber(
            target_id=settings.generic_webhook_url,
            channel_type=ChannelType.WEBHOOK,
            filters=SubscriptionFilter(min_cvss=settings.default_min_cvss),
        )
        logger.info("Registered global Generic HTTP Webhook destination.")

    # Build Telegram Bot
    telegram_app = build_telegram_bot_app(
        settings=settings,
        repository=repository,
        fetcher_manager=fetcher_manager,
        dispatcher=dispatcher,
    )

    if telegram_app:
        logger.info("Starting Telegram bot polling...")
        # PTB application run_polling handles its own loop when called from sync, or run_polling() directly
        await telegram_app.initialize()
        await telegram_app.start()
        await telegram_app.updater.start_polling(drop_pending_updates=True)

        # Run an initial vulnerability check in background with retained strong reference
        background_tasks = set()
        initial_poll_task = asyncio.create_task(fetcher_manager.poll_and_ingest())
        background_tasks.add(initial_poll_task)
        initial_poll_task.add_done_callback(background_tasks.discard)

        # Keep running until cancelled
        stop_event = asyncio.Event()

        def _signal_handler():
            logger.info("Shutdown signal received.")
            stop_event.set()

        loop = asyncio.get_running_loop()
        for sig in (signal.SIGINT, signal.SIGTERM):
            try:
                loop.add_signal_handler(sig, _signal_handler)
            except NotImplementedError:
                # Windows ProactorEventLoop doesn't support add_signal_handler
                pass

        try:
            # Interruptible poll loop for cross-platform graceful shutdown
            while not stop_event.is_set():
                await asyncio.sleep(0.5)
        except (KeyboardInterrupt, asyncio.CancelledError):
            pass
        finally:
            logger.info("Stopping Telegram bot...")
            await telegram_app.updater.stop()
            await telegram_app.stop()
            await telegram_app.shutdown()
            await dispatcher.close()
            await fetcher_manager.close()
            await engine.dispose()
    else:
        # Standalone worker loop
        await run_standalone_worker(settings, fetcher_manager, dispatcher)


def main() -> None:
    """Entry point for CLI or docker container."""
    try:
        asyncio.run(async_main())
    except (KeyboardInterrupt, SystemExit):
        logger.info("CVE Tracker Bot stopped gracefully.")


if __name__ == "__main__":
    main()

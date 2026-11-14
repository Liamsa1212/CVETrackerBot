"""Tests for Telegram Bot handlers: import validation, state machine transitions, and callback menus."""

from unittest.mock import AsyncMock, MagicMock
import pytest
from telegram import Update

import cve_tracker.bot.handlers as handlers
from cve_tracker.bot.handlers import (
    handle_callback_navigation,
    handle_text_menu_buttons,
    latest_command,
)
from cve_tracker.models.cve import CVEItem
from cve_tracker.models.subscriber import ChannelType
from cve_tracker.storage.repository import CVERepository


def test_inline_keyboard_classes_imported():
    """Verify that InlineKeyboardButton and InlineKeyboardMarkup are properly imported in handlers."""
    assert hasattr(handlers, "InlineKeyboardButton")
    assert hasattr(handlers, "InlineKeyboardMarkup")


@pytest.mark.asyncio
async def test_latest_command_with_cves_renders_without_crash(
    repository: CVERepository,
    sample_cve: CVEItem,
):
    """Verify latest_command renders inline navigation buttons without NameError."""
    await repository.upsert_cve(sample_cve)

    update = MagicMock(spec=Update)
    update.effective_chat.id = 12345
    update.effective_message.reply_text = AsyncMock()

    context = MagicMock()
    context.bot_data = {"repository": repository}

    await latest_command(update, context)
    update.effective_message.reply_text.assert_called_once()


@pytest.mark.asyncio
async def test_filter_score_state_machine_transition(repository: CVERepository):
    """Verify user state transition when setting minimum CVSS filter."""
    chat_id = "5551234"
    await repository.add_or_activate_subscriber(chat_id, ChannelType.TELEGRAM)

    update = MagicMock(spec=Update)
    update.effective_chat.id = int(chat_id)
    update.effective_message.text = "8.5"
    update.effective_message.reply_text = AsyncMock()

    context = MagicMock()
    context.bot_data = {"repository": repository}
    context.user_data = {"awaiting_filter": "min_cvss"}

    # Process text input
    await handle_text_menu_buttons(update, context)

    # State must be cleared
    assert "awaiting_filter" not in context.user_data

    # Repository must reflect new minimum CVSS
    sub = await repository.get_subscriber(chat_id, ChannelType.TELEGRAM)
    assert sub is not None
    assert sub.filters.min_cvss == 8.5


@pytest.mark.asyncio
async def test_filter_score_invalid_input_retains_state(repository: CVERepository):
    """Verify invalid non-numeric input does not crash, notifies user, and preserves awaiting state."""
    chat_id = "5551234"
    await repository.add_or_activate_subscriber(chat_id, ChannelType.TELEGRAM)

    update = MagicMock(spec=Update)
    update.effective_chat.id = int(chat_id)
    update.effective_message.text = "invalid-score"
    update.effective_message.reply_text = AsyncMock()

    context = MagicMock()
    context.bot_data = {"repository": repository}
    context.user_data = {"awaiting_filter": "min_cvss"}

    await handle_text_menu_buttons(update, context)

    # State must be preserved for retry
    assert context.user_data.get("awaiting_filter") == "min_cvss"
    update.effective_message.reply_text.assert_called_with(
        "❌ Please enter a valid number between 0.0 and 10.0 (e.g. 7.5)."
    )


@pytest.mark.asyncio
async def test_callback_toggle_cisa_only(repository: CVERepository):
    """Verify callback query toggles CISA KEV filter dynamically."""
    chat_id = "77788899"
    await repository.add_or_activate_subscriber(chat_id, ChannelType.TELEGRAM)

    query = MagicMock()
    query.data = "filter_toggle_cisa"
    query.message.chat.id = int(chat_id)
    query.answer = AsyncMock()
    query.edit_message_text = AsyncMock()

    update = MagicMock(spec=Update)
    update.callback_query = query

    context = MagicMock()
    context.bot_data = {"repository": repository}

    # Initial state is False
    sub_before = await repository.get_subscriber(chat_id, ChannelType.TELEGRAM)
    assert sub_before.filters.cisa_kev_only is False

    # Execute toggle
    await handle_callback_navigation(update, context)

    query.answer.assert_called_once()
    query.edit_message_text.assert_called_once()

    sub_after = await repository.get_subscriber(chat_id, ChannelType.TELEGRAM)
    assert sub_after.filters.cisa_kev_only is True

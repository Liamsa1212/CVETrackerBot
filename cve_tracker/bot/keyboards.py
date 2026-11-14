"""Inline keyboards and persistent menus for Telegram Bot."""

from typing import Optional
from telegram import (
    InlineKeyboardButton,
    InlineKeyboardMarkup,
    KeyboardButton,
    ReplyKeyboardMarkup,
)
from cve_tracker.models.filter import SubscriptionFilter


def get_persistent_reply_keyboard() -> ReplyKeyboardMarkup:
    """Always-visible bottom menu keyboard attached to chat input."""
    return ReplyKeyboardMarkup(
        [
            [KeyboardButton("🔍 Latest CVEs"), KeyboardButton("🔥 CISA 0-Days")],
            [KeyboardButton("🔔 Subscribe"), KeyboardButton("🔕 Unsubscribe")],
            [KeyboardButton("⚙️ My Filters"), KeyboardButton("❓ Help")],
        ],
        resize_keyboard=True,
        is_persistent=True,
    )


def get_main_menu() -> InlineKeyboardMarkup:
    """Main navigation inline menu keyboard."""
    return InlineKeyboardMarkup([
        [
            InlineKeyboardButton("🔍 Latest CVEs", callback_data="nav_latest"),
            InlineKeyboardButton("🔥 CISA KEV (0-Day)", callback_data="nav_cisa"),
        ],
        [
            InlineKeyboardButton("🔔 Subscribe", callback_data="nav_subscribe"),
            InlineKeyboardButton("🔕 Unsubscribe", callback_data="nav_unsubscribe"),
        ],
        [
            InlineKeyboardButton("⚙️ Filter Rules", callback_data="nav_filterlist"),
            InlineKeyboardButton("❓ Help", callback_data="nav_help"),
        ],
    ])


def get_filter_type_menu(filt: Optional[SubscriptionFilter] = None) -> InlineKeyboardMarkup:
    """Filter management keyboard with dynamic toggles and action triggers."""
    f = filt or SubscriptionFilter()
    cisa_status = "🟢 ON" if f.cisa_kev_only else "⚪ OFF"
    poc_status = "🟢 ON" if f.has_poc_only else "⚪ OFF"
    score_display = f"{f.min_cvss:.1f}" if f.min_cvss is not None else "Any"

    return InlineKeyboardMarkup([
        [
            InlineKeyboardButton("🏢 + Add Vendor", callback_data="filter_add_vendor"),
            InlineKeyboardButton("📦 + Add Product", callback_data="filter_add_product"),
        ],
        [
            InlineKeyboardButton("🔑 + Add Keyword", callback_data="filter_add_keyword"),
            InlineKeyboardButton("🏷️ + Add CWE", callback_data="filter_add_cwe"),
        ],
        [
            InlineKeyboardButton(f"📊 Min CVSS: {score_display}", callback_data="filter_set_score"),
        ],
        [
            InlineKeyboardButton(f"🔥 CISA Only: {cisa_status}", callback_data="filter_toggle_cisa"),
            InlineKeyboardButton(f"🧪 PoC Only: {poc_status}", callback_data="filter_toggle_poc"),
        ],
        [
            InlineKeyboardButton("🧹 Clear All Filters", callback_data="filter_clear"),
            InlineKeyboardButton("🔙 Back to Main Menu", callback_data="nav_menu"),
        ],
    ])
